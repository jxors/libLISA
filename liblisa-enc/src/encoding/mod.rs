use liblisa_core::{AccessKind, GetDest, Location};
use liblisa_core::{Dataflows, Encoding, encoding::PartValue, FlowOutputLocation, FlowValueLocation, Size, Source};
use liblisa_core::computation::BasicComputation;
use liblisa_core::gen::{StateGen, RandomizationError, RemapError};
use crate::cache::CombinedCache;
use liblisa_core::{arch::{Arch, Instruction, InstructionInfo, Register, Flag}, oracle::Oracle, oracle::OracleError};
use itertools::Itertools;
use log::{debug, error, info, trace, warn};
use std::{collections::{HashMap, HashSet}, fmt::Debug};
use thiserror::Error;
use liblisa_core::encoding::{BitKind, Part, PartMapping};
use rand::Rng;

mod changes;
mod imm;
use changes::*;

pub struct EncodingAnalysis<'a, A: Arch, O: Oracle<A>> {
    o: &'a mut O,
    cache: &'a CombinedCache<A>,
    dataflows: &'a Dataflows<A, BasicComputation>,
}

#[derive(Error, Debug)]
pub enum EncodingError<A: Arch>{
    #[error("Not supported")]
    NotSupported,

    #[error("Randomization failed: {}", .0)]
    RandomizationFailed(RandomizationError),

    #[error("Remapping failed: {}", .0)]
    RemapFailed(RemapError<A>),

    #[error("Oracle error: {}", .0)]
    Oracle(OracleError),
}

impl<A: Arch> From<RandomizationError> for EncodingError<A> {
    fn from(e: RandomizationError) -> Self {
        EncodingError::RandomizationFailed(e)
    }
}

impl<A: Arch> From<RemapError<A>> for EncodingError<A> {
    fn from(e: RemapError<A>) -> Self {
        EncodingError::RemapFailed(e)
    }
}

impl<A: Arch> From<OracleError> for EncodingError<A> {
    fn from(e: OracleError) -> Self {
        EncodingError::Oracle(e)
    }
}

enum RegOrSize<A: Arch> {
    Reg(A::Reg),
    Size(Size),
    None,
}

impl<'x, A: Arch + 'static, O: Oracle<A> + 'static> EncodingAnalysis<'x, A, O> {
    fn count_around<F: FnMut(&Change<A>) -> bool>(
        changes: &[Change<A>],
        index: usize,
        mut check: F,
    ) -> usize {
        let mut around = 0;
        let mut pos = index;
        while pos >= 1 {
            pos -= 1;
            if check(&changes[pos]) {
                around += 1;
            } else {
                break;
            }
        }

        let mut pos = index;
        while pos < changes.len() - 1 {
            pos += 1;
            if check(&changes[pos]) {
                around += 1;
            } else {
                break;
            }
        }

        around
    }

    fn cleanup_bit_changes(bit_changes: &mut Vec<Change<A>>) {
        let mut v = HashSet::new();
        let mut start_index = None;

        // Expand scope for consecutive ValueImms that have overlapping output_indexes
        // Rationale behind this: it's very unlikely that two immediate values will be used in partially different, but also partially
        // equivalent outputs. In the case that this does happen, we can still correctly learn semantics if we allow the semantics to
        // contain some logic for splitting the two values. On the other hand, if we end up with multiple separate parts in the case
        // where there is only one (but for some reason, we can't conclusively detect this) semantics become pretty much impossible
        // to learn correctly. Therefore, it is preferrable to have these joined here.
        // TODO: Handle memory_indexes?
        for index in 0..bit_changes.len() {
            debug!("Change #{:2}: {:?}", index, bit_changes[index]);
            match &bit_changes[index] {
                Change::ValueImm { output_indexes, .. } => {
                    if start_index.is_some() && output_indexes.iter().any(|index| v.contains(index)) {
                        // There is at least some overlap between earlier items
                        for index in output_indexes {
                            v.insert(*index);
                        }

                        // Make sure all earlier items use the expanded locations
                        let new_output_indexes: Vec<usize> = v.iter().copied().sorted().collect();
                        for i in start_index.unwrap()..=index {
                            if let Change::ValueImm { output_indexes, memory_indexes: _ } = &mut bit_changes[i] {
                                *output_indexes = new_output_indexes.clone();
                            }
                        }
                    } else {
                        start_index = Some(index);
                        v = output_indexes.iter().copied().collect();
                    }
                },
                _ => {
                    start_index = None;
                    v.clear()
                },
            }
        }

        // Clean up changes by removing Imm values of 4 or less bits, folding memory errors in to Imms if possible
        for index in 0..bit_changes.len() {
            debug!("Change #{:2}: {:?}", index, bit_changes[index]);
            match &bit_changes[index] {
                Change::UnknownMemoryError { constraint_index } => {
                    let mut around = None;
                    let mut real_addresses = 0;
                    let memory_around =
                        Self::count_around(&bit_changes, index, |change| {
                            match change {
                                Change::ValueImm { memory_indexes: locations, .. }
                                    if locations.contains(constraint_index) =>
                                {
                                    around = Some(change.clone());
                                    real_addresses += 1;
                                    true
                                }
                                Change::UnknownMemoryError { constraint_index: i } if i == constraint_index => true,
                                _ => false,
                            }
                        });

                    if memory_around >= 4 && real_addresses >= (memory_around * 3 / 4).checked_sub(2).unwrap_or(0) {
                        bit_changes[index] = around.unwrap().clone();
                    } else {
                        bit_changes[index] = Change::Invalid;
                    }
                }
                Change::ValueImm { memory_indexes: locations, output_indexes } => {
                    if output_indexes.len() > 0 && Self::count_around(&bit_changes, index, |change| change == &bit_changes[index]) < 1 {
                        bit_changes[index] = Change::Invalid;
                    } else if Self::count_around(&bit_changes, index, |change| {
                        match change {
                            Change::UnknownMemoryError { constraint_index } => locations.contains(constraint_index),
                            change => change == &bit_changes[index],
                        }
                    }) < 1 {
                        bit_changes[index] = Change::Invalid;
                    }
                }
                Change::Register { locations, from: _, to: _, } => {
                    // If there are multiple bits that change overlapping locations, only use the one with locations such that for all other bits the locations is a subset of this one; If there is no such bit, don't use any of them. For example, this problem occurs with the "swap output register" of add eax,edx. The bit switches the output from the first to the second operand. However, this means that every bit depends on every other bit, which would mean we would have to enumerate 127 different register combinations (which defeats the point of identifying them separately). An easier solution is to see the "swap output register" bit as a non-register bit.

                    if !bit_changes.iter().all(|other| match other {
                        Change::Register {
                            locations: other_locations,
                            from: _,
                            to: _,
                        } => {
                            // other_locations must either be a subset of locations, or not contain any of the same registers for the current change to be valid
                            debug!(
                                "Checking: {:?} subset or distinct from {:?} {} {}",
                                locations,
                                other_locations,
                                other_locations
                                    .iter()
                                    .all(|other| locations.contains(other)),
                                other_locations
                                    .iter()
                                    .all(|other| !locations.contains(other))
                            );
                            other_locations
                                .iter()
                                .all(|other| locations.contains(other))
                                || other_locations
                                    .iter()
                                    .all(|other| !locations.contains(other))
                        }
                        _ => true,
                    }) {
                        bit_changes[index] = Change::Invalid;
                    }
                }
                Change::OperandSize { locations, from: _, to: _ } => {
                    // Idem here, we cannot have multiple bits (partially) control the same memory locations with different values.
                    if !bit_changes.iter().enumerate().all(|(other_index, other)| match other {
                        Change::OperandSize {
                            locations: other_locations,
                            from: _,
                            to: _,
                        } if other_index != index => {
                            let distinct = locations.iter().all(|loc| !other_locations.contains(loc));
                            distinct || other_locations.len() > locations.len() || other_index > index
                        }
                        _ => true,
                    }) {
                        bit_changes[index] = Change::Invalid;
                    }
                },
                Change::None | Change::Invalid => {}
            }
        }

        debug!("Cleaned up:");
        for (index, change) in bit_changes.iter().enumerate() {
            debug!("Change #{:2}: {:?}", index, change);
        }
    }

    fn create_parts<'a>(dataflows: &mut Dataflows<A, BasicComputation>, bit_changes: &'a [Change<A>]) -> (Vec<BitKind>, Vec<(Part<A>, RegOrSize<A>, ChangeBase<'a, A>)>) {
        let instr = dataflows.addresses.instr.clone();
        let mut bits = Vec::new();
        let mut mapping = HashMap::<_, usize>::new();
        let mut part_info: Vec<(Part<A>, RegOrSize<A>, ChangeBase<A>)> = Vec::new();
        for (bit_index, change) in bit_changes.iter().enumerate() {
            let base = change.into_base();

            // We remove AddressImms and ValueImms from the mapping if the current bit is not part of the sequence. This makes sure
            // AddressImms and ValueImms are always consecutive.
            mapping.retain(|key, _| {
                match key {
                    ChangeBase::ValueImm { .. } => key == &base,
                    _ => true,
                }
            });

            match change {
                Change::None => bits.push(BitKind::DontCare),
                Change::Invalid => bits.push(BitKind::Fixed(instr.bit_at(bit_index))),
                change => {
                    let index = if let Some(part_index) = mapping.get(&base) {
                        let entry = &mut part_info[*part_index].0;
                        entry.value |= (instr.bit_at(bit_index) as u64) << entry.size;
                        entry.size += 1;
                        *part_index
                    } else {
                        trace!(
                            "Not in mapping: {:?}! Already in mapping are: {:?}",
                            change, mapping
                        );
                        let part_index = part_info.len();
                        part_info.push((Part {
                            size: 1,
                            value: instr.bit_at(bit_index) as u64,
                            mapping: match &base {
                                ChangeBase::None | ChangeBase::Invalid | ChangeBase::UnknownMemoryError { constraint_index: _ } => unreachable!(),
                                ChangeBase::Register { locations, from: _ } => PartMapping::Register {
                                    locations: locations.iter().map(FlowValueLocation::from).collect::<Vec<_>>(),
                                    mapping: Vec::new(),
                                },
                                ChangeBase::OperandSize { locations, from: _ } => PartMapping::Size {
                                    locations: locations.iter().map(FlowValueLocation::from).collect::<Vec<_>>(),
                                    mapping: Vec::new(),
                                },
                                ChangeBase::ValueImm { memory_indexes, output_indexes } => PartMapping::ValueImm {
                                    locations: dataflows.insert_value(memory_indexes.iter()
                                        .map(|index| FlowOutputLocation::MemoryAccess(*index))
                                        .chain(output_indexes.iter()
                                            .map(|index| FlowOutputLocation::Output(*index))
                                        ), 
                                        Source::Imm(part_index)
                                    ).into_iter()
                                        .map(FlowValueLocation::from)
                                        .collect::<Vec<_>>(),
                                    mapping: None,
                                },
                            },
                        }, match &base {
                            ChangeBase::Register { locations: _ , from } => RegOrSize::Reg(from.clone()),
                            ChangeBase::OperandSize { locations: _, from } => RegOrSize::Size(from.clone()),
                            _ => RegOrSize::None,
                        }, base.clone()));
                        mapping.insert(base, part_index);

                        part_index
                    };

                    bits.push(BitKind::Value(index));
                }
            }
        }

        (bits, part_info)
    }

    fn enum_values<T: Clone>(&mut self, size: usize, bits: &[BitKind], part_index: usize, check: impl Fn(&Change<A>) -> T, base: &ChangeBase<A>, mapped_value: T, invalid_value: T) -> Result<Vec<T>, EncodingError<A>> {
        let instr = self.dataflows.addresses.instr.as_instr();
        let mut mapping = Vec::new();
        for v in 0..(1 << size) {
            let mut new_instr = Instruction::from(instr);
            let mut k = 0;
            for (index, bit) in bits.iter().enumerate() {
                match bit {
                    BitKind::Value(n) if *n == part_index => {
                        new_instr = new_instr.with_bit(index, (v >> k) & 1);
                        k += 1;
                    }
                    _ => {},
                }
            }

            info!("Instruction variant {:?}, {:02X?} for value {:b} (base: {:02X?}, equal={:?})", new_instr, new_instr.bytes(), v, instr.bytes(), new_instr.as_instr() == instr);
            if new_instr.as_instr() == instr {
                mapping.push(mapped_value.clone());
            } else {
                let mut change = ChangeAnalysis {
                    cache: self.cache,
                    dataflows: self.dataflows,
                    o: self.o,
                }.detect_change(new_instr.as_instr())?;
                change.sort();
                if &change.into_base() == base {
                    info!("{:b} ({:02X?}) = {:?}", v, new_instr.bytes(), change);
                    mapping.push(check(&change));
                } else {
                    error!(
                        "Checking {:?} gave a different change: {:?} but expected {:?}",
                        instr, change, base
                    );
                    mapping.push(invalid_value.clone());
                }
            }
        }

        Ok(mapping)
    }

    fn fill_part_mapping(&mut self, mut part_info: Vec<(Part<A>, RegOrSize<A>, ChangeBase<A>)>, bits: &[BitKind]) -> Result<(Vec<Part<A>>, Vec<usize>), EncodingError<A>> {
        let mut invalid_change_indices = Vec::new();
        for (index, (part, reg_or_size, base)) in part_info.iter_mut().enumerate() {
            let base: &ChangeBase<A> = base;
            match (&mut part.mapping, reg_or_size) {
                (PartMapping::Register { locations: _, mapping }, RegOrSize::Reg(mapped_value)) => {
                    *mapping = self.enum_values(part.size, bits, index, |change| {
                        if let Change::Register {
                            locations: _,
                            from: _,
                            to,
                        } = change {
                            Some(to.clone())
                        } else {
                            None
                        }
                    }, base, Some(mapped_value.clone()), None)?;

                    if mapping.iter().filter(|x| x.is_some()).count() <= 1 {
                        invalid_change_indices.push(index);
                    }
                }
                (PartMapping::Size { locations: _, mapping }, RegOrSize::Size(mapped_value)) => {
                    *mapping = self.enum_values(part.size, bits, index, |change| {
                        if let Change::OperandSize {
                            locations: _,
                            from: _,
                            to,
                        } = change {
                            Some(to.clone())
                        } else {
                            None
                        }
                    }, base, Some(mapped_value.clone()), None)?;

                    if mapping.iter().filter(|x| x.is_some()).count() <= 1 {
                        invalid_change_indices.push(index);
                    }
                }
                (PartMapping::ValueImm { locations, mapping }, RegOrSize::None) => {
                    if part.size <= 4 && locations.iter().any(|loc| matches!(loc, FlowValueLocation::InputForOutput { .. })) {
                        let base_output_indices = locations.iter().flat_map(|loc| match loc {
                            FlowValueLocation::InputForOutput { output_index, .. } => Some(*output_index),
                            FlowValueLocation::MemoryAddress { .. } => None,
                            _ => unreachable!(),
                        }).collect::<Vec<_>>();

                        let base_memory_indices = locations.iter().flat_map(|loc| match loc {
                            FlowValueLocation::MemoryAddress { memory_index, .. } => Some(*memory_index),
                            FlowValueLocation::InputForOutput { .. } => None,
                            _ => unreachable!(),
                        }).collect::<Vec<_>>();

                        *mapping = Some(self.enum_values(part.size, bits, index, |change| {
                            if let Change::ValueImm {
                                memory_indexes,
                                output_indexes,
                            } = change {
                                debug!("ValueImm comparison: {:?} vs {:?}", base_output_indices, output_indexes);
                                if &base_output_indices == output_indexes && &base_memory_indices == memory_indexes {
                                    PartValue::Valid
                                } else {
                                    PartValue::Invalid
                                }
                            } else {
                                PartValue::Invalid
                            }
                        }, base, PartValue::Valid, PartValue::Invalid)?);

                        if mapping.as_ref().unwrap().iter().filter(|x| x.is_invalid()).count() > 2 {
                            info!("Mapping: {:?}, missing more than 2 arguments, removing", mapping);
                            invalid_change_indices.push(index);
                        }
                    }
                }
                _ => unreachable!(),
            }
        }

        Ok((part_info.into_iter().map(|(x, _, _)| x).collect(), invalid_change_indices))
    }

    fn bit_changes(&mut self) -> Result<Vec<Change<A>>, EncodingError<A>> {
        let instr = self.dataflows.addresses.instr.as_instr();
        let mut bit_changes = Vec::new();

        info!("Analyzing base instruction: {:?}", instr);
        for bit in 0..instr.bit_len() {
            let new_instr = instr.with_flipped_bit(bit);
            info!(
                "Checking (bit {} flipped)  : {:?} {:02X?}",
                bit,
                new_instr,
                new_instr.bytes()
            );
            let change = ChangeAnalysis {
                cache: self.cache,
                dataflows: self.dataflows,
                o: self.o,
            }.detect_change(new_instr.as_instr())?;
            info!("Final change: {:?}", change);
            bit_changes.push(change);
        }

        // Sort all changes to make sure they (read: the locations stored in the change) are identical if we end up comparing them
        for change in bit_changes.iter_mut() {
            change.sort();
        }

        Ok(bit_changes)
    }

    fn validate_dontcare(&mut self, encoding: &mut Encoding<A, BasicComputation>) -> Result<(), EncodingError<A>> {
        let mut dont_care_indices = encoding.bits.iter()
            .enumerate()
            .filter(|(_, bit)| matches!(bit, BitKind::DontCare))
            .map(|(index, _)| index)
            .collect::<Vec<_>>();

        info!("DontCare indices are: {:?} for {} {:?}", dont_care_indices, encoding, encoding);
        
        let mut num_errs = 0;
        let mut rng = rand::thread_rng();
        for num_inst in 0..500 {
            let part_values = encoding.parts.iter()
                .map(|part| rng.gen::<u64>() & ((1 << part.size) - 1))
                .collect::<Vec<_>>();
            if let Ok(instance) = encoding.instantiate(&part_values) {
                let base_instr = instance.addresses.instr.clone();
                for num_try in 0..5 {
                    debug!("Using {:?} as base ({:02X?})", base_instr, base_instr.bytes());
                    if let Ok(base_state) = StateGen::randomize_new(&instance.addresses, &mut rng, self.o) {
                        let base_result = self.o.observe(&base_state);

                        let randomize = dont_care_indices.len() >= 14;
                        // If a bit is set in value, we will flip the bit in the modified instruction.
                        for value in 0..(1usize << dont_care_indices.len().min(14)) {
                            let value = if randomize {
                                debug!("Iteration {} of try {} of instantiation {}", value, num_try, num_inst);
                                rng.gen::<usize>() & ((1usize << dont_care_indices.len()) - 1)
                            } else {
                                value
                            };

                            let modified_instr = dont_care_indices.iter()
                                .enumerate()
                                .fold(base_instr, |acc, (n, bit_index)| {
                                    // Flip the bits that correspond to the bits that are set in `value`
                                    acc.with_bit(*bit_index, base_instr.bit_at(*bit_index) ^ ((value >> n) as u8 & 1))
                                });

                            trace!("Modified({:0b}) = {:?}", value, modified_instr);

                            let is_ok = {
                                let modified_state = {
                                    let mut s = base_state.clone();
                                    s.memory.data[0].2 = modified_instr.bytes().to_vec();
                                    s
                                };
                                let mut modified_result = self.o.observe(&modified_state);

                                if let (Ok(base_result), Ok(modified_result)) = (&base_result, &mut modified_result) {
                                    // Replace the modified instruction with the base instruction so that the memory is identical
                                    modified_result.memory.data[0].2 = base_result.memory.data[0].2.clone();
                                }

                                match (&base_result, &modified_result) {
                                    // We expect the instruction to either execute successfully or fail with a computation error
                                    // If we see anything else, something has gone horribly wrong during the previous steps.
                                    // In that case, it's probably best not to try and filter more bits because we can't be too sure
                                    // about the result.
                                    (Ok(a), Ok(b)) if a == b => true,
                                    (Err(OracleError::ComputationError), Err(OracleError::ComputationError)) => true,
                                    _ => {
                                        warn!("Found invalid DontCare bits between instruction {:?} and {:?} because of differences for inputs: {:?}; Outputs: {:X?} vs {:X?}", base_instr, modified_instr, base_state, base_result, modified_result);
                                        false
                                    }
                                }
                            };

                            if !is_ok {
                                if !randomize {
                                    // We are enumerating all possible DontCare values in ascending order.
                                    // All values before this were OK.
                                    // So the highest set bit must be the cause of this difference.
                                    // We remove that bit from the DontCare set, and try again.
                                    if let Some(highest_dontcare_index) = ((0usize).leading_zeros() - value.leading_zeros())
                                        .checked_sub(1)
                                        .map(|x| x as usize) {
                                        let bit_index = dont_care_indices.remove(highest_dontcare_index);
                                        encoding.bits[bit_index] = BitKind::Fixed(encoding.dataflows.addresses.instr.bit_at(bit_index));
                                    } else {
                                        assert_eq!(modified_instr, base_instr, "There is no highest_dontcare_index, so the instruction should be equal");
                                        // Just ignore this I guess? If we see this we are producing different results for multiple runs.
                                    }
                                } else {
                                    // We could try a more sophisticated approach, but randomized DontCare checks don't occur often.
                                    // For now it does not seem worth it to make this more complicated.
                                    dont_care_indices.retain(|&bit_index| {
                                        if base_instr.bit_at(bit_index) != modified_instr.bit_at(bit_index) {
                                            info!("Removing DontCare bit at index {}", bit_index);
                                            // Remove the bit from the encoding
                                            encoding.bits[bit_index] = BitKind::Fixed(encoding.dataflows.addresses.instr.bit_at(bit_index));

                                            false
                                        } else {
                                            true
                                        }
                                    });
                                }
                                
                                break;
                            }
                        }
                    }
                }
            } else {
                num_errs += 1;
            }
        }

        info!("DontCare validation, num_errs = {}", num_errs);

        Ok(())
    }

    pub fn remove_incorrect_generalizations(o: &mut O, encoding: &mut Encoding<A, BasicComputation>) -> bool {
        let mut rng = rand::thread_rng();
        let mut changed = false;
        for _ in 0..encoding.instr().bit_len() {
            if encoding.parts.len() <= 0 {
                break;
            }

            let mut bad_instrs = Vec::new();
            for n in 0..1000 {
                let part_values = encoding.parts.iter()
                    .map(|part| rng.gen::<u64>() & ((1 << part.size) - 1))
                    .collect::<Vec<_>>();
                if let Ok(instance) = encoding.instantiate(&part_values) {
                    if let Ok(base_state) = StateGen::randomize_new(&instance.addresses, &mut rng, o) {
                        let base_result = o.observe(&base_state);

                        // Modify all storage locations that aren't listed anywhere in instance
                        let active_locations = instance.iter_with_locations()
                            .flat_map(|o| o.iter()
                                .cloned()
                                .chain(o.target().cloned()
                                    .into_iter()
                                    .map(|d| Source::Dest(d))
                                ).collect::<Vec<_>>()
                            )
                            .filter(|loc| loc != &Location::Reg(A::Reg::zero()))
                            .collect::<Vec<_>>();

                        let all_locations: Vec<Location<A>> = A::Reg::iter()
                            .map(|reg| Location::Reg(reg))
                            .chain(instance.addresses.memory.iter().enumerate().filter(|(_, c)| c.kind != AccessKind::Executable).map(|(index, _)| Location::Memory(index)))
                            .chain(A::Flag::iter().map(|flag| Location::Flag(flag)))
                            .filter(|loc| loc != &Location::Reg(A::Reg::zero()))
                            .collect::<Vec<_>>();

                        trace!("Active locations = {:?}", active_locations);
                        
                        let mut state = base_state.clone();
                        let mut all_locations_with_bytes = Vec::new();
                        for loc in all_locations.iter() {
                            let mut bytes_to_keep_unchanged = vec![ false; instance.addresses.max_size_of(loc) ];
                            for active_loc in active_locations.iter().flat_map(|s| match s {
                                Source::Dest(d) => Some(d),
                                _ => None,
                            }) {
                                if loc == &Location::from(active_loc) {
                                    if let Some(size) = active_loc.size() {
                                        for n in size.start_byte..=size.end_byte {
                                            bytes_to_keep_unchanged[n] = true;
                                        }
                                    } else {
                                        // Keep all bytes unchanged
                                        for b in bytes_to_keep_unchanged.iter_mut() {
                                            *b = true;
                                        }

                                        break;
                                    }
                                }
                            }

                            if !bytes_to_keep_unchanged.iter().all(|b| *b) {
                                let current_value = base_state.location(loc);
                                StateGen::randomize_value(&mut rng, &current_value, &bytes_to_keep_unchanged, |new_value| {
                                    state.set_location(loc, new_value);
                                });
                            }

                            all_locations_with_bytes.push((loc.clone(), bytes_to_keep_unchanged));
                        }

                        trace!("All locations with bytes = {:?}", all_locations_with_bytes);

                        let new_result = o.observe(&state);
                        let equal = match (&base_result, &new_result) {
                            (Ok(base), Ok(new)) => {
                                let mut new = new.clone();
                                for flow in instance.output_dataflows() {
                                    if flow.unobservable_external_inputs {
                                        base.get_dest(&flow.target, |v| new.set_dest(&flow.target, v));
                                    }
                                }

                                let mut equal = true;
                                for (loc, bytes_to_keep_unchanged) in all_locations_with_bytes.iter() {
                                    if !base.get_location(loc).unwrap().equal_with_mixed_bytes(bytes_to_keep_unchanged, &new.get_location(loc).unwrap(), &state.get_location(loc).unwrap()) {
                                        info!("Difference in {:?} with bytes_unchanged = {:?}", loc, bytes_to_keep_unchanged);
                                        equal = false;
                                        break;
                                    }
                                }

                                equal
                            },
                            // TODO: Should we compare Err()s as well?
                            _ => true,
                        };

                        if !equal {
                            info!("Inconsistency for: {:?} vs {:?}; Results: {:?} vs {:?}", base_state, state, base_result, new_result);
                            bad_instrs.push(instance.addresses.instr.clone());
                        }
                    }
                }

                // Allow early break if instruction seems to be OK
                if n > 250 + bad_instrs.len() * 25 {
                    break;
                }
            }

            if bad_instrs.len() > 0 {
                let instr = encoding.instr();
                let mut responsible_bits = (0..instr.bit_len())
                    .map(|n| (n, bad_instrs.iter().filter(|bad| bad.bit_at(n) != instr.bit_at(n)).count()))
                    .collect::<Vec<_>>();
                responsible_bits.sort_by_key(|(_, c)| usize::MAX - c);
                info!("Remove most responsible bit: {:?} in {} / {:?}", responsible_bits, encoding, encoding);

                let v = responsible_bits[0].1 * 8 / 10;
                responsible_bits.retain(|(_, c)| *c >= v);

                // Choose the entry that removes the least good values and the most invalid values
                responsible_bits.sort_by_cached_key(|(n, _)| {
                    let (good, invalid) = encoding.preview_remove_bit(*n);
                    (good * 1000).checked_div(good + invalid).unwrap_or(usize::MAX)
                });

                info!("Choosing from: {:?}", responsible_bits);

                encoding.remove_bit(responsible_bits[0].0);

                info!("Resulting encoding: {} / {:?}", encoding, encoding);
                changed = true;
            } else {
                break;
            }
        }

        changed
    }

    pub fn infer(
        o: &mut O,
        cache: &CombinedCache<A>,
        dataflows: &Dataflows<A, BasicComputation>,
    ) -> Result<Encoding<A, BasicComputation>, EncodingError<A>> {
        let mut builder = EncodingAnalysis {
            o,
            cache,
            dataflows,
        };
        
        let mut dataflows = dataflows.clone();
        let mut bit_changes = builder.bit_changes()?;
        Self::cleanup_bit_changes(&mut bit_changes);

        let (bits, parts) = Self::create_parts(&mut dataflows, &bit_changes);
        let (mut parts, mut invalid_indices) = builder.fill_part_mapping(parts, &bits)?;

        info!("Invalid indices: {:?}", invalid_indices);
        println!("Invalid indices for {:02X?}: {:?}", dataflows.addresses.instr.bytes(), invalid_indices);

        invalid_indices.sort();
        let mut n = 0;
        let mut remapping = Vec::new();
        for index in 0..parts.len() {
            if !invalid_indices.contains(&index) {
                remapping.push(Some(n));
                n += 1;
            } else {
                remapping.push(None);
            }
        }

        for &index in invalid_indices.iter().rev() {
            parts.remove(index);
        }
        
        let mut bits = bits;
        for (bit_index, bit) in bits.iter_mut().enumerate() {
            match bit {
                BitKind::Value(n) => {
                    if let Some(remapped) = remapping[*n] {
                        *n = remapped;
                    } else {
                        *bit = BitKind::Fixed(dataflows.addresses.instr.bit_at(bit_index));
                    }
                }
                BitKind::Fixed(_) | BitKind::DontCare => {}
            }
        }

        for part in parts.iter_mut() {
            let locations = match &mut part.mapping {
                PartMapping::ValueImm { locations, .. } => locations,
                PartMapping::Register { locations, .. } => locations,
                PartMapping::Size { locations, .. } => locations,
            };

            for location in locations.iter_mut() {
                // Adjust locations such that they refer to the correct entry again
                let (inputs, input_index) = match location {
                    FlowValueLocation::InputForOutput { output_index, input_index } => {
                        (&dataflows.outputs[*output_index].inputs, input_index)
                    }
                    FlowValueLocation::MemoryAddress { memory_index, input_index } => {
                        (&dataflows.addresses.memory[*memory_index].inputs, input_index)
                    }
                    FlowValueLocation::Output(_) => continue,
                };

                let before = inputs.iter().take(*input_index).filter(|i| match i {
                    Source::Imm(n) if invalid_indices.contains(n) => true,
                    _ => false,
                }).count();

                *input_index -= before;
            }
        }

        // Remove Imms from dataflows as well
        dataflows = dataflows.map(dataflows.addresses.instr, |_, source| -> Result<_, EncodingError<A>> {
            Ok(match source {
                Source::Imm(n) => if let Some(new_n) = remapping[*n] {
                    Some(Source::Imm(new_n))
                } else {
                    None
                },
                other => Some(other.clone()),
            })
        })?;

        // Remove the calculation in all places where we added an immediate value
        for access in dataflows.addresses.memory.iter_mut() {
            if access.inputs.iter().any(|i| match i {
                Source::Imm(_) => true,
                Source::Const { .. } => true,
                Source::Dest(_) => false,
            }) {
                access.calculation = None;
            }
        }

        let mut encoding = Encoding::<A, BasicComputation> {
            bits,
            dataflows,
            parts,
        };

        if encoding.bits.iter().any(|b| matches!(b, BitKind::DontCare)) {
            // Make sure the DontCare bits really don't make a difference
            builder.validate_dontcare(&mut encoding)?;
        }

        Self::remove_incorrect_generalizations(o, &mut encoding);

        Ok(encoding)
    }
}