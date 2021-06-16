use std::{collections::HashMap, collections::HashSet, fmt::Debug, marker::PhantomData, ops::Range, time::Instant};
use log::{debug, info, trace, warn};
use rand::Rng;
use rand::prelude::SliceRandom;
use maplit::{hashmap, hashset};
use thiserror::Error;
use liblisa_core::{accesses::{AccessKind, MemoryAccesses}, arch::{Arch, Flag, Register, SystemState, Value}, oracle::{Oracle, OracleError}, randomized_bytes};
use liblisa_core::{Source, Inputs, Dest, IntoDestWithSize, IntoSourceWithSize, Location, Size, randomized_value};
use liblisa_core::computation::BasicComputation;
use liblisa_core::dataflow::{Dataflows, Flow};
use liblisa_core::gen::{StateGen, RandomizationError, ModifySingleLocationIter};
use crate::accesses::{MemoryAccessAnalysis, FindInputError};

#[derive(Error, Debug, Clone)] 
pub enum DataflowError<A: Arch> {
    #[error("An oracle invocation returned an error: {}. This should not be possible, and means that constraint analysis failed. State: {:X?}", .0, .1)]
    ConstraintAnalysisInvalid(OracleError, SystemState<A>),

    #[error("Unable to randomize: {}", .0)]
    Randomization(RandomizationError),

    #[error("Unable to find input for {:?}: {}", .0, .1)]
    FindInputFailed(Location<A>, FindInputError),

    #[error("Unable to generate enough bases to do dataflow analysis")]
    UnableToGenerateBases,
}

impl<A: Arch> From<RandomizationError> for DataflowError<A> {
    fn from(e: RandomizationError) -> Self {
        DataflowError::Randomization(e)
    }
}

struct OutputSizeAnalyzer<'a, A: Arch, O: Oracle<A>> {
    oracle: &'a mut O,
    sizes: HashMap<Location<A>, Size>,
    locations: &'a [Location<A>],
    _phantom: PhantomData<A>,
}

impl<'a, A: Arch, O: Oracle<A>> OutputSizeAnalyzer<'a, A, O> {
    pub fn new(oracle: &'a mut O, locations: &'a [Location<A>]) -> OutputSizeAnalyzer<'a, A, O> {
        Self {
            oracle,
            sizes: hashmap! [
                // Set the program counter to always be the full size
                Location::Reg(A::Reg::pc()) => Size::new(0, 7),   
            ],
            locations,
            _phantom: Default::default(),
        }
    }
}

fn find_size_constraints(from: &[u8], to: &[u8]) -> Size {
    let mut lower = from.len().max(to.len());
    let mut upper = 0;
    for (index, (a, b)) in from.iter().zip(to.iter()).enumerate() {
        if a != b {
            lower = lower.min(index);
            upper = upper.max(index);
        }
    }

    Size::new(lower, upper)
}

impl<'a, A: Arch, O: Oracle<A>> Oracle<A> for OutputSizeAnalyzer<'a, A, O> {
    fn valid_executable_addresses(&mut self) -> Range<u64> {
        self.oracle.valid_executable_addresses()
    }

    fn can_map(&mut self, addr: u64) -> bool {
        self.oracle.can_map(addr)
    }

    fn page_size(&mut self) -> u64 {
        self.oracle.page_size()
    }

    fn observe(&mut self, before: &SystemState<A>) -> Result<SystemState<A>, OracleError> {
        let result = self.oracle.observe(before);

        if let Ok(result) = &result {
            for loc in self.locations.iter() {
                let left = before.get_location(loc);
                let right = result.get_location(loc);
                if let (Some(left), Some(right)) = (left, right) {
                    if left != right {
                        let size_range = find_size_constraints(&left.to_le_bytes(), &right.to_le_bytes());
                        let size = if let Some(size) = self.sizes.get_mut(loc) {
                            size
                        } else {
                            self.sizes.insert(loc.clone(), Size::new(999, 0));
                            self.sizes.get_mut(loc).unwrap()
                        };
                        *size = size.union(&size_range);
                    }
                }
            }
        }

        result
    }

    fn observe_carefully(&mut self, _before: &SystemState<A>) -> Result<SystemState<A>, OracleError> {
        todo!()
    }

    fn debug_dump(&mut self) {
        self.oracle.debug_dump()
    }

    fn scan_unspecified_memory_accesses(&mut self, _before: &SystemState<A>) -> Result<Vec<u64>, OracleError> {
        todo!()
    }

    fn restart(&mut self) {
        self.oracle.restart()
    }

    fn kill(self) {
        todo!()
    }
}


pub struct DataflowAnalysis;

impl DataflowAnalysis {
    fn outputs_are_different<A: Arch>(base_in: &SystemState<A>, base_out: &SystemState<A>, new_in: &SystemState<A>, new_out: &SystemState<A>, loc: &Location<A>) -> bool {
        // We need to take into account the possibility that the output register is also an input. In that case, we don't want to detect
        // a change in value as a real change. In particular, if only a part of the output is updated we don't want to detect a change
        // every time we modify the part of the output that isn't updated by the instruction.

        // For example: mov al, dl copies the lower 8 bits of rdx into rax. Consider two possible input-output pairs for rax:
        // old: (rax=0510, rdx=99) -> 0599
        // new: (rax=3010, rdx=99) -> 3099
        // this shouldn't be seen as a change.

        // However, we do want ORring to be seen as change. For example, [or rax, 0x100]
        // old: 0010 -> 0110
        // new: 0f53 -> 0f53
        // Ideally we would want to detect a change between the new input and the new output compared to the old input and the old output as well.
        // We cannot do this, as ORing is in fact just overwriting bits with a '1'. In that sense, we don't make use of the old value.
        // However, we only split inputs on a byte-level, so there is no point in trying to detect changes here at the bit-level.

        // ? I argue that it might be cleaner to consider rax to be an input in the mov al, dl example -- at least temporary until we have determined the sizes of the inputs.

        let base_in = base_in.location(loc);
        let base_out = base_out.location(loc);
        let new_in = new_in.location(loc);
        let new_out = new_out.location(loc);

        // If the output storage location had the same value before execution in both cases, we can just compare the values after execution directly.
        if base_in == new_in {
            return base_out != new_out;
        }

        // If the output storage location did not have the same value before execution in both cases, we are going to determine which
        // bytes are changing from input to output, and then compare only those bytes. This way we don't consider the bytes that we
        // changed ourselves, and could potentially give false positives.
        // base_in value, base_out value, new_in value, new_out value
        // mask = ((base_in ^ base_out) | (new_out ^ new_in))
        // expand for every byte in mask the value to 0b1111_1111 if it is not equal to 0b0000_0000
        // masked_new = (mask & new_out)
        // masked_old = (mask & old_out)
        base_in.xor(&base_out, |old_mask| 
            new_out.xor(&new_in, |new_mask| {
                old_mask.or(&new_mask, |mask| {
                    if let Location::Flags = loc {
                        // Flags are special because we have an 'any flag' register (Location::Flags) as well as separate flags (Location::Flag(f))
                        // We cannot compare on a byte-level here, because it interferes with the separate flags
                        mask.and(&new_out, |masked_new| { 
                            mask.and(&base_out, |masked_old| {
                                if masked_new != masked_old {
                                    debug!("Difference for masked outputs {:?}, {:?} vs {:?}; Inputs were: {:?} and {:?}", loc, masked_old, masked_new, base_in, new_in);
                                }

                                masked_new != masked_old
                            })
                        })
                    } else {
                        // We compare normal values on a byte level
                        mask.expand_to_bytes(|mask| mask.and(&new_out, |masked_new| {
                            mask.and(&base_out, |masked_old| {                                if masked_new != masked_old {
                                    debug!("Difference for masked outputs {:?}, {:?} vs {:?}; Inputs were: {:?} and {:?}", loc, masked_old, masked_new, base_in, new_in);
                                }

                                masked_new != masked_old
                            })
                        }))
                    }
                })
            })
        )
    }

    pub fn infer<A: Arch + 'static, O: Oracle<A>>(o: &mut O, memory_accesses: &MemoryAccesses<A, BasicComputation>) -> Result<Dataflows<A, BasicComputation>, DataflowError<A>> {
        let mut rng = rand::thread_rng();
        let mut rng2 = rand::thread_rng();

        let output_locations: Vec<Location<A>> = A::Reg::iter()
            .map(|reg| Location::Reg(reg))
            .chain(memory_accesses.memory.iter().enumerate().filter(|(_, c)| c.kind != AccessKind::Executable).map(|(index, _)| Location::Memory(index)))
            .chain(vec![ Location::Flags ].into_iter())
            .collect::<Vec<_>>();

        let input_locations: Vec<Location<A>> = A::Reg::iter()
            .map(|reg| Location::Reg(reg))
            .chain(memory_accesses.memory.iter().enumerate().filter(|(_, c)| c.kind != AccessKind::Executable).map(|(index, _)| Location::Memory(index)))
            .chain(A::Flag::iter().map(|flag| Location::Flag(flag)))
            .collect::<Vec<_>>();

        let mut o = OutputSizeAnalyzer::new(o, &output_locations);
        let o = &mut o;

        let mut outputs = HashSet::new();
        let mut flows: Vec<Flow<A, BasicComputation>> = Vec::new();
        let mut bases = Vec::new();

        for k in 0..50_000 {
            if let Ok(base) = StateGen::randomize_new(&memory_accesses, &mut rng, o) {
                match o.observe(&base) {
                    Err(OracleError::ComputationError) | Err(OracleError::GeneralFault) => {},
                    Err(e) => Err(DataflowError::ConstraintAnalysisInvalid(e, base))?,
                    Ok(base_result) => {
                        bases.push((base, base_result));
                    }
                }
            }

            if bases.len() < (k / 200usize).checked_sub(500).unwrap_or(0) {
                return Err(DataflowError::UnableToGenerateBases);
            }

            let extra = match (k + 1 - bases.len()) / 100 {
                0 => 0,
                1 => 1000,
                2 => 1500,
                3 => 2000,
                4 => 2250,
                5 => 2500,
                _ => 3000,
            };

            if bases.len() >= 5000 + k / 5 + extra {
                break;
            }
        }

        info!("Bases generated: {}", bases.len());
        let addr_locs = memory_accesses.memory.iter()
            .flat_map(|m| m.inputs.iter())
            .flat_map(|s| match s {
                Source::Dest(d) => Some(Location::from(d)),
                _ => None,
            })
            .collect::<HashSet<_>>();

        let mut extra_bases = Vec::new();
        for (index, (base_in, _)) in bases.iter().take(bases.len() / 20).enumerate() {
            let r = if index < 25 {
                0
            } else if index < 50 {
                0xff
            } else {
                rng.gen::<u8>()
            };
            let mut state = base_in.clone();
            // Set non-memory locations
            for loc in input_locations.iter() {
                if !addr_locs.contains(loc) {
                    let original_value = base_in.get_location(loc).unwrap();
                    let v;
                    let new_value = match original_value {
                        Value::Num(_) => Value::Num(u64::from_le_bytes([ r, r, r, r, r, r, r, r ])),
                        Value::FlagBitmap(v) => Value::FlagBitmap(v),
                        Value::Bytes(b) => {
                            v = std::iter::repeat(r).take(b.len()).collect::<Vec<_>>();
                            Value::Bytes(&v)
                        }
                    };

                    state.set_location(loc, new_value);
                }
            }

            // Try to set a few memory locations as well
            // TODO: This is somewhat x86-64 specific logic.
            // On x86-64, the only byte filling pattern that always generates a valid memory address is 0x0; 
            // Many CPUs use a 48-bit canonical address space, so anything that sets the upper 16 bits non-zero will not be valid.
            if r == 0 {
                let mut addr_locs = addr_locs.iter().collect::<Vec<_>>();
                addr_locs.shuffle(&mut rng);
                for loc in addr_locs {
                    let backup = state.clone();

                    let original_value = base_in.get_location(loc).unwrap();
                    let v;
                    let new_value = match original_value {
                        Value::Num(_) => Value::Num(u64::from_le_bytes([ r, r, r, r, r, r, r, r ])),
                        Value::FlagBitmap(v) => Value::FlagBitmap(v),
                        Value::Bytes(b) => {
                            v = std::iter::repeat(r).take(b.len()).collect::<Vec<_>>();
                            Value::Bytes(&v)
                        }
                    };

                    state.set_location(loc, new_value);
                    if !StateGen::adapt(memory_accesses, o, &mut state, &hashset![ loc.clone() ], false)? {
                        state = backup;
                    }
                }
            }

            let state = state;
            match o.observe(&state) {
                Ok(result) => extra_bases.push((state.clone(), result)),
                Err(OracleError::ComputationError) => continue,
                Err(OracleError::GeneralFault) => continue,
                Err(e) => Err(DataflowError::ConstraintAnalysisInvalid(e, state.clone()))?,
            }

            // Try setting address inputs to (-1)
            for loc in addr_locs.iter() {
                let mut modified_state = state.clone();

                let original_value = base_in.get_location(loc).unwrap();
                let v;
                let r = 0xff;
                let new_value = match original_value {
                    Value::Num(_) => Value::Num(u64::from_le_bytes([ r, r, r, r, r, r, r, r ])),
                    Value::FlagBitmap(v) => Value::FlagBitmap(v),
                    Value::Bytes(b) => {
                        v = std::iter::repeat(r).take(b.len()).collect::<Vec<_>>();
                        Value::Bytes(&v)
                    }
                };

                modified_state.set_location(loc, new_value);
                if StateGen::adapt_with_modifications(memory_accesses, o, &mut modified_state, &hashset![ loc.clone() ], false, &hashset![ loc.clone() ])? {
                    match o.observe(&modified_state) {
                        Ok(result) => extra_bases.push((modified_state, result)),
                        Err(OracleError::ComputationError) | Err(OracleError::GeneralFault) => {},
                        Err(e) => Err(DataflowError::ConstraintAnalysisInvalid(e, modified_state))?,
                    }
                }
            }

            // Try setting address inputs to a checkerboard pattern
            for loc in addr_locs.iter() {
                let mut modified_state = state.clone();

                let original_value = base_in.get_location(loc).unwrap();
                let v;
                let r = 0x55;
                let new_value = match original_value {
                    Value::Num(_) => Value::Num(u64::from_le_bytes([ r, r, r, r, r, r, r, r ])),
                    Value::FlagBitmap(v) => Value::FlagBitmap(v),
                    Value::Bytes(b) => {
                        v = std::iter::repeat(r).take(b.len()).collect::<Vec<_>>();
                        Value::Bytes(&v)
                    }
                };

                modified_state.set_location(loc, new_value);
                if StateGen::adapt_with_modifications(memory_accesses, o, &mut modified_state, &hashset![ loc.clone() ], false, &hashset![ loc.clone() ])? {
                    match o.observe(&modified_state) {
                        Ok(result) => {
                            extra_bases.push((modified_state, result))
                        },
                        Err(OracleError::ComputationError) | Err(OracleError::GeneralFault) => {},
                        Err(e) => Err(DataflowError::ConstraintAnalysisInvalid(e, modified_state))?,
                    }
                }
            }

            // Make some small modifications
            for _ in 0..if r == 0 { 150 } else { 10 } {
                let mut modified_state = state.clone();
                let num_changes = A::Reg::iter().count() / 2;
                for _ in 0..num_changes {
                    let loc = &input_locations[rng.gen_range(0, input_locations.len())];
                    let backup = modified_state.clone();

                    let original_value = base_in.get_location(loc).unwrap();
                    let v;
                    let new_value = match original_value {
                        Value::Num(_) => Value::Num(randomized_value(&mut rng)),
                        Value::FlagBitmap(v) => Value::FlagBitmap(v),
                        Value::Bytes(b) => {
                            v = randomized_bytes(&mut rng, b.len());
                            Value::Bytes(&v)
                        }
                    };

                    modified_state.set_location(loc, new_value);

                    if addr_locs.contains(loc) {
                        if !StateGen::adapt(memory_accesses, o, &mut modified_state, &hashset![ loc.clone() ], false)? {
                            modified_state = backup;
                        }
                    }
                }

                match o.observe(&modified_state) {
                    Ok(result) => extra_bases.push((modified_state, result)),
                    Err(OracleError::ComputationError) | Err(OracleError::GeneralFault) => {},
                    Err(e) => Err(DataflowError::ConstraintAnalysisInvalid(e, modified_state))?,
                }
            }

            // Try to set memory locations to '1' and randomly set registers to '0'. This helps fuzz overflows that produce exceptions.
            let memory_locs = (1..memory_accesses.memory.len()).map(|n| Location::Memory(n)).collect::<Vec<_>>();
            for le in &[false, true] {
                for loc in memory_locs.iter() {
                    let mut modified_state = state.clone();
                    let num_zeroed = A::Reg::iter().count() / 2;
                    let original_value = base_in.get_location(loc).unwrap();
                    let v;
                    let new_value = match original_value {
                        Value::Bytes(b) => {
                            if *le {
                                v = std::iter::repeat(0).take(b.len() - 1).chain(std::iter::once(1)).collect::<Vec<_>>();
                            } else {
                                v = std::iter::once(1).chain(std::iter::repeat(0).take(b.len() - 1)).collect::<Vec<_>>();
                            }
                            Value::Bytes(&v)
                        }
                        _ => panic!("Memory should always contain bytes"),
                    };

                    modified_state.set_location(loc, new_value);
                    if StateGen::adapt(memory_accesses, o, &mut modified_state, &hashset![ loc.clone() ], false)? {
                        for _ in 0..num_zeroed {
                            match o.observe(&modified_state) {
                                Ok(result) => {
                                    extra_bases.push((modified_state, result));
                                    break
                                },
                                Err(OracleError::ComputationError) | Err(OracleError::GeneralFault) => {
                                    // Set a register to zero and try again
                                    let loc = &input_locations[rng.gen_range(0, input_locations.len())];
                                    let backup = modified_state.clone();

                                    let original_value = base_in.get_location(loc).unwrap();
                                    let v;
                                    let new_value = match original_value {
                                        Value::Num(_) => Value::Num(0),
                                        Value::FlagBitmap(v) => Value::FlagBitmap(v),
                                        Value::Bytes(b) => {
                                            v = std::iter::repeat(0).take(b.len()).collect::<Vec<_>>();
                                            Value::Bytes(&v)
                                        }
                                    };

                                    modified_state.set_location(loc, new_value);
                                    if addr_locs.contains(loc) {
                                        if !StateGen::adapt(memory_accesses, o, &mut modified_state, &hashset![ loc.clone() ], false)? {
                                            modified_state = backup;
                                        }
                                    }
                                },
                                Err(e) => return Err(DataflowError::ConstraintAnalysisInvalid(e, modified_state)),
                            }
                        }
                    }
                }
            }
        }

        bases.extend(extra_bases.into_iter());
        let bases = bases;
        info!("Bases extended to: {}", bases.len());
        
        if bases.len() <= 5000 {
            return Err(DataflowError::UnableToGenerateBases);
        }

        let mut extra_bases: Option<Vec<(SystemState<A>, SystemState<A>)>> = None;

        // TODO: We can be more efficient here; We can scan by altering all non-inputs or non-outputs at the same time, and seeing if we observe any input/output behaviour. If not, we should assume that we have identified all inputs/outputs.
        for (base_state, result) in bases.iter() {
            for loc in output_locations.iter().filter(|loc| !outputs.contains(*loc)).collect::<Vec<_>>() {
                if result.location(loc) != base_state.location(loc) {
                    info!("Output identified: {:?} based on difference {:?} vs {:?}", loc, base_state.location(loc), result.location(loc));
                    trace!("{:?} vs {:?}", base_state, result);
                    let before_inputs = Instant::now();
                    let mut fast_inputs = HashSet::new();
                    let mut not_input_locations = input_locations.clone();
                    let mut num_errors = 0;
                    let mut unobservable_external_inputs = false;
                    for (base_in, base_out) in bases.iter() {
                        // TODO: What if modifying values always fails?
                        if let Some(Ok(r)) = ModifySingleLocationIter::new(&memory_accesses, &mut rng, o, base_in.clone(), &not_input_locations).next() {
                            let (new_in, new_out) = r;
                            
                            // TODO: workaround for the fact that iter_with_modified_locations sometimes changes more values than specified
                            // TODO: This if condition should no longer be needed
                            if fast_inputs.iter().all(|loc| base_in.location(loc) == new_in.location(loc)) {
                                if matches!(new_out, Err(OracleError::ComputationError)) {
                                    continue;
                                }
                                if matches!(new_out, Err(OracleError::GeneralFault)) {
                                    continue;
                                }

                                let new_out = new_out.map_err(|e| DataflowError::ConstraintAnalysisInvalid(e, new_in.clone()))?;
                                if Self::outputs_are_different(base_in, base_out, &new_in, &new_out, loc) {
                                    debug!("Trying to find input for {:X?} in {:X?}", loc, output_locations);

                                    let fast_inputs_copy = fast_inputs.clone();
                                    for _ in 0..20 {
                                        match MemoryAccessAnalysis::find_input(&memory_accesses, o, &mut rng2, base_in, &not_input_locations, &mut fast_inputs, &|_, new_in, new_out| {
                                            let new_result = new_out.as_ref().map_err(|e| e.clone())?;

                                            Ok(Self::outputs_are_different(base_in, base_out, new_in, new_result, loc))
                                        }) {
                                            Ok(_) => break,
                                            Err(FindInputError::UnobservableExternalInputs) => {
                                                // Set flag and revert any inputs that might have been added
                                                unobservable_external_inputs = true;
                                                fast_inputs = fast_inputs_copy.clone();
                                                break
                                            }
                                            Err(e) => {
                                                num_errors += 1;
                                                if num_errors > bases.len() * 2 {
                                                    return Err(DataflowError::FindInputFailed(loc.clone(), e));
                                                }
                                            }
                                        }
                                    }

                                    // If we found new inputs, we have to verify that none of them were detected because instructions
                                    // change outputs based on some external input that we cannot observe (i.e., RDRAND, but also things like LSL)
                                    if fast_inputs.len() != fast_inputs_copy.len() {
                                        for _ in 0..50 {
                                            let second_observation = o.observe(&new_in);
                                            if second_observation.as_ref().ok() != Some(&new_out) {
                                                warn!("This instruction uses external input that we cannot observe (via new_out)");
                                                unobservable_external_inputs = true;
                                                fast_inputs = fast_inputs_copy;
                                                break;
                                            }

                                            let second_observation = o.observe(&base_in);
                                            if second_observation.as_ref().ok() != Some(&base_out) {
                                                warn!("This instruction uses external input that we cannot observe (via base_out)");
                                                unobservable_external_inputs = true;
                                                fast_inputs = fast_inputs_copy;
                                                break;
                                            }
                                        }
                                    }

                                    not_input_locations.retain(|loc| !fast_inputs.contains(loc));
                                }
                            } else {
                                unreachable!();
                            }
                        }
                    }

                    info!("Found inputs in {}ms: {:?}", (Instant::now() - before_inputs).as_millis(), fast_inputs);

                    let start = Instant::now();
                    // TODO: Instead of including bytes that we can observe changing, exclude bytes where we don't observe any changes (this makes a difference for cases where we're not able to observe anything due to errors)
                    let mut sized_inputs = Vec::new();
                    for input in fast_inputs.iter() {
                        let fast_size: Option<Size>;
                        if let Location::Flags = &input {
                            fast_size = Some(Size::new(0, 7));
                        } else if let Location::Flag(_) = &input {
                            fast_size = Some(Size::new(0, 0));  
                        } else if memory_accesses.max_size_of(input) == 1 {
                            // If there is only one byte, it must be the byte that is being used.
                            fast_size = Some(Size::new(0, 0));
                        } else if &Location::Reg(A::Reg::pc()) == input && &Location::Reg(A::Reg::pc()) == loc {
                            // Assume the program counter always uses the entire 64-bit register when updating the program counter
                            fast_size = Some(Size::new(0, 7));
                        } else {
                            // TODO: Binary search? Or at least fuzz multiple outputs at the same time?
                            let max_size = memory_accesses.max_size_of(input);
                            let mut bytes = vec![ false; max_size ];

                            info!("Determining size of {:?} for output {:?}", input, loc);

                            let iter = if loc == input || loc == &Location::Flags {
                                if let Some(extra_bases) = &extra_bases {
                                    extra_bases.iter()
                                } else {
                                    let mut v = (0..8_000).map(|_| -> Result<(_, _), RandomizationError> {
                                            let base = StateGen::randomize_new(&memory_accesses, &mut rng, o)?;
                                            let base_result = o.observe(&base);
                                            Ok((base, base_result))
                                        })
                                        .flat_map(|v| v.ok())
                                        .filter(|(_, base_result)| !matches!(base_result, Err(OracleError::ComputationError)))
                                        .filter(|(_, base_result)| !matches!(base_result, Err(OracleError::GeneralFault)))
                                        .map(|(base, base_result)| match base_result {
                                            Ok(base_result) => Ok((base, base_result)),
                                            Err(e) => Err(DataflowError::ConstraintAnalysisInvalid(e, base)),
                                        })
                                        .collect::<Result<Vec<_>, _>>()?;
                                    info!("Additional bases generated: {}", v.len());
                                    v.extend_from_slice(&bases);
                                    extra_bases = Some(v);

                                    extra_bases.as_ref().unwrap().iter()
                                }
                            } else {
                                bases.iter()
                            };

                            if !bytes.iter().all(|b| *b) {
                                'outer2: for (base_in, base_out) in iter {
                                    for _ in 0..4 {
                                        let mut new_in = base_in.clone();
                                        StateGen::randomize_value(&mut rng, &base_in.location(input), &bytes, |new_value| {
                                            new_in.set_location(input, new_value);
                                        });

                                        // Justification for adapt_with_modifications:
                                        // We have already identified all inputs.
                                        // (assuming we fuzzed properly, which we must assume if we want to do anything useful with the result)
                                        // Changing any register that is not used as input is therefore not a problem.
                                        // This allows better identification of operand size when a register is used both as operand and for the memory address.
                                        if StateGen::adapt_with_modifications(&memory_accesses, o, &mut new_in, &hashset![ input.clone() ], false, &fast_inputs)? {
                                            let new_out = o.observe(&new_in);
                                            if let Ok(new_result) = new_out {
                                                if base_out.location(loc) != new_result.location(loc) && (loc != input || !base_out.location(loc).equal_with_mixed_bytes(&bytes, &new_result.location(loc), &new_in.location(loc))) {
                                                    debug!("Found difference {:?} vs {:?} ({:?} of base_out/new_out) at bytes {:?}, which was {:?} vs {:?} before ({:?} of base_in,new_in);", base_out.location(loc), new_result.location(loc), loc, &bytes, base_in.location(loc), new_in.location(loc), loc);
                                                    debug!("Full inputs: {:?} and {:?}", base_in, new_in);

                                                    // Now we need to figure out which byte that was.
                                                    let indexes = bytes.iter().enumerate()
                                                        .filter(|(_, keep)| !**keep)
                                                        .map(|(index, _)| index)
                                                        .collect::<Vec<_>>();
                                                    let found = Self::find_size(o, &mut rng, memory_accesses, &mut bytes, &indexes, &base_in, &base_out, input, loc, &fast_inputs)?;

                                                    if !found {
                                                        Self::find_size(o, &mut rng, memory_accesses, &mut bytes, &indexes, &new_in, &new_result, input, loc, &fast_inputs)?;
                                                    }
                                                    debug!("New bytes = {:?}", bytes);
                                                    if let Some(first_index) = bytes.iter().position(|b| *b) {
                                                        let last_index = bytes.len() - bytes.iter().rev().position(|b| *b).unwrap();

                                                        for b in bytes[first_index..last_index].iter_mut() {
                                                            *b = true;
                                                        }
                                                    }

                                                    debug!("Filled in bytes = {:?}", bytes);
                                                    if bytes.iter().all(|b| *b) {
                                                        break 'outer2;
                                                    }
                                                }
                                            } else {
                                                warn!("Execution after remapping failed for input {:?} of output {:?}", input, loc);
                                            }
                                        } else {
                                            trace!("Could not adapt state to check for input size on {:?} of output {:?}", input, loc);
                                        }
                                    }
                                }
                            }

                            fast_size = if let Some(first_index) = bytes.iter().position(|b| *b) {
                                let last_index = bytes.len() - bytes.iter().rev().position(|b| *b).unwrap();

                                Some(Size::new(first_index, last_index - 1))
                            } else {
                                None
                            };
                        }

                        let size = fast_size;
                        debug!("Size for input {:?} to output {:?} appears to be {:?}", input, loc, size);
                        sized_inputs.push(input.clone().into_source_with_size(size.unwrap_or(Size::qword())));
                    }

                    info!("Determining input sizes took {}ms", (Instant::now() - start).as_millis());

                    outputs.insert(loc.clone());
                    flows.push(Flow {
                        target: loc.clone().into_dest_with_size(o.sizes.get(loc).cloned().unwrap_or(Size::qword())),
                        inputs: Inputs::sorted(sized_inputs),
                        unobservable_external_inputs,
                        computation: None,
                    });
                }
            }
        }

        // TODO: We should be focussing our observations on edge cases for constants if possible (i.e. rip always gets +n, where N is < 16, so we should try to generate a value like 0xffffffffffff to observe as many bytes as possible changing.

        let mut max_sizes = o.sizes.clone();
        for flow in flows.iter_mut() {
            match &mut flow.target {
                Dest::Reg(reg, size) => {
                    if let Some(output_size) = o.sizes.get(&Location::Reg(reg.clone())) {
                        *size = output_size.clone();
                    }
                },
                Dest::Mem(index, size) => {
                    if let Some(output_size) = o.sizes.get(&Location::Memory(*index)) {
                        *size = output_size.clone();
                    }
                },
                Dest::Flags | Dest::Flag(_) => {},
            }

            for input in flow.inputs.iter() {
                if let Source::Dest(d) = input {
                    let loc = Location::from(d.clone());
                    let prev = max_sizes.get(&loc).cloned();
                    if let Some(size) = d.size() {
                        max_sizes.insert(loc, if let Some(prev) = prev {
                            size.union(&prev)
                        } else {
                            size
                        });
                    }
                }
            }
        }

        for flow in flows.iter_mut() {
            if flow.target == Dest::Flags {
                for input in flow.inputs.iter_mut() {
                    if let Source::Dest(d) = input {
                        let loc = Location::from(d.clone());
                        if let Some(max_size) = max_sizes.get(&loc) {
                            match d {
                                Dest::Reg(_, size) | Dest::Mem(_, size) => {
                                    *size = size.union(max_size);
                                }
                                Dest::Flag(_) | Dest::Flags => {}
                            }
                        }
                    }
                }
            }
        }

        flows.sort_by_key(|x| x.target.clone());
        info!("Output sizes: {:?}", o.sizes);

        Ok(Dataflows {
            addresses: memory_accesses.clone(),
            outputs: flows,
        })
    }

    fn find_size<A: Arch + 'static, R: Rng, O: Oracle<A>>(o: &mut O, rng: &mut R, constraints: &MemoryAccesses<A, BasicComputation>, bytes: &mut [bool], indexes: &[usize], base_in: &SystemState<A>, base_out: &SystemState<A>, input: &Location<A>, loc: &Location<A>, fixed: &HashSet<Location<A>>) -> Result<bool, DataflowError<A>> {
        if indexes.len() <= 0 {
            return Ok(false);
        }
        
        if indexes.len() == 1 {
            let split_bytes = bytes.iter().enumerate().map(|(index, b)| *b || !indexes.contains(&index)).collect::<Vec<_>>();
            trace!("Verifying {:?} = {:?}", indexes, split_bytes);
            for _ in 0..200 {
                let mut new_in = base_in.clone();
                StateGen::randomize_value(rng, &base_in.location(input), &split_bytes, |new_value| {
                    new_in.set_location(input, new_value);
                });

                if StateGen::adapt_with_modifications(constraints, o, &mut new_in, &hashset![ input.clone() ], false, fixed)? {
                    let new_out = o.observe(&new_in);
                    if let Ok(new_result) = new_out {
                        if base_out.location(loc) != new_result.location(loc) && (loc != input || !base_out.location(loc).equal_with_mixed_bytes(&split_bytes, &new_result.location(loc), &new_in.location(loc))) {
                            debug!("Found difference {:?} vs {:?} at byte {:?}, with inputs {:?} vs {:?};", base_out.location(loc), new_result.location(loc), &indexes, base_in.location(loc), new_in.location(loc));
                            bytes[indexes[0]] = true;
                            return Ok(true);
                        }
                    } else {
                        warn!("Execution after remapping failed for input {:?} of output {:?}", input, loc);
                    }
                } else {
                    trace!("Could not adapt state to check for input size on {:?} of output {:?}", input, loc);
                }
            }
        } else {
            let split_size = indexes.len() / 2;
            let (left, right) = indexes.split_at(split_size);

            for _ in 0..1000 {
                trace!("Trying 5 randomizations on each side of the split: {:?} ==> {:?} & {:?}", indexes, left, right);
                let mut found = false;
                let mut result = false;

                let left_split_bytes = bytes.iter().enumerate().map(|(index, b)| *b || !left.contains(&index)).collect::<Vec<_>>();
                let right_split_bytes = bytes.iter().enumerate().map(|(index, b)| *b || !right.contains(&index)).collect::<Vec<_>>();

                // Left side
                trace!("Left: {:?}", left_split_bytes);
                for _ in 0..5 {
                    let mut new_in = base_in.clone();
                    StateGen::randomize_value(rng, &base_in.location(input), &left_split_bytes, |new_value| {
                        new_in.set_location(input, new_value);
                    });
    
                    if StateGen::adapt_with_modifications(constraints, o, &mut new_in, &hashset![ input.clone() ], false, fixed)? {
                        let new_out = o.observe(&new_in);
                        if let Ok(new_result) = new_out {
                            if base_out.location(loc) != new_result.location(loc) && (loc != input || !base_out.location(loc).equal_with_mixed_bytes(&left_split_bytes, &new_result.location(loc), &new_in.location(loc))) {
                                result |= Self::find_size(o, rng, constraints, bytes, left, base_in, base_out, input, loc, fixed)?;
                                found = true;
                                break;
                            }
                        } else {
                            warn!("Execution after remapping failed for input {:?} of output {:?}", input, loc);
                        }
                    } else {
                        trace!("Could not adapt state to check for input size on {:?} of output {:?}", input, loc);
                    }
                }

                // Right side
                trace!("Right: {:?}", right_split_bytes);
                for _ in 0..5 {
                    let mut new_in = base_in.clone();
                    StateGen::randomize_value(rng, &base_in.location(input), &right_split_bytes, |new_value| {
                        new_in.set_location(input, new_value);
                    });
    
                    if StateGen::adapt_with_modifications(constraints, o, &mut new_in, &hashset![ input.clone() ], false, fixed)? {
                        let new_out = o.observe(&new_in);
                        if let Ok(new_result) = new_out {
                            trace!("New In: {:X?}; New Out: {:X?}", new_in, new_result);
                            trace!("Base In: {:X?}; Base Out: {:X?}", base_in, base_out);
                            if base_out.location(loc) != new_result.location(loc) && (loc != input || !base_out.location(loc).equal_with_mixed_bytes(&right_split_bytes, &new_result.location(loc), &new_in.location(loc))) {
                                result |= Self::find_size(o, rng, constraints, bytes, right, base_in, base_out, input, loc, fixed)?;
                                found = true;
                                break;
                            }
                        } else {
                            warn!("Execution after remapping failed for input {:?} of output {:?}", input, loc);
                        }
                    } else {
                        trace!("Could not adapt state to check for input size on {:?} of output {:?}", input, loc);
                    }
                }


                if found {
                    return Ok(result);
                }
            }

            trace!("Was not able to find a size even though we detected a change");
        }

        Ok(false)
    }
}