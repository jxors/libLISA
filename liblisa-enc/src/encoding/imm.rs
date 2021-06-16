use liblisa_core::{Dataflows, Dest, GetDest, IntoDestWithSize, Location, MemoryAccesses, Source, arch::Value};
use liblisa_core::gen::{StateGen, RandomizationError};
use liblisa_core::computation::{Computation, BasicComputation};
use liblisa_core::{arch::{Arch, SystemState}, oracle::Oracle, oracle::OracleError};
use itertools::Itertools;
use log::{debug, error, info, trace, warn};
use maplit::hashset;
use std::{collections::HashSet, convert::TryFrom};
use rand::Rng;
use super::*;

pub(crate) struct ImmAnalysis<'a, A: Arch, O: Oracle<A>> {
    pub(crate) o: &'a mut O,
    pub(crate) dataflows: &'a Dataflows<A, BasicComputation>,
}

impl<'a, A: Arch + 'static, O: Oracle<A>> ImmAnalysis<'a, A, O> {
    pub(crate) fn find_memory_access_imm(&mut self, new_constraints: &MemoryAccesses<A, BasicComputation>, mut current_change: Change<A>) -> Result<Change<A>, EncodingError<A>> {
        let base_constraints = &self.dataflows.addresses;
        // We verify that we see the same memory access (or memory error) for every constraint. If we discover a difference, we add
        // a AddressImm change to indicate that whichever bits were changed in the instruction must be part of some immediate value.
        let mut rng = rand::thread_rng();
        let mut checked_all = true;
        for (constraint_index, (base, new)) in base_constraints.memory.iter().zip(new_constraints.memory.iter()).enumerate() {
            match (base.calculation.as_ref(), new.calculation.as_ref()) {
                (Some(c1), Some(c2)) => if c1 != c2 {
                    match current_change {
                        Change::None => {
                            current_change = Change::ValueImm {
                                memory_indexes: vec![constraint_index],
                                output_indexes: vec![],
                            };
                        }
                        Change::ValueImm { memory_indexes: ref mut locations, .. } => {
                            if !locations.contains(&constraint_index) {
                                locations.push(constraint_index);
                            }
                        }
                        Change::Register { ref locations, ref from, ref to } if locations.iter().any(|loc| match loc {
                            ChangeLocation::MemoryAddress { memory_index, .. } if *memory_index == constraint_index => true,
                            _ => false
                        }) => {
                            for _ in 0..100_000 {
                                let new_state = StateGen::randomize_new(new_constraints, &mut rng, self.o)?;
                                let old_state = new_state.with_location(&Location::Reg(from.clone()), new_state.location(&Location::Reg(to.clone())));

                                if c1.compute(&base.inputs, &old_state) != c2.compute(&new.inputs, &new_state) {
                                    info!("Found an address Imm between {} and {}, but we're already tracking a register change from {:?} to {:?}", base, new, from, to);
                                    debug!("Imm case: {:X?} vs {:X?}", new_state, old_state);
                                    return Ok(Change::Invalid);
                                }
                            }
                        }
                        _ => {
                            info!("Found an address Imm between {} and {}, but we're already tracking another change {:?}", base, new, current_change);
                            return Ok(Change::Invalid);
                        }
                    }
                },
                _ => {
                    checked_all = false;
                },
            }
        }

        // We only need to try the randomization approach if we were not able to verify all memory accesses with calculations.
        if !checked_all {
            for _ in 0..1000 {
                let state_new_template = StateGen::randomize_new(new_constraints, &mut rng, self.o)?;
                match StateGen::remap(base_constraints, self.o, &state_new_template) {
                    Ok(mut state_old_template) => {
                        let changed = match &current_change {
                            Change::Register {
                                locations,
                                from,
                                to,
                            } if locations.iter().any(ChangeLocation::is_memory_input) => {
                                state_old_template.set_location(&Location::Reg(from.clone()), state_new_template.location(&Location::Reg(to.clone())));

                                hashset! [ Location::Reg(from.clone()) ]
                            }
                            _ => hashset! [],
                        };

                        if StateGen::adapt(base_constraints, self.o, &mut state_old_template, &changed, false)? {
                            for constraint_index in 1..base_constraints.memory.len() {
                                let addr_a = state_new_template.memory.data[constraint_index].0;
                                let addr_b = state_old_template.memory.data[constraint_index].0;

                                if addr_a != addr_b {
                                    match current_change {
                                        Change::None => {
                                            current_change = Change::ValueImm {
                                                memory_indexes: vec![constraint_index],
                                                output_indexes: vec![],
                                            };
                                        }
                                        Change::ValueImm { memory_indexes: ref mut locations, .. } => {
                                            if !locations.contains(&constraint_index) {
                                                locations.push(constraint_index);
                                            }
                                        }
                                        _ => {
                                            info!("Got two different memory accesses, but we're already tracking another unrelated change ({:X?}): {:X} and {:X} given states: {:X?} {:X?}", current_change, addr_a, addr_b, state_old_template, state_new_template);
                                            return Ok(Change::Invalid);
                                        }
                                    }
                                }
                            }
                        }
                    },
                    Err(e) => {
                        trace!("Unable to remap: {}", e);
                    }
                }
            }
        }

        Ok(current_change)
    }

    fn verify_dataflow_imm_base(&mut self, state_new: &SystemState<A>, mut current_change: Change<A>, size_change_locations: &mut Option<Vec<ChangeLocation>>) -> Result<Change<A>, RandomizationError> {
        let base_constraints = &self.dataflows.addresses;
        match StateGen::remap(base_constraints, self.o, &state_new) {
            Ok(mut state_old) => {
                let changed = match &current_change {
                    Change::Register {
                        locations,
                        from,
                        to,
                    } if locations.iter().any(ChangeLocation::is_input) => {
                        state_old.set_location(&Location::Reg(from.clone()), state_new.location(&Location::Reg(to.clone())));

                        hashset! [ Location::Reg(from.clone()) ]
                    }
                    Change::OperandSize {
                        locations,
                        from,
                        to,
                    } if locations.iter().any(ChangeLocation::is_input) => {
                        let mut changed = HashSet::new();
                        
                        for loc in locations.iter() {
                            match loc {
                                ChangeLocation::InputForOutput { output_index, input_index } => {
                                    let val = &self.dataflows[*output_index].inputs[*input_index];
                                    let loc = Location::try_from(val).unwrap();
                                    let old_val = loc.clone().into_dest_with_size(from.clone());
                                    let new_val = loc.clone().into_dest_with_size(to.clone());
                                    state_old = state_new.get_dest(&new_val, |v| {
                                        state_old.with_dest(&old_val, v)
                                    });

                                    changed.insert(loc);
                                }
                                _ => {}
                            }
                        }

                        trace!("Adapted for operand size change: {:?}; old: {:?}; new: {:?}", current_change, state_old, state_new);

                        changed
                    }
                    _ => hashset! [],
                };
                
                if StateGen::adapt(base_constraints, self.o, &mut state_old, &changed, false)? {
                    let base_result = self.o.observe(&state_old);
                    let new_result = self.o.observe(&state_new);

                    trace!("Trying to find an imm value with inputs: {:X?} {:X?}; Outputs: {:X?} {:X?}", state_old, state_new, base_result, new_result);

                    // We compare the two results we got. One from instr and one from new_instr. If the results aren't equal, this might be an immediate value.
                    // This happens often enough to be important to check; For example, the encoding for add al, al contains a bit that swaps the operand order. This does not give different results, so we don't want to identify it as an immediate value.
                    match (base_result, new_result) {
                        (Ok(left), Ok(right)) => {
                            // Check outputs
                            for (index, output) in self.dataflows.output_dataflows().enumerate() {
                                let left_loc = &output.target;
                                let right_loc = match &current_change {
                                    Change::Register {
                                        locations,
                                        from,
                                        to,
                                    } if locations.contains(&ChangeLocation::Output(index))
                                        && left_loc == &Location::Reg(from.clone()) =>
                                    {
                                        Dest::Reg(to.clone(), left_loc.size().unwrap())
                                    }
                                    Change::OperandSize {
                                        locations,
                                        from,
                                        to,
                                    } if locations.contains(&ChangeLocation::Output(index))
                                        && left_loc.size().as_ref() == Some(from) =>
                                    {
                                        left_loc.with_size(to.clone())
                                    }
                                    _ => left_loc.clone(),
                                };
                                
                                let current_change = &mut current_change;
                                if let Some(result) = left.get_dest(&left_loc, |left_val| {
                                    right.get_dest(&right_loc, |right_val| {
                                        trace!("Comparing {:?} vs {:?} ==> {:?} vs {:?}", left_loc, right_loc, left_val, right_val);
                                        if left_val != right_val {
                                            let location = index;
                                            match current_change {
                                                Change::ValueImm { output_indexes: ref mut locations, .. } => {
                                                    if !locations.contains(&location) {
                                                        locations.push(location);
                                                    }
                                                }
                                                Change::OperandSize { from, to, locations } if from.contains(to) => {
                                                    if let Some(existing_locations) = size_change_locations {
                                                        if &existing_locations[..] != &locations[..] {
                                                            warn!("Detected an imm value between {:?} and {:?} that we can't handle because we're already tracking a size change from {:?} to {:?}; The special case doesn't apply, because the locations aren't identical: {:?} vs {:?}", left_loc, right_loc, from, to, existing_locations, locations);
                                                            return Some(Ok(Change::Invalid));
                                                        }
                                                    } else {
                                                        *size_change_locations = Some(locations.clone());
                                                    }

                                                    // We will make sure the locations match the size change locations when returing this change
                                                    *current_change = Change::ValueImm {
                                                        output_indexes: vec![ location ],
                                                        memory_indexes: Vec::new(),
                                                    };
                                                }
                                                Change::None => {
                                                    *current_change = Change::ValueImm {
                                                        output_indexes: vec![ location ],
                                                        memory_indexes: Vec::new(),
                                                    };
                                                }
                                                change => {
                                                    warn!("Detected an imm value between {:?} and {:?} that we can't handle because we're already tracking another change: {:?}; Inputs were: {:X?} {:X?}; Outputs were: {:X?} {:X?}", left_loc, right_loc, change, state_old, state_new, left, right);
                                                    return Some(Ok(Change::Invalid));
                                                }
                                            }
                                        }
                                        
                                        None
                                    })
                                }) {
                                    return result;
                                }
                            }
                        }
                        // TODO: Should these errors be equal?
                        (Err(_e1), Err(_e2)) => {}
                        // Changing of an immediate value might cause a computation error, but not sure.
                        // Should just hope for another case where both results are Ok(_)
                        (Ok(_), Err(OracleError::ComputationError)) | (Err(OracleError::ComputationError), Ok(_)) => {},
                        (a, b) => {
                            debug!(
                                "Imm value check failed because of inconsistent output: {:X?} vs {:X?} on: {:X?} vs {:X?}",
                                a, b, state_old, state_new
                            );
                            return Ok(Change::Invalid);
                        }
                    }
                }
            }
            Err(e) => {
                trace!("find_dataflow_imm remap failed: {}", e);
            }
        }

        Ok(current_change)
    }

    /// Some outputs have an "abrupt" value change. Rather than slowly changing over time, they switch from one value to another at a specific point.
    /// A good example are output flags in a comparison. An overflow flag will switch from 0 to 1 at one specific point.
    /// It can sometimes be hard to find random states that get close to this "edge".
    /// We need to find this edge to find some immediate values. For example, imagine we only found states where:
    ///
    /// 1) RAX = 100
    /// 2) RAX = 500
    /// 3) RAX = 721
    ///
    /// Given two instructions cmp RAX, 724 and cmp RAX, 725, we would conclude that there is no immediate value, given the 3 examples we found.
    /// The ImmScan is effectively a sort of binary search that aims to approximate this point where the output flags switch.
    /// This makes it much easier to find the immediate value.
    fn dataflow_imm_scan<R: Rng>(&mut self, rng: &mut R, new_constraints: &MemoryAccesses<A, BasicComputation>, target: Dest<A>, input: Dest<A>, set_input: impl Fn(&SystemState<A>, u64) -> SystemState<A>, current_change: &mut Change<A>, size_change_locations: &mut Option<Vec<ChangeLocation>>) -> Result<bool, RandomizationError> {
        let num_bits = input.size().map(|s| s.len() * 8).unwrap_or(1);
        if num_bits > 64 {
            // Ignore inputs and outputs of more than 64 bits, since they're probably not numbers.
            return Ok(true);
        }

        let base = StateGen::randomize_new(new_constraints, rng, self.o)?;
        let mut base = set_input(&base, 0);
        if StateGen::adapt(new_constraints, self.o, &mut base, &hashset![ Location::from(&input) ], false)? {
            let base_result = self.o.observe(&base)?;
            let base_value = base_result.get_dest(&target, |v| match v {
                Value::Num(n) => *n,
                Value::FlagBitmap(f) => *f,
                Value::Bytes(b) => b.iter().fold(0u64, |acc, v| (acc << 8) | *v as u64),
            });

            let mut value = 0;
            for bit in (0..num_bits).rev() {
                let mut state = set_input(&base, value | (1 << bit));
                if StateGen::adapt(new_constraints, self.o, &mut state, &hashset![ Location::from(&input) ], false)? {
                    let new_result = self.o.observe(&state)?;
                    let new_value = new_result.get_dest(&target, |v| match v {
                        Value::Num(n) => *n,
                        Value::FlagBitmap(f) => *f,
                        Value::Bytes(b) => b.iter().fold(0u64, |acc, v| (acc << 8) | *v as u64),
                    });

                    *current_change = self.verify_dataflow_imm_base(&state, current_change.clone(), size_change_locations)?;

                    if new_value == base_value {
                        value |= 1 << bit;
                    }
                } else {
                    // Fail because we cannot modify state properly
                    return Ok(false);
                }
            }
        }

        Ok(true)
    }

    /// Requires constraints on instr and new_instr to be fully equal
    // TODO: Tecnhically, this function will incorrectly report 'No immediate value' if all adapts() fail. It would be nicer to have a separate ImmError, which could fold in to adjacent Imms if there are any, or become an Invalid if there are none. This does not seem to happen very often in practice, so it's not implemented for now.
    pub(crate) fn find_dataflow_imm(&mut self, new_constraints: &MemoryAccesses<A, BasicComputation>, new_dataflows: &Dataflows<A, BasicComputation>, mut current_change: Change<A>) -> Result<Change<A>, RandomizationError> {
        let base_constraints = &self.dataflows.addresses;
        debug_assert_eq!(base_constraints.memory.len(), new_constraints.memory.len());
        let mut rng = rand::thread_rng();
        let mut size_change_locations: Option<Vec<ChangeLocation>> = None;
        for _ in 0..1_000 {
            let state_new = StateGen::randomize_new(new_constraints, &mut rng, self.o)?;
            current_change = self.verify_dataflow_imm_base(&state_new, current_change, &mut size_change_locations)?;

            if current_change == Change::Invalid {
                return Ok(Change::Invalid);
            }
        }

        for flow in new_dataflows.output_dataflows() {
            let target = flow.target.clone();
            for source in flow.inputs.iter() {
                match source {
                    Source::Dest(dest @ Dest::Reg(_, _)) => {
                        match self.dataflow_imm_scan(&mut rng, new_constraints, target.clone(), dest.clone(), |state, value| {
                            state.with_dest(dest, &Value::Num(value))
                        }, &mut current_change, &mut size_change_locations) {
                            Ok(result) => debug!("Dataflow imm scan result: {}", result),
                            Err(e) => error!("Imm Scan: {}", e),
                        }
                    }
                    Source::Dest(dest @ Dest::Mem(_, _)) => {
                        // Scanning for little endian memory
                        let size = dest.size().unwrap().len();
                        match self.dataflow_imm_scan(&mut rng, new_constraints, target.clone(), dest.clone(), |state, value| {
                            let bytes = value.to_le_bytes();
                            state.with_dest(dest, &Value::Bytes(&bytes[..size]))
                        }, &mut current_change, &mut size_change_locations) {
                            Ok(result) => debug!("Dataflow imm scan result: {}", result),
                            Err(e) => error!("Imm Scan: {}", e),
                        }

                        // Scanning for big endian memory
                        match self.dataflow_imm_scan(&mut rng, new_constraints, target.clone(), dest.clone(), |state, value| {
                            let bytes = value.to_be_bytes();
                            state.with_dest(dest, &Value::Bytes(&bytes[bytes.len() - size..]))
                        }, &mut current_change, &mut size_change_locations) {
                            Ok(result) => debug!("Dataflow imm scan result: {}", result),
                            Err(e) => error!("Imm Scan: {}", e),
                        }
                    }
                    // TODO: Similar thing for memory
                    _ => {},
                }
            }
        }

        // We kept track of all the locations where we found an immediate value, but were already tracking an operand size change.
        // All operand size changes can be expressed as immediate values.
        // For example, a change from al to ah is equivalent to a 1-bit immediate value 'c' for: ((if c then rax else rax >> 8) & 0xff)
        // In some cases, we allow the OperandSize change that we detected to transform into an immediate value.
        // TODO: Explain what the rules for this transformation are, and why they are a good idea
        if let Some(existing_locations) = size_change_locations {
            if let Change::ValueImm { output_indexes, .. } = &current_change {
                debug!("Comparing locations: {:?} ⊆ {:?}", existing_locations, output_indexes);
                let equal = existing_locations.iter().all(|ch| match ch {
                    ChangeLocation::InputForOutput { output_index, .. } => output_indexes.iter().any(|idx| idx == output_index),
                    ChangeLocation::Output(output_index) => output_indexes.iter().any(|idx| idx == output_index),
                    _ => false,
                });

                if !equal {
                    debug!("Comparing operand size locations to output indexes failed");
                    return Ok(Change::Invalid);
                }
            }
        }

        match current_change {
            Change::OperandSize { from, to, locations } if from.len() != to.len() && from.contains(&to) => {
                if locations.iter().any(|ch| matches!(ch, ChangeLocation::MemoryAddress { .. })) {
                    Ok(Change::Invalid)
                } else {
                    Ok(Change::ValueImm {
                        output_indexes: locations.into_iter().map(|ch| match ch {
                            ChangeLocation::InputForOutput { output_index, .. } => output_index,
                            ChangeLocation::Output(output_index) => output_index,
                            _ => unreachable!("")
                        }).unique().collect(),
                        memory_indexes: Vec::new(),
                    })
                }
            },
            other => Ok(other),
        }
    }
}