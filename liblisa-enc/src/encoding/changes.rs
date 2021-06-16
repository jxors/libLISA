use liblisa_core::{Dataflows, Dest, FlowInputLocation, FlowValueLocation, GetDest, Inputs, Location, MemoryAccesses, Size, Source};
use liblisa_core::gen::{StateGen, RandomizationError};
use liblisa_core::computation::BasicComputation;
use crate::cache::CombinedCache;
use crate::dataflow::DataflowError;
use crate::accesses::ConstraintAnalysisError;
use crate::validity::Validity;
use liblisa_core::{arch::{Arch, Instr, Register}, arch::SystemState, oracle::Oracle};
use log::{debug, error, info, trace, warn};
use maplit::hashset;
use std::{collections::HashSet, convert::{TryFrom, TryInto}, fmt::Debug, iter};
use serde::{Serialize, Deserialize};
use super::*;

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub(crate) enum ChangeLocation {
    Output(usize),
    InputForOutput {
        output_index: usize,
        input_index: usize,
    },
    MemoryAddress {
        memory_index: usize,
        input_index: usize,
    },
}

impl ChangeLocation {
    pub(crate) fn is_input(&self) -> bool {
        match self {
            ChangeLocation::InputForOutput { output_index: _, input_index: _ } => true,
            _ => false,
        }
    }

    pub(crate) fn is_memory_input(&self) -> bool {
        match self {
            ChangeLocation::MemoryAddress { memory_index: _, input_index: _ } => true,
            _ => false,
        }
    }
}

impl From<FlowInputLocation> for ChangeLocation {
    fn from(location: FlowInputLocation) -> Self {
        match location {
            FlowInputLocation::InputForOutput { output_index, input_index } => ChangeLocation::InputForOutput { output_index, input_index },
            FlowInputLocation::MemoryAddress { memory_index, input_index } => ChangeLocation::MemoryAddress { memory_index, input_index },
        }
    }
}

impl From<ChangeLocation> for FlowValueLocation {
    fn from(location: ChangeLocation) -> Self {
        match location {
            ChangeLocation::Output(index) => FlowValueLocation::Output(index),
            ChangeLocation::InputForOutput { output_index, input_index } => FlowValueLocation::InputForOutput { output_index, input_index },
            ChangeLocation::MemoryAddress { memory_index, input_index } => FlowValueLocation::MemoryAddress { memory_index, input_index },
        }
    }
}

impl From<&ChangeLocation> for FlowValueLocation {
    fn from(location: &ChangeLocation) -> Self {
        (*location).into()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Change<A: Arch> {
    None,
    Invalid,
    UnknownMemoryError {
        constraint_index: usize,
    },
    Register {
        locations: Vec<ChangeLocation>,
        from: A::Reg,
        to: A::Reg,
    },
    OperandSize {
        locations: Vec<ChangeLocation>,
        from: Size,
        to: Size,
    },
    ValueImm {
        output_indexes: Vec<usize>,
        memory_indexes: Vec<usize>,
    },
}

impl<A: Arch> Change<A> {
    pub(crate) fn into_base(&self) -> ChangeBase<A> {
        match self {
            Change::None => ChangeBase::None,
            Change::Invalid => ChangeBase::Invalid,
            Change::UnknownMemoryError { constraint_index } => ChangeBase::UnknownMemoryError {
                constraint_index: *constraint_index,
            },
            Change::Register {
                locations,
                from,
                to: _,
            } => ChangeBase::Register {
                locations,
                from: from.clone(),
            },
            Change::OperandSize {
                locations,
                from,
                to: _,
            } => ChangeBase::OperandSize {
                locations,
                from: from.clone(),
            },
            Change::ValueImm { memory_indexes, output_indexes } => ChangeBase::ValueImm { memory_indexes, output_indexes },
        }
    }

    pub(crate) fn sort(&mut self) {
        match self {
            Change::Register {
                locations,
                from: _,
                to: _,
            }
            | Change::OperandSize {
                locations,
                from: _,
                to: _,
            } => locations.sort(),
            Change::ValueImm { memory_indexes, output_indexes } => {
                memory_indexes.sort();
                output_indexes.sort();
            },
            _ => {}
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) enum ChangeBase<'a, A: Arch> {
    None,
    Invalid,
    UnknownMemoryError {
        constraint_index: usize,
    },
    Register {
        locations: &'a [ChangeLocation],
        from: A::Reg,
    },
    OperandSize {
        locations: &'a [ChangeLocation],
        from: Size,
    },
    ValueImm {
        memory_indexes: &'a [usize],
        output_indexes: &'a [usize],
    },
}

impl<A: Arch> Change<A> {
    fn add_register_change(
        &mut self,
        location: ChangeLocation,
        from: Source<A>,
        to: Location<A>,
    ) -> bool {
        trace!(
            "Stacking register change {:?} => {:?} in {:?} on top of {:?}",
            from,
            to,
            location,
            self
        );
        match (from, to) {
            (Source::Dest(Dest::Reg(from, _)), Location::Reg(to)) => match self {
                Change::None => {
                    info!("Trying register change: {:?} => {:?}", from, to);
                    *self = Change::Register {
                        locations: vec![location],
                        from,
                        to,
                    };
                }
                Change::Register {
                    ref mut locations,
                    from: old_from,
                    to: old_to,
                } if *old_from == from && *old_to == to => {
                    if !locations.contains(&location) {
                        locations.push(location);
                    }
                }
                // If we're already tracking some change, return Invalid. If a single bit causes multiple changes things get too complex to fit into a single Encoding.
                _ => return false,
            },
            (from, to) => {
                warn!("Unsupported change from {:?} to {:?}", from, to);
                return false;
            }
        }

        return true;
    }

    fn add_size_change(
        &mut self,
        location: ChangeLocation,
        from: Size,
        to: Size,
    ) -> bool {
        trace!(
            "Stacking size change {:?} => {:?} in {:?} on top of {:?}",
            from,
            to,
            location,
            self
        );
        
        match self {
            Change::None => {
                info!("Trying size change: {:?} => {:?}", from, to);
                *self = Change::OperandSize {
                    locations: vec![location],
                    from,
                    to,
                };
            }
            Change::OperandSize {
                ref mut locations,
                from: old_from,
                to: old_to,
            } if *old_from == from && *old_to == to => {
                if !locations.contains(&location) {
                    locations.push(location);
                }
            }
            // If we're already tracking some change, return Invalid. If a single bit causes multiple changes things get too complex to fit into a single Encoding.
            _ => return false,
        }

        return true;
    }
}

pub(crate) struct ChangeAnalysis<'a, A: Arch, O: Oracle<A>> {
    pub(crate) o: &'a mut O,
    pub(crate) cache: &'a CombinedCache<A>,
    pub(crate) dataflows: &'a Dataflows<A, BasicComputation>,
}

impl<'a, A: Arch + 'static, O: Oracle<A>> ChangeAnalysis<'a, A, O> {
    fn determine_input_change_type(&mut self, input: &Location<A>, all_inputs: &HashSet<Location<A>>, outputs_equal: impl Fn(&mut O, &SystemState<A>, &SystemState<A>) -> Result<bool, EncodingError<A>>, new_constraints: &MemoryAccesses<A, BasicComputation>) -> Result<Option<Location<A>>, EncodingError<A>> {
        let base_constraints = &self.dataflows.addresses;
        // input was used in constraints, but is no longer present in new_constraints. How come?
        // Here, we try to see if the input possibly got replaced by another register or the RIZ register. 
        // Example: 
        // old = rcx + rax * 2      { rcx, rax }
        // new = rax + rax * 2      { rax }
        // input = rcx
        // all_inputs = rcx, rax
        // possibilities = rax, riz
        let mut possibilities = all_inputs.iter()
            .filter(|x| x != &input)
            .cloned()
            .chain(iter::once(Location::Reg(A::Reg::zero())))
            .filter(|p| p.kind() == input.kind())
            .collect::<HashSet<_>>();
        let mut rng = rand::thread_rng();
        info!("Determining if input {:?} got folded or into one of {:?}", input, all_inputs);

        for _ in 0..1000 {
            let mut impossible = Vec::new();
            for possibility in possibilities.iter() {
                let new_state = StateGen::randomize_new(new_constraints, &mut rng, self.o)?;
                match StateGen::remap(base_constraints, self.o, &new_state) {
                    Ok(mut old_state) => {
                        old_state.set_location(input, new_state.location(possibility));

                        if StateGen::adapt(base_constraints, self.o, &mut old_state, &hashset![ input.clone() ], false)? {
                            match outputs_equal(self.o, &old_state, &new_state) {
                                Ok(false) => {
                                    debug!("Possibility eliminated: {:?} -> {:?}", input, possibility);
                                    impossible.push(possibility.clone());
                                },
                                Ok(true) => {},
                                Err(e) => trace!("outputs_equal failed: {:?}", e),
                            }
                        }
                    }
                    Err(e) => trace!("Remap failed: {}", e),
                }
            }

            for remove in impossible {
                possibilities.remove(&remove);
            }

            if possibilities.len() == 0 {
                return Ok(None);
            } else if possibilities.len() == 1 {
                // TODO: Terminate early after a few successful confirmations?
            }
        }

        if possibilities.len() == 1 {
            Ok(Some(possibilities.into_iter().next().unwrap()))
        } else {
            Ok(None)
        }
    }

    fn compare_inputs(&mut self, current_change: &mut Change<A>, build_loc: impl Fn(usize) -> ChangeLocation, outputs_equal: impl Fn(&mut O, &SystemState<A>, &SystemState<A>) -> Result<bool, EncodingError<A>>, reference_inputs: &Inputs<A>, inputs: &Inputs<A>, new_memory_accesses: &MemoryAccesses<A, BasicComputation>) -> Result<bool, EncodingError<A>> {
        let removed = reference_inputs
            .iter()
            .enumerate()
            .filter(|(_, ref_input)| {
                Location::try_from(*ref_input)
                    .map(|ref_input| inputs.get(&ref_input).is_none())
                    .unwrap_or(false)
            })
            .collect::<Vec<_>>();
        let added = inputs
            .iter()
            .filter(|input| 
                Location::try_from(*input)
                    .map(|input| reference_inputs.get(&input).is_none())
                    .unwrap_or(false)
            )
            .collect::<Vec<_>>();

        debug!("Comparing inputs: Removed {:?}; added {:?}", removed, added);

        for (input_index, ref_input) in reference_inputs.iter().enumerate() {
            if let Ok(loc) = ref_input.try_into() {
                if let Some(new_input) = inputs.get(&loc) {
                    if ref_input.size() != new_input.size() {
                        let location = build_loc(input_index);

                        match (ref_input.size(), new_input.size()) {
                            (None, None) => {},
                            (Some(ref_size), Some(new_size)) => {
                                if !current_change.add_size_change(location, ref_size, new_size.clone()) {
                                    return Ok(false);
                                }
                            },
                            _ => {
                                error!("Encountered values with and without size, which should not be possible: {:?} {:?}", reference_inputs, inputs);
                                return Ok(false);
                            },
                        }
                    }
                }
            }
        }

        if removed.len() == 1 {
            let location = build_loc(removed[0].0);
            let from = removed[0].1.clone();

            if added.len() == 1 {
                let to = added[0].clone();
                if from.size() != to.size() {
                    // Registers are already different, so sizes must be equal
                    trace!("Incompatible size change");
                    return Ok(false);
                }

                if let Ok(to) = Location::try_from(&to) {
                    if !current_change.add_register_change(location, from, to) {
                        return Ok(false);
                    }
                } else {
                    return Ok(false);
                }
            } else if added.len() == 0 {
                // The register potentially folded on to one of the other registers?
                if let Ok(from_loc) = Location::try_from(&from) {
                    let all_inputs = reference_inputs.iter().map(|x| Location::try_from(x)).flatten().collect();
                    match self.determine_input_change_type(&from_loc, &all_inputs, outputs_equal, &new_memory_accesses)? {
                        Some(to) => {
                            if !current_change.add_register_change(location, from.clone(), to) {
                                return Ok(false);
                            }
                        }
                        None => return Ok(false),
                    }
                }
            } else if added.len() == 0 && removed.len() == 1 {
                // Change to zero register?
                let from = removed[0].1.clone();
                let to = Location::Reg(A::Reg::zero());
                if !current_change.add_register_change(location, from, to) {
                    return Ok(false);
                }
            } else {
                trace!("Unsupported added/removed configuration");
                return Ok(false);
            }
        } else if !(removed.len() == 0 && added.len() == 0) {
            trace!("Unsupported added/removed configuration");
            return Ok(false);
        }

        Ok(true)
    }

    fn compare_memory_accesses(&mut self, new_constraints: &MemoryAccesses<A, BasicComputation>) -> Result<Change<A>, EncodingError<A>> {
        let base_constraints = &self.dataflows.addresses;
        if new_constraints.len() != base_constraints.len() {
            Ok(Change::Invalid)
        } else {
            let mut current_change = Change::None;
            for (index, (base_access, new_access)) in base_constraints.iter()
                .zip(new_constraints.iter())
                .enumerate()
            {
                if !self.compare_inputs(&mut current_change, |input_index| {
                    ChangeLocation::MemoryAddress {
                        memory_index: index,
                        input_index,
                    }
                }, |_, old_state, new_state| {
                    let old_addr = old_state.memory.data[index].0;
                    let new_addr = new_state.memory.data[index].0;

                    Ok(old_addr == new_addr)
                }, &base_access.inputs, &new_access.inputs, &new_constraints)? {
                    return Ok(Change::Invalid);
                }

                if base_access.kind != new_access.kind {
                    return Ok(Change::Invalid);
                }
                
                if base_access.alignment != new_access.alignment {
                    return Ok(Change::Invalid);
                }
            }

            Ok(current_change)
        }
    }
    fn compare_dataflows(&mut self, new_dataflows: &Dataflows<A, BasicComputation>, mut current_change: Change<A>) -> Result<Change<A>, EncodingError<A>> {
        let removed = self.dataflows.output_dataflows()
            .filter(|o| 
                Location::try_from(&o.target)
                    .map(|ref_loc| new_dataflows.get(&ref_loc).is_none())
                    .unwrap_or(false)
            )
            .collect::<Vec<_>>();
        let added = new_dataflows.output_dataflows()
            .filter(|o| 
                Location::try_from(&o.target)
                    .map(|loc| self.dataflows.get(&loc).is_none())
                    .unwrap_or(false)
            )
            .collect::<Vec<_>>();
            
        if !(removed.len() == 0 && added.len() == 0) && !(removed.len() == 1 && added.len() == 1) {
            debug!("Unsupported R/A configuration: Removed: {:?}, added: {:?}", removed, added);
            return Ok(Change::Invalid);
        }

        for (index, ref_flow) in self.dataflows.output_dataflows().enumerate() {
            if let Ok(loc) = Location::try_from(&ref_flow.target) {
                debug!("Checking output {:?}", loc);
                if let Some(new_flow) = new_dataflows.get(&loc) {
                    if new_flow.target.size() != ref_flow.target.size() {
                        let location = ChangeLocation::Output(index);
                        match current_change {
                            Change::None => {
                                current_change = Change::OperandSize {
                                    locations: vec![ location ],
                                    from: ref_flow.target.size().unwrap(),
                                    to: new_flow.target.size().unwrap(),
                                };
                            },
                            Change::OperandSize { ref mut locations, ref from, ref to } if from == &ref_flow.target.size().unwrap() && to == &new_flow.target.size().unwrap() => {
                                if !locations.contains(&location) {
                                    locations.push(location);
                                }
                            }
                            change => {
                                debug!("Found an operand size change, but we're already tracking {:?}", change);
                                return Ok(Change::Invalid);
                            },
                        }
                    }

                    let old_dest = &ref_flow.target;
                    let new_dest = &new_flow.target;
                    if !self.compare_inputs(&mut current_change, |input_index| ChangeLocation::InputForOutput {
                        output_index: index,
                        input_index,
                    }, |o, old_state, new_state| {
                        let old_output = o.observe(&old_state);
                        let new_output = o.observe(&new_state);
                        Ok(match (old_output, new_output) {
                            (Ok(old_output), Ok(new_output)) => {
                                old_output.get_dest(&old_dest, |left| {
                                    new_output.get_dest(&new_dest, |right| {
                                        left == right
                                    })
                                })
                            },
                            (Err(e), _) | (_, Err(e)) => Err(e)?,
                        })
                    }, &ref_flow.inputs, &new_flow.inputs, &new_dataflows.addresses)? {
                        debug!("Comparing inputs {:?} with {:?} failed", ref_flow.inputs, new_flow);
                        return Ok(Change::Invalid);
                    }
                } else {
                    // Find the register with which this thing was swapped.
                    assert_eq!(removed.len(), 1);
                    assert_eq!(removed[0].target, loc);

                    debug!("Old dataflow: {:?}", self.dataflows);
                    debug!("New dataflow: {:?}", new_dataflows);
                    debug!(
                        "Output register changed: {:?}; removed = {:?}, added = {:?}",
                        loc, removed, added
                    );

                    if removed.len() == 1 && added.len() == 1 {
                        let from = removed[0].clone();
                        let to = added[0].clone();

                        if from.target.size() != to.target.size() {
                            // Registers are already different, so sizes must be equal
                            return Ok(Change::Invalid);
                        }

                        if let Ok(to) = Location::try_from(&to.target) {
                            if !current_change.add_register_change(
                                ChangeLocation::Output(index),
                                from.target.clone().into(),
                                to,
                            ) {
                                debug!("Adding an output register change failed");
                                return Ok(Change::Invalid);
                            }
                        } else {
                            return Ok(Change::Invalid);
                        }

                        let old_dest = &from.target;
                        let new_dest = &to.target;
                        if !self.compare_inputs(&mut current_change, |input_index| ChangeLocation::InputForOutput {
                            output_index: index,
                            input_index,
                        }, |o, old_state, new_state| {
                            let old_output = o.observe(&old_state)?;
                            let new_output = o.observe(&new_state)?;
                            Ok(old_output.get_dest(&old_dest, |left| {
                                new_output.get_dest(&new_dest, |right| {
                                    left == right
                                })
                            }))
                        }, &from.inputs, &to.inputs, &new_dataflows.addresses)? {
                            debug!("Comparing inputs {:?} with {:?} (for changed output) failed", from.inputs, to.inputs);
                            return Ok(Change::Invalid);
                        }
                    } else {
                        // Maybe multiple outputs changed. In any case, this is too complex; we'll just ignore it.
                        debug!("Unknown removed/added configuration for outputs");
                        return Ok(Change::Invalid);
                    }
                }
            }
        }

        Ok(current_change)
    }

    pub(crate) fn detect_change(&mut self, new_instr: Instr<'_>) -> Result<Change<A>, EncodingError<A>> {
        Ok(match Validity::infer(self.o, new_instr) {
            v @ Validity::TooShort | v @ Validity::InvalidInstruction | v @ Validity::TooLong | v @ Validity::Excluded => {
                info!("Validity check failed: {:?}", v);
                Change::Invalid
            }
            Validity::Ok => {
                let new_memory_accesses = self.cache.infer_constraints(self.o, new_instr);
                info!("New constraints: {:X?}", new_memory_accesses);
                match new_memory_accesses {
                    Ok(new_memory_accesses) => {
                        let change = self.compare_memory_accesses(&new_memory_accesses)?;
                        info!("Change after comparing memory accesses: {:?}", change);
                        if let Change::Invalid = change {
                            return Ok(Change::Invalid);
                        }

                        let change = imm::ImmAnalysis {
                            dataflows: self.dataflows,
                            o: self.o,
                        }.find_memory_access_imm(&new_memory_accesses, change)?;
                        info!("Change after checking for memory access imm: {:?}", change);
                        if let Change::Invalid = change {
                            return Ok(Change::Invalid);
                        }

                        match self.cache.infer_dataflow(self.o, &new_memory_accesses) {
                            Ok(new_dataflow) => {
                                info!("New dataflow: {:X?}", new_dataflow);

                                let change = self.compare_dataflows(&new_dataflow, change)?;
                                info!("Changes after comparing dataflow: {:?}", change);
                                if let Change::Invalid = change {
                                    return Ok(Change::Invalid);
                                }

                                let change = match (imm::ImmAnalysis {
                                    dataflows: self.dataflows,
                                    o: self.o,
                                }).find_dataflow_imm(&new_memory_accesses, &new_dataflow, change) {
                                    Ok(change) => change,
                                    Err(e) => {
                                        error!("Error while searching for dataflow imms: {}", e);
                                        return Ok(Change::Invalid);
                                    }
                                };

                                info!("Changes finding dataflow imm: {:?}", change);
                                change
                            }
                            Err(DataflowError::Randomization(RandomizationError::CannotFillState(constraint_index))) => {
                                warn!("Inferring dataflow failed with memory error in constraint #{}", constraint_index);
                                Change::UnknownMemoryError { constraint_index }
                            },
                            Err(e) => {
                                warn!("Inferring dataflow failed: {}", e);
                                Change::Invalid
                            },
                        }
                    }
                    Err(ConstraintAnalysisError::Randomization(
                        RandomizationError::UnmappableFixedOffset(constraint_index),
                    ))
                    | Err(ConstraintAnalysisError::Randomization(
                        RandomizationError::CannotFillState(constraint_index),
                    ))
                    | Err(ConstraintAnalysisError::Randomization(
                        RandomizationError::NoMemoryAccess(constraint_index),
                    ))
                    | Err(ConstraintAnalysisError::Randomization(
                        RandomizationError::Unsatisfiable(constraint_index),
                    ))
                    | Err(ConstraintAnalysisError::UnaccessibleMemoryAccess(constraint_index)) => {
                        // When constraint verification fails because we can't map memory, we might want to consider the bit a MemoryImm (it might be e.g. the highest bit in a fixed memory address, making the address negative and unmappable from userspace). It doesn't hurt to mark too many bits as that (except of course that our filters would be too general but that can be solved by integrating the semantics into the filter).
                        Change::UnknownMemoryError { constraint_index }
                    }
                    Err(e) => {
                        warn!("detect_change failed with error: {}", e);
                        Change::Invalid
                    },
                }
            }
        })
    }
}