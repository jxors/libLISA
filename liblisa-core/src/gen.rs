use std::{collections::HashSet, convert::TryFrom, fmt::Debug};
use log::*;
use rand::{Rng, prelude::SliceRandom};
use thiserror::Error;
use serde::{Serialize, Deserialize};
use crate::{arch::{Arch, Flag, InstructionInfo, MemoryState, Permissions, Register, State, SystemState, Value}, oracle::{Oracle, OracleError}};
use crate::{Dest, Location, Source, Computation, randomized_value};
use crate::accesses::{MemoryAccess, MemoryAccesses, AccessKind};

#[derive(Error, Debug, Clone)]
pub enum RandomizationError {
    #[error("Modifying values failed")]
    ModifyingValuesFailed,

    #[error("Unable to synthesize a valid random state")]
    RandomStateSynthesisFailed,

    #[error("Invalid instruction")]
    InvalidInstruction,

    #[error("Unable fill to a valid state, hung at constraint {}", .0)]
    CannotFillState(usize),

    #[error("Oracle error: {}", .0)]
    OracleError(OracleError),

    #[error("Encountered an unmappable fixed offset for constraint {}", .0)]
    UnmappableFixedOffset(usize),

    #[error("We expected a memory access for constraint {}, but we did not encounter one", .0)]
    NoMemoryAccess(usize),

    #[error("We could not find acceptable values for inputs to memory access #{}", .0)]
    Unsatisfiable(usize),
}

impl From<OracleError> for RandomizationError {
    fn from(e: OracleError) -> Self {
        RandomizationError::OracleError(e)
    }
}

#[derive(Error, Debug)]
pub enum RemapError<A: Arch> {
    #[error("Phantom")]
    Phantom(A),

    #[error("Oracle gave an error: {}", .0)]
    OracleError(OracleError),

    #[error("The remapping causes memory #{} to be mapped on to two separate pages", .0)]
    MemoryMappingCrossesPageBounds(usize),

    #[error("The remapping causes memory #{} to unmappable", .0)]
    CannotMapMemory(usize),

    #[error("The remapping causes two memory pages to overlap, the second page is #{}", .0)]
    OverlappingMemory(usize),

    #[error("The remapping causes unknown issues with memory #{}", .0)]
    UnknownMemoryIssue(usize),

    #[error("Adapting to the new memory constraints failed")]
    AdaptFailed,

    #[error("Randomization error: {}", .0)]
    RandomizationError(RandomizationError),
}

impl<A: Arch> From<RandomizationError> for RemapError<A> {
    fn from(e: RandomizationError) -> Self {
        RemapError::RandomizationError(e)
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Serialize, Deserialize, Hash)]
enum Constraint {
    None,
    Impossible,
    PageRegion { min_offset: u64, max_offset: u64 },
}

pub trait TryIntoBasicComputation {
    fn basic(&self) -> Option<&crate::computation::BasicComputation>;
}

impl TryIntoBasicComputation for crate::computation::BasicComputation {
    fn basic(&self) -> Option<&crate::computation::BasicComputation> {
        Some(&self)
    }
}

pub struct StateGen;

impl StateGen {
    fn good_addr<A: Arch, O: Oracle<A>, C: Computation>(o: &mut O, memory: &[(u64, Permissions, Vec<u8>)], accesses: &[MemoryAccess<A, C>], access: &MemoryAccess<A, C>, addr: u64, perms: Permissions, computed: bool) -> bool {
        if !o.can_map(addr) {
            false
        } else {
            let page_size = o.page_size();
            let page_addr = addr / page_size;
            let next_page = (page_addr + 1) * page_size;
            if addr + access.size.end as u64 > next_page {
                false 
            } else {
                // If the address was observed, we need a margin to account for when we observe an incorrect start offset.
                // We might observe an incorrect start offset if the page before page_addr is already mapped.
                // The first few bytes of this memory access might have occurred on the page before it, which we cannot observe.
                // If the address was computed, we are 100% sure about the start offset and don't need any padding.
                let padding_addr = addr.wrapping_sub(if computed {
                    0
                } else {
                    access.size.end as u64
                });

                if !computed && memory.iter().any(|(addr, _, _)| addr / page_size == padding_addr / page_size) {
                    false
                } else {
                    memory.iter().zip(accesses.iter()).all(|((other_addr, other_perms, _), other)| {
                        if computed && other.calculation.is_some() && perms == *other_perms {
                            // We are able to compute the exact locations of both accesses, and they have the same permissions.
                            // We can let them occur on the same page. We just make sure they don't overlap
                            addr + access.size.end as u64 <= *other_addr || addr >= other_addr + other.size.end as u64
                        } else {
                            // We either obtain the address by observation, or there is a permission mismatch.
                            // In such a case, the memory accesses may not occur on the same page.
                            let other_page_addr = other_addr / page_size;
                            other_page_addr != page_addr
                        }
                    })
                }
            }
        }
    }

    pub fn adapt_with_modifications<A: Arch, O: Oracle<A>, C: Computation + TryIntoBasicComputation>(accesses: &MemoryAccesses<A, C>, o: &mut O, s: &mut SystemState<A>, changed: &HashSet<Location<A>>, changed_instr: bool, fixed_locations: &HashSet<Location<A>>) -> Result<bool, RandomizationError> {
        let relevant_accesses = accesses.memory[..s.memory.data.len()].iter()
            .enumerate()
            .filter(|(_, c)| changed_instr || changed.iter().any(|loc| c.inputs.get(loc).is_some()))
            .collect::<Vec<_>>();
        let relevant_locs = relevant_accesses.iter()
            .flat_map(|(_, a)| a.inputs.iter())
            .filter(|loc| match loc {
                Source::Dest(d) => !fixed_locations.contains(&d.clone().into()),
                _ => true,
            })
            .collect::<Vec<_>>();
        let mut tmp = s.clone();
        let mut rng = rand::thread_rng();
        
        for k in 0..100 {
            if Self::adapt(accesses, o, &mut tmp, changed, changed_instr)? {
                *s = tmp;
                return Ok(true);
            } else {
                for loc in relevant_locs.iter() {
                    match loc {
                        Source::Dest(Dest::Reg(reg, _)) => tmp.set_reg(reg, randomized_value(&mut rng)),
                        // TODO: None of these are likely to happen in x86-64, so we'll just ignore them for now
                        Source::Dest(Dest::Mem(_, _)) | Source::Dest(Dest::Flag(_)) | Source::Dest(Dest::Flags) | Source::Imm(_) | Source::Const { .. } => {},
                    }
                }

                if k >= 10 && k % 2 == 0 {
                    let mut any = false;
                    for (access_index, access) in relevant_accesses.iter() {
                        if let (Some(computation), Some(addr), desired_addr) = (access.calculation.as_ref().map(|c| c.basic()).flatten(), access.compute_address(&tmp), s.memory.data[*access_index].0) {
                            if !o.can_map(addr) {
                                // We might be able to move this address to the right position directly if we have a basic computation available.
                                let delta = desired_addr.wrapping_sub(addr);
                                let mut inputs = access.inputs.iter().enumerate().collect::<Vec<_>>();
                                inputs.shuffle(&mut rng);
                                for (input_index, input) in inputs {
                                    if Option::<Location<_>>::from(input).map(|loc| !fixed_locations.contains(&loc)).unwrap_or(false) {
                                        let scale = if input_index == computation.scaled_index { computation.scale } else { 1 };
                                        let offset = delta / scale;

                                        match input {
                                            Source::Dest(Dest::Reg(reg, _)) => tmp.set_reg(reg, tmp.cpu.reg(reg).wrapping_add(offset)),
                                            // TODO: None of these are likely to happen in x86-64, so we'll just ignore them for now
                                            Source::Dest(Dest::Mem(_, _)) | Source::Dest(Dest::Flag(_)) | Source::Dest(Dest::Flags) | Source::Imm(_) | Source::Const { .. } => {},
                                        }

                                        any = true;
                                    }
                                }
                            }
                        }
                    }

                    if !any {
                        return Ok(false);
                    }
                }
            }
        }

        Ok(false)
    }

    pub fn adapt<A: Arch, O: Oracle<A>, C: Computation>(accesses: &MemoryAccesses<A, C>, o: &mut O, s: &mut SystemState<A>, changed: &HashSet<Location<A>>, changed_instr: bool) -> Result<bool, RandomizationError> {
        trace!("====== Begin adapt() ======");
        let recheck_constraints = accesses.memory[..s.memory.data.len()].iter()
            .enumerate()
            .filter(|(_, c)| changed_instr || changed.iter().any(|loc| c.inputs.get(loc).is_some()))
            .collect::<Vec<_>>();

        if recheck_constraints.len() > 0 {
            debug!("Changed {:?}, rechecking {:X?}", changed, recheck_constraints);
            let mut new_memory = s.memory.data.clone();
            
            for &(constraint_index, access) in recheck_constraints.iter() {
                trace!("Checking constraint {}: {:X?}", constraint_index, access);

                let (addr, computed) = if constraint_index == 0 {
                    (Some(s.cpu.reg(&A::Reg::pc())), true)
                } else {
                    s.memory.data = new_memory[0..constraint_index].to_owned();
                    trace!("Executing {:X?}", s);

                    let (result, computed) = access.compute_memory_access(&s)
                        .map(|e| (Err(e), true))
                        .unwrap_or_else(|| (o.observe(&s), false));
                    trace!("Result = {:X?}", result);
                    match result {
                        // We pass a rebuilt constraint instances list that contains all constraints except the one we're currently evaluating or are still going to evaluate
                        Err(OracleError::MemoryAccess(addr)) => (Some(addr), computed),
                        // We're accessing non-canonical or non-aligned memory
                        | Err(OracleError::GeneralFault)
                        // We should be seeing a memory error, but we aren't => Likely we mapped something onto an existing region
                        | Ok(_) => (None, computed),
                        Err(OracleError::ComputationError) => return Err(RandomizationError::ModifyingValuesFailed),
                        Err(OracleError::InvalidInstruction) => return Err(RandomizationError::InvalidInstruction),
                        Err(e) => todo!("Handle {}", e),
                    }
                };

                match addr {
                    Some(addr) if Self::good_addr(o, &new_memory.iter().enumerate()
                        .filter(|(index, _)| 
                            *index < constraint_index 
                            || !recheck_constraints.iter().any(|rc| rc.0 == *index)
                        )
                        .map(|(_, x)| x)
                        .cloned()
                        .collect::<Vec<_>>(), &accesses.memory.iter().enumerate()
                        .filter(|(index, _)| 
                            *index < constraint_index 
                            || !recheck_constraints.iter().any(|rc| rc.0 == *index)
                        )
                        .map(|(_, x)| x)
                        .cloned()
                        .collect::<Vec<_>>(), access, addr, new_memory[constraint_index].1, computed) => {
                        let old_addr = new_memory[constraint_index].0;
                        trace!("Changing memory #{} from {:X?} to {:X?}", constraint_index, old_addr, addr);
                        new_memory[constraint_index].0 = addr;
                    },
                    // We're either accessing memory that we can't map (e.g., already mapped memory or "negative" memory), or we did not find a memory access at all
                    _ => {
                        // Make sure we keep the state consistent
                        s.memory.data = new_memory.to_owned();
                        return Ok(false);
                    }
                }
            }

            // Trim memory data if we have some slices that are bigger than what we would expect from the constraints (this can occur when we're adapting from another instruction)
            for (constraint_index, constraint) in recheck_constraints.iter() {
                if *constraint_index != 0 {
                    let v = &mut new_memory[*constraint_index].2;
                    if v.len() > constraint.size.end {
                        v.resize(constraint.size.end, 0);
                    }
                }
            }

            s.memory.data = new_memory.to_owned();

            // Ensure that each memory allocation is on a separate page
            // TODO: Make sure accesses with different permissions or without calculations are on a separate page
            debug_assert!(s.memory.data.iter()
                .enumerate()
                .all(|(index, (a1, _, d1))| s.memory.data.iter()
                    .skip(index + 1)
                    .all(|(a2, _, d2)| a1 + d1.len() as u64 <= *a2 || *a1 >= a2 + d2.len() as u64)
                ),
                "Memory accesses must not overlap: {:X?} (rechecked: {:X?})", s, recheck_constraints
            );

            debug!("Adapted state: {:X?}", s);
        }

        trace!("====== Successfully completed adapt() ======");
        Ok(true)
    }

    fn fill_state<A: Arch, O: Oracle<A>, R: Rng, C: Computation + TryIntoBasicComputation>(accesses: &MemoryAccesses<A, C>, rng: &mut R, o: &mut O, state: &mut SystemState<A>, constraints: &[Constraint]) -> Result<FillResult, RandomizationError> {
        for (access_index, access) in accesses.memory.iter().enumerate().skip(1) {
            let mut n = 0;
            loop {
                trace!("Current fill state: {:X?}", state);
                let (result, computed) = access.compute_memory_access(&state)
                    .map(|e| (Err(e), true))
                    .unwrap_or_else(|| (o.observe(&state), false));
                n += 1;
                if n > 10 {
                    return Ok(FillResult::Unsatisfiable(access_index));
                }

                trace!("Result = {:X?}", result);

                let perms = match access.kind {
                    AccessKind::Input => if access.calculation.is_some() {
                        Permissions::ReadWrite
                    } else {
                        Permissions::Read
                    },
                    AccessKind::InputOutput => Permissions::ReadWrite,
                    AccessKind::Executable => Permissions::Execute,
                };
                match result {
                    // If we see no memory access even though we expected one, one of our previous access instantiations 
                    // caused an overlap where two memory accesses go to the same page. We need to retry everything in this case,
                    // as we do not know which of our instantiations caused the overlap.
                    Ok(_) => return Ok(FillResult::NoMemoryAccess(access_index)),
                    Err(OracleError::MemoryAccess(addr)) if Self::good_addr(o, &state.memory.data, &accesses.memory, access, addr, perms, computed) => {
                        // We have found acceptable values for this memory access!
                        let data = if access.kind == AccessKind::Executable {
                            accesses.instr.bytes().to_owned()
                        } else {
                            super::randomized_bytes(rng, access.size.end)
                        };

                        debug!("Filled {:X?} (index={}) @ address {:X} with {:X?}", access, access_index, addr, data);

                        state.memory.push(addr, perms, data);
                        break;
                    }
                    Err(OracleError::MemoryAccess(addr)) if state.memory.iter().any(|(other_addr, _, _)| *other_addr == addr) => {
                        // We have exactly this address already mapped, which means that this must be a write to a read-only page.
                        // Assuming we have identified the memory accesses correctly, this means that we are double-mapping some
                        // memory.
                        return Ok(FillResult::DoubleMappedMemory(access_index));
                    }
                    Err(OracleError::MemoryAccess(_)) | Err(OracleError::GeneralFault) => {
                        // The memory access from this combination of registers is not acceptable, so we randomize and retry
                        let mut n = 0;
                        loop {
                            let mut any_changed = false;
                            let ps = o.page_size();
                            let mut tries = 0;
                            'fix_loop: loop {
                                for reg in access.inputs.iter() {
                                    match reg {
                                        Source::Dest(Dest::Reg(reg, _)) => if !reg.is_zero() {
                                            state.set_reg(reg, randomized_value(rng));
                                            any_changed = true;
                                        },
                                        Source::Dest(Dest::Mem(index, _)) => {
                                            state.memory.data[*index].2 = super::randomized_bytes(rng, accesses.memory[*index].size.end);
                                        },
                                        Source::Dest(Dest::Flags) => {
                                            for flag in A::Flag::iter() {
                                                state.set_flag(&flag, rng.gen());
                                            }
                                        },
                                        Source::Dest(Dest::Flag(flag)) => {
                                            state.set_flag(flag, rng.gen());
                                            any_changed = true;
                                        },
                                        Source::Imm(_) | Source::Const { .. } => {},
                                    }
                                }

                                // If we have a constraint, we should check the constraint to make sure we are adhering to it.
                                // If we are not adhering to a constraint, fill_state is guaranteed to fail.
                                match constraints.get(access_index) {
                                    Some(c) => {
                                        if let Some(calculation) = access.calculation.as_ref().map(|c| c.basic()).flatten() {
                                            let new_addr = calculation.compute(&access.inputs, &state);
                                            if o.can_map(new_addr) {
                                                let page_offset = new_addr % ps;
                                                let delta = match c {
                                                    Constraint::Impossible => return Ok(FillResult::Unsatisfiable(access_index)),
                                                    Constraint::None => break,
                                                    Constraint::PageRegion { min_offset, max_offset } => if page_offset >= *min_offset && page_offset <= *max_offset {
                                                        debug!("Constraint OK");
                                                        break
                                                    } else {
                                                        let fixed_offset = if min_offset == max_offset {
                                                            *min_offset
                                                        } else {
                                                            rng.gen_range(*min_offset, max_offset)
                                                        };
                                                        let fixed_addr = (new_addr / ps) * ps + fixed_offset;

                                                        fixed_addr.wrapping_sub(new_addr)
                                                    },
                                                };

                                                debug!("Trying to fix randomization because a constraint is not valid: {:X?} on page offset {:X} (address = {:X}) (all constraints = {:X?}) in state: {:X?}", c, page_offset, new_addr, constraints, state);

                                                for (index, reg) in access.inputs.iter().enumerate() {
                                                    if index != calculation.scaled_index || calculation.scale == 1 {
                                                        match reg {
                                                            Source::Dest(Dest::Reg(reg, _)) if !reg.is_zero() => {
                                                                state.set_reg(reg, state.cpu.reg(reg).wrapping_add(delta));
                                                                any_changed = true;
                                                                debug!("Fixed state: {:X?}", state);

                                                                debug!("New memory location: {:X?} ({:X?})", calculation.compute(&access.inputs, &state), access);
                                                                break 'fix_loop;
                                                            },
                                                            _ => {},
                                                        }
                                                    }
                                                }
                                            }
                                        } else {
                                            break
                                        }
                                    },
                                    None => {
                                        if access.alignment > 1 {
                                            // TODO: Try to correct the inputs such that the memory access is properly aligned
                                        }

                                        break
                                    },
                                }

                                tries += 1;
                                if tries > 10_000 {
                                    return Ok(FillResult::Unsatisfiable(access_index));
                                }
                            }

                            if !any_changed {
                                // This is a fixed address so we cannot change it.
                                // We have to restart from the beginning
                                warn!("Found an unmappable fixed offset: {:X?}", result);
                                return Ok(FillResult::UnmappableFixedOffset(access_index));
                            }

                            if Self::adapt(accesses, o, state, &access.inputs.iter().flat_map(|i| Location::try_from(i).ok()).collect(), false)? {
                                break;
                            } else {
                                n += 1;
                                if n > 50 {
                                    return Ok(FillResult::Unsatisfiable(access_index));
                                }
                            }
                        }
                    }
                    Err(OracleError::ComputationError) => return Ok(FillResult::Invalid),
                    Err(OracleError::InvalidInstruction) => return Ok(FillResult::InvalidInstruction),
                    Err(e) => {
                        // TODO: What if we end up in an enless loop here?
                        warn!("Unexpected error encountered while randomizing: {}", e)
                    }
                }
            }
        }

        // TODO: We may need to verify that none of our mappings are double mapped.

        Ok(FillResult::Ok)
    }

    fn randomize_register<A: Arch, O: Oracle<A>, R: Rng, C: Computation>(accesses: &MemoryAccesses<A, C>, rng: &mut R, o: &mut O, reg: &A::Reg) -> u64 {
        if reg.is_pc() {
            let pages = o.valid_executable_addresses();
            let page_size = o.page_size();
            let page = {
                let mut result = (randomized_value(rng) / page_size) * page_size;
                while result < pages.start || result >= pages.end {
                    result = (randomized_value(rng) / page_size) * page_size;
                }

                result
            };

            let page = page..page + page_size;
            // It is tempting to just always put the PC near the end or the start of a page.
            // This reduces the differences in PC that we will see.
            // If there are some instructions that use the PC as part of a computation, we will never observe the full input space.
            // This is a problem, for example because we won't be able to infer alignment for memory accesses of the form (pc + 0x....)
            // Therefore we add a small offset of up to 31. We ensure that lower offsets occur more often.
            let pc_offset = (rng.gen_range(0, 0x80) | 0x80 ) >> rng.gen_range(0, 9);
            if rng.gen() {
                page.start + pc_offset
            } else {
                page.end - accesses.instr.byte_len() as u64 - pc_offset
            }

            // rng.gen_range(page.start, page.end - instr.byte_len() as u64)
        } else {
            randomized_value(rng)
        }
    }

    pub fn randomize_new<A: Arch, O: Oracle<A>, R: Rng, C: Computation + TryIntoBasicComputation>(accesses: &MemoryAccesses<A, C>, rng: &mut R, o: &mut O) -> Result<SystemState<A>, RandomizationError> {
        let mut rng2 = rand::thread_rng();
        let mut last_result = FillResult::Ok;
        let mut error_counter = 0;
        let ps = o.page_size();
        let constraints = accesses.memory.iter()
            .map(|m| m.calculation.as_ref().map(|c| c.basic()).flatten().map(|c| {
                if m.inputs.len() <= 0 && !o.can_map(c.offset as u64) {
                    return Constraint::Impossible;
                }

                let offsets = accesses.memory.iter()
                    .filter(|other| other.inputs == m.inputs)
                    .flat_map(|other| other.calculation.as_ref().map(|c| c.basic()).flatten().map(|other| c.constant_offset_with(other)).flatten().map(|x| (other, x)))
                    .filter(|(_, n)| n.abs() < ps as i64)
                    .collect::<Vec<_>>();

                if offsets.len() <= 1 {
                    Constraint::PageRegion {
                        min_offset: 0,
                        max_offset: ps - m.size.end as u64,
                    }
                } else {
                    if offsets.iter().all(|(access, _)| access.calculation.is_some()) {
                        Constraint::PageRegion {
                            min_offset: 0,
                            max_offset: ps - m.size.end as u64,
                        }
                    } else {
                        if offsets.len() > 2 {
                            Constraint::Impossible
                        } else {
                            let (other, offset) = offsets.into_iter()
                                .filter(|(_, offset)| *offset != 0)
                                .next()
                                .unwrap();

                            if offset < 0 {
                                let max_offset = -(offset + other.size.end as i64);
                                if max_offset >= 0 {
                                    Constraint::PageRegion {
                                        min_offset: 0,
                                        max_offset: max_offset as u64,
                                    }
                                } else {
                                    Constraint::Impossible
                                }
                            } else if offset > 0 {
                                if m.size.end <= offset as usize {
                                    Constraint::PageRegion {
                                        min_offset: ps - offset as u64,
                                        max_offset: ps - m.size.end as u64,
                                    }
                                } else {
                                    Constraint::Impossible
                                }
                            } else {
                                Constraint::Impossible
                            }
                        }
                    }
                }
            }).unwrap_or(Constraint::None))
            .collect::<Vec<_>>();
        debug!("Constraints = {:X?}", constraints);
        
        if let Some(index) = constraints.iter().position(|c| matches!(c, Constraint::Impossible)) {
            return Err(RandomizationError::Unsatisfiable(index));
        }

        for _ in 0..5_000 {
            // We pre-fill the executable page, since we know that we're going to need it anyways so doing an observation for that is just wasting time
            let state = A::CpuState::create(
            |reg| Self::randomize_register(accesses, rng, o, reg), 
            |_| rng2.gen()
            );
            let pc = state.reg(&A::Reg::pc());
            let mut state = SystemState::new(state, MemoryState::new([ (pc, Permissions::Execute, accesses.instr.bytes().to_vec()) ].iter().cloned()));

            // Try to fill the state. If this fails, one of the filled constraints caused an overlap. 
            // When that happens, we retry from the start with different values by looping again.
            let result = Self::fill_state(accesses, rng, o, &mut state, &constraints)?;

            if let FillResult::Ok = result {
                return Ok(state);
            } if let FillResult::InvalidInstruction = result {
                return Err(RandomizationError::OracleError(OracleError::InvalidInstruction));
            } else {
                if last_result == result {
                    error_counter += 1;
                } else {
                    error_counter = 1;
                    last_result = result;
                }
            }
        }

        if error_counter >= 50 {
            match last_result {
                FillResult::Ok => unreachable!(),
                FillResult::UnmappableFixedOffset(index) => Err(RandomizationError::UnmappableFixedOffset(index)),
                FillResult::NoMemoryAccess(index) => Err(RandomizationError::NoMemoryAccess(index)),
                FillResult::Unsatisfiable(index) => Err(RandomizationError::Unsatisfiable(index)),
                FillResult::DoubleMappedMemory(index) => Err(RandomizationError::Unsatisfiable(index - 1)),
                FillResult::Invalid => Err(RandomizationError::ModifyingValuesFailed),
                FillResult::InvalidInstruction => unreachable!(),
            }
        } else {
            Err(RandomizationError::RandomStateSynthesisFailed)
        }
    }

    pub fn modify_locations<A: Arch, O: Oracle<A>, R: Rng, C: Computation>(accesses: &MemoryAccesses<A, C>, rng: &mut R, o: &mut O, base: SystemState<A>, locations: &[Location<A>]) -> Result<SystemState<A>, RandomizationError> {
        let mut s = base;

        trace!("Current: {:X?}", s);

        let mut n = 0;
        loop {
            // We randomize all locations
            for loc in locations.iter() {
                match loc {
                    Location::Reg(reg) => s.set_reg(reg, Self::randomize_register(accesses, rng, o, reg)),
                    Location::Memory(index) => {
                        let constraint = &accesses.memory[*index];
                        s.memory.data[*index].2 = super::randomized_bytes(rng, constraint.size.end);
                        trace!("Modifying memory {:X?} to {:X?}", index, s.memory.data[*index].2);
                    },
                    Location::Flags => for flag in A::Flag::iter() {
                        s.set_flag(&flag, rng.gen());
                    },
                    Location::Flag(flag) => s.set_flag(&flag, rng.gen()),
                }
            }

            trace!("Modified: {:X?}", s);
            if Self::adapt(accesses, o, &mut s, &locations.iter().cloned().collect(), false)? {
                trace!("Adapted: {:X?}", s);
                return Ok(s);
            } else {
                n += 1;
                if n > 5000 {
                    return Err(RandomizationError::ModifyingValuesFailed);
                }
            }
        }
    }

    pub fn remap<A: Arch, O: Oracle<A>, C: Computation>(accesses: &MemoryAccesses<A, C>, o: &mut O, cs: &SystemState<A>) -> Result<SystemState<A>, RemapError<A>> {
        let ps = o.page_size();
        let new_instr = accesses.instr.as_instr();

        let mut cs = cs.clone();
        let pc = cs.cpu.reg(&A::Reg::pc());
        if pc / ps != (pc + new_instr.byte_len() as u64 - 1) / ps {
            return Err(RemapError::MemoryMappingCrossesPageBounds(0));
        }

        if !o.can_map(pc) {
            return Err(RemapError::CannotMapMemory(0));
        }

        cs.memory.data[0] = (pc, Permissions::Execute, new_instr.bytes().to_owned());

        if Self::adapt(accesses, o, &mut cs, &Default::default(), true)? {
            Ok(cs)
        } else {
            Err(RemapError::AdaptFailed)
        }
    }

    pub fn randomize_value<T, R: Rng>(rng: &mut R, value: &'_ Value, bytes_to_keep_unchanged: &[bool], mut f: impl FnMut(Value<'_>) -> T) -> T {
        match value {
            Value::Num(n) => loop {
                let new = if rng.gen() {
                    randomized_value(rng)
                } else {
                    rng.gen()
                };

                let mask = bytes_to_keep_unchanged.iter()
                    .rev()
                    .map(|&b| if b { 0xff } else { 0u64 })
                    .fold(0, |acc, b| (acc << 8) | b);

                let new = Value::Num((n & mask) | (new & !mask));
                if &new != value {
                    return f(new);
                }
            }
            Value::Bytes(b) => loop {
                let mut new = crate::randomized_bytes(rng, b.len());
                for (index, _) in bytes_to_keep_unchanged.iter().enumerate().filter(|(_, keep)| **keep) {
                    new[index] = b[index];
                }

                let new = Value::Bytes(&new);
                if &new != value {
                    return f(new);
                }
            }
            Value::FlagBitmap(_) => unimplemented!("Cannot alter bytes in Flags"),
        }
    }
}


pub struct ModifySingleLocationIter<'a, A: Arch, O: Oracle<A>, R: Rng, C: Computation> {
    constraints: &'a MemoryAccesses<A, C>,
    locations: &'a [Location<A>],
    base: SystemState<A>,
    oracle: &'a mut O,
    rng: &'a mut R,
}

impl<'a, A: Arch, O: Oracle<A>, R: Rng, C: Computation> ModifySingleLocationIter<'a, A, O, R, C> {
    pub fn new(accesses: &'a MemoryAccesses<A, C>, rng: &'a mut R, o: &'a mut O, base: SystemState<A>, locations: &'a [Location<A>]) -> Self {
        ModifySingleLocationIter {
            constraints: accesses,
            locations,
            base,
            oracle: o,
            rng,
        }
    }
}

impl<'a, A: Arch + 'static, O: Oracle<A>, R: Rng, C: Computation> Iterator for ModifySingleLocationIter<'a, A, O, R, C> {
    type Item = Result<(SystemState<A>, Result<SystemState<A>, OracleError>), RandomizationError>;

    fn next(&mut self) -> Option<Self::Item> {
        match StateGen::modify_locations(self.constraints, self.rng, self.oracle, self.base.clone(), self.locations) {
            Ok(new_state) => {
                let result = self.oracle.observe(&new_state);
                Some(Ok((new_state, result)))
            },
            Err(e) => Some(Err(e)),
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum FillResult {
    Ok,
    UnmappableFixedOffset(usize),
    NoMemoryAccess(usize),
    Unsatisfiable(usize),
    DoubleMappedMemory(usize),
    Invalid,
    InvalidInstruction,
}
