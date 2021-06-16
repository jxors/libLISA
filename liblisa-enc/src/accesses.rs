use std::{collections::{HashMap, HashSet}, convert::TryInto, fmt::Debug, ops::Range};
use fallible_iterator::{FallibleIterator, convert};
use itertools::Itertools;
use log::{debug, error, info, trace, warn};
use maplit::hashset;
use rand::Rng;
use thiserror::Error;
use liblisa_core::arch::{Arch, Flag, Instr, InstructionInfo, Permissions, Register, State, SystemState, Value};
use liblisa_core::oracle::{Oracle, CarefulOracle, OracleError};
use liblisa_core::{Dest, IntoSourceWithSize, Location, Size, Source, Inputs};
use liblisa_core::accesses::{MemoryAccesses, MemoryAccess, AccessKind};
use liblisa_core::computation::{Computation, BasicComputation};
use liblisa_core::gen::{RandomizationError, StateGen, ModifySingleLocationIter};

#[derive(Error, Debug, Clone)]
pub enum ConstraintAnalysisError<A: Arch> {
    #[error("Phantom")]
    Phantom(A),

    #[error("Unable to randomize: {}", .0)]
    Randomization(RandomizationError),

    #[error("Oracle gave an error: {}", .0)]
    OracleError(OracleError),

    #[error("Finding an input for memory access #{} failed: {}", .0, .1)]
    FindInputFailed(usize, FindInputError),

    #[error("Memory access #{} accesses unaccessable memory", .0)]
    UnaccessibleMemoryAccess(usize),

    #[error("The instruction keeps causing CPU faults, no matter the inputs")]
    InstructionKeepsFaulting,

    #[error("Encountered a page fault on a page that is already readable and writeable")]
    MemoryErrorOnWritableRegion,

    #[error("Invalid instruction")]
    InvalidInstruction,

    #[error("Instruction is emulated")]
    InstructionIsEmulated,
}

impl<A: Arch> From<RandomizationError> for ConstraintAnalysisError<A> {
    fn from(e: RandomizationError) -> Self {
        ConstraintAnalysisError::Randomization(e)
    }
}

impl<A: Arch> From<OracleError> for ConstraintAnalysisError<A> {
    fn from(e: OracleError) -> Self {
        ConstraintAnalysisError::OracleError(e)
    }
}


trait Distill {
    fn distill(self, init: Range<usize>) -> Range<usize>;
}

impl<I: Iterator<Item = Range<usize>>> Distill for I {
    fn distill(mut self, init: Range<usize>) -> Range<usize> {
        let mut acc = init;
        while let Some(el) = self.next() {
            acc = acc.start.max(el.start)..acc.end.min(el.end);

            if acc.len() == 0 {
                break;
            }
        }

        acc
    }
}

trait DistillFallible<E> {
    fn distill_fallible(self, init: Range<usize>) -> Result<Range<usize>, E>;
}

impl<E, I: FallibleIterator<Item = Range<usize>, Error = E>> DistillFallible<E> for I {
    fn distill_fallible(mut self, init: Range<usize>) -> Result<Range<usize>, E> {
        let mut acc = init;
        while let Some(el) = self.next()? {
            acc = acc.start.max(el.start)..acc.end.min(el.end);

            if acc.len() == 0 {
                break;
            }
        }

        Ok(acc)
    }
}


trait DistillFallibleOption<E> {
    fn distill_fallible(self, init: Range<usize>) -> Result<Range<usize>, E>;
}

impl<E, I: FallibleIterator<Item = Option<Range<usize>>, Error = E>> DistillFallibleOption<E> for I {
    fn distill_fallible(mut self, init: Range<usize>) -> Result<Range<usize>, E> {
        let mut acc = init;
        while let Some(el) = self.next()? {
            if let Some(el) = el {
                acc = acc.start.max(el.start)..acc.end.min(el.end);
            }

            if acc.len() == 0 {
                break;
            }
        }

        Ok(acc)
    }
}

#[derive(Debug, Error, Clone)]
pub enum FindInputError {
    #[error("has_change failed: {}", .0)]
    HasInputFailed(OracleError),

    #[error("Modification failed: {}", .0)]
    RandomizationFailed(RandomizationError),

    #[error("Generic oracle error: {}", .0)]
    OracleError(OracleError),

    #[error("This instruction receives external inputs that we cannot observe")]
    UnobservableExternalInputs,
}

impl From<OracleError> for FindInputError {
    fn from(e: OracleError) -> Self {
        FindInputError::OracleError(e)
    }
}

impl From<RandomizationError> for FindInputError {
    fn from(e: RandomizationError) -> Self {
        FindInputError::RandomizationFailed(e)
    }
}

pub struct MemoryAccessAnalysis;

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum SizeKind {
    Before(u64),
    After(u64),
}

#[derive(Debug, Copy, Clone)]
enum CheckSizeResult {
    Impossible,
    Failed,
    Increase,
    Ok,
}

struct BasicComputationIterator<'a, A: Arch> {
    inputs: &'a Inputs<A>,
    bases: &'a [(SystemState<A>, u64)],
}

impl<'a, A: Arch> BasicComputationIterator<'a, A> {
    pub fn new(inputs: &'a Inputs<A>, bases: &'a [(SystemState<A>, u64)]) -> BasicComputationIterator<'a, A> {
        BasicComputationIterator {
            inputs,
            bases,
        }
    }

    pub fn run(&self, f: impl Fn(&BasicComputation) -> bool) -> Vec<BasicComputation> {
        let mut seen = HashSet::new();
        let mut possible_calculations = Vec::new();
        for (base, addr) in self.bases.iter() {
            let c = BasicComputation::new_with_inferred_offset(1, 0, self.inputs, &base, *addr);
            if !seen.contains(&c.offset) {
                seen.insert(c.offset);

                if f(&c) {
                    possible_calculations.push(c);
                }
            }
        }

        for scale_index in 0..self.inputs.len() {
            for scale in [2, 3, 4, 5, 8, 9].iter().copied() {
                seen.clear();
                for (base, addr) in self.bases.iter() {
                    let c = BasicComputation::new_with_inferred_offset(scale, scale_index, &self.inputs, &base, *addr);
                    if !seen.contains(&c.offset) {
                        seen.insert(c.offset);

                        if f(&c) {
                            possible_calculations.push(c);
                        }
                    }
                }
            }
        }

        possible_calculations
    }
}


struct BaseGenerator<'a, A: Arch, O: Oracle<A>, R: Rng> {
    accesses: &'a MemoryAccesses<A, BasicComputation>,
    oracle: &'a mut O,
    bases: Vec<(SystemState<A>, u64)>,
    unaddressable: Vec<SystemState<A>>,
    oks: usize,
    ignored: usize,
    rng: &'a mut R,
    distinct_values: HashMap<A::Reg, HashSet<u64>>,
    max_memory_spacing: i64,
    instr_is_emulated: bool,
}

impl<'a, A: Arch + 'static, O: Oracle<A>, R: Rng> BaseGenerator<'a, A, O, R> {
    pub fn new(oracle: &'a mut O, accesses: &'a MemoryAccesses<A, BasicComputation>, rng: &'a mut R) -> Self {
        BaseGenerator {
            oracle,
            accesses,
            bases: Vec::new(),
            unaddressable: Vec::new(),
            oks: 0,
            ignored: 0,
            rng,
            distinct_values: HashMap::new(),
            max_memory_spacing: 0,
            instr_is_emulated: false,
        }
    }

    fn consider_base(&mut self, base: &SystemState<A>) -> bool {
        let ps = self.oracle.page_size();
        let base_result = self.oracle.observe(&base);
        trace!("Base with result {:X?}: {:X?}", base_result, base);
        if let Err(OracleError::MemoryAccess(addr)) = base_result {
            // If the memory access occurs just past the end of a mapped page, the address is likely not the base address.
            // The first few bytes on the mapped page would not have caused a page fault.
            // We also ignore memory errors on already mapped pages, since those are ignored during early synthesis.
            if base.memory.iter().any(|(mapped_addr, _, _)| (mapped_addr / ps + 1) * ps == addr || mapped_addr / ps == addr / ps) {
                // self.oracle.debug_dump();

                let instr_mapping = &base.memory.data[0];
                let is_emulated = if instr_mapping.0 + instr_mapping.2.len() as u64 == addr {
                    // This might be a kernel-emulated instruction.
                    // Some instructions (sgdt, lgdt, etc.) are blocked via UMIP.
                    // These instructions are emulated by the kernel.
                    // The kernel does a bad job of emulating.
                    // It does not trigger the breakpoint after executing one instruction.
                    // It does not trigger page faults at the right addresses.
                    // It might change behavior from one kernel version to another.
                    // We try to detect this by observing some side-effects.
                    let is_executed = if base.memory.iter().any(|(mapped_addr, perms, _)| mapped_addr / ps == addr / ps && perms == &Permissions::ReadWrite) {
                        true
                    } else {
                        let mut s = base.clone();
                        s.memory.push(addr, Permissions::ReadWrite, vec![ 0x00 ]);
                        let result = self.oracle.observe(&s);

                        if let Err(OracleError::MemoryAccess(new_addr)) = result {
                            new_addr == addr
                        } else {
                            false
                        }
                    };

                    if is_executed {
                        // TODO: x86 specific code
                        // TODO: This should no longer be necessary because we eliminated these instructions via the validity check
                        // Check 1.
                        // No break is triggered after executing an emulated instruction. 
                        // We can observe this by appending an undefined instruction after the real instruction.
                        // If we see an #UD, we know the break is not triggered.
                        let mut s = base.clone();
                        s.cpu.set_reg(&A::Reg::pc(), s.cpu.reg(&A::Reg::pc()) - 2);
                        let entry = &mut s.memory.data[0];
                        entry.0 -= 2;
                        entry.2.push(0x0F);
                        entry.2.push(0x0B);
                        let is_invalid_instr = if StateGen::adapt(self.accesses, self.oracle, &mut s, &hashset![ Location::Reg(A::Reg::pc()) ], false).unwrap() {
                            let result = self.oracle.observe(&s);
                            match result {
                                Err(OracleError::InvalidInstruction) => true,
                                _ => false
                            }
                        } else {
                            false
                        };

                        // Check 2.
                        // No break is triggered after executing an emulated instruction. 
                        // We can observe this by appending a break instruction (int 0x3).
                        // If the CPU breaks after the breakpoint, we know the actual break *before* the break instruction did not trigger.
                        let mut s = base.clone();
                        let entry = &mut s.memory.data[0];
                        s.cpu.set_reg(&A::Reg::pc(), s.cpu.reg(&A::Reg::pc()) - 1);
                        entry.0 -= 1;
                        entry.2.push(0xCC);
                        let is_break = if StateGen::adapt(self.accesses, self.oracle, &mut s, &hashset![ Location::Reg(A::Reg::pc()) ], false).unwrap() {
                            match self.oracle.observe(&s) {
                                Ok(result) if result.cpu.reg(&A::Reg::pc()) == addr => true,
                                _ => false
                            }
                        } else {
                            false
                        };

                        is_invalid_instr && is_break
                    } else {
                        false
                    }
                } else {
                    false
                };

                if !is_emulated {
                    self.ignored += 1;
                } else {
                    self.instr_is_emulated = true;
                }

                false
            } else {
                for reg in A::Reg::iter() {
                    self.distinct_values.entry(reg.clone())
                        .or_insert(HashSet::new())
                        .insert(base.cpu.reg(&reg));
                }

                let spacing = base.memory.iter().enumerate()
                    .flat_map(|(index, (existing_addr, _, _))| base.memory.iter().skip(index + 1)
                        .map(|(addr2, _, _)| (existing_addr.wrapping_sub(*addr2) as i64).abs())
                        .min()
                    )
                    .chain(base.memory.iter()
                        .map(|(existing_addr, _, _)| (existing_addr.wrapping_sub(addr) as i64).abs())
                    )
                    .min()
                    .unwrap_or(0);

                self.max_memory_spacing = spacing.max(self.max_memory_spacing);
                
                self.bases.push((base.clone(), addr));
                true
            }
        } else if let Err(OracleError::GeneralFault) = base_result {
            // We cannot increment `ignored` here, because UnaddressableMemory might be caused by alignment issues.
            // This means that we can see this error even if we have correctly mapped all memory accesses.
            // We should therefore rely on actual page faults to detect memory accesses.
            // If an instruction is *only* accessing unadressable memory, we won't increment `self.oks` and MA analysis will still fail.

            self.unaddressable.push(base.clone());
            false
        } else {
            self.oks += 1;
            true
        }
    }

    pub fn gen(&mut self) -> Result<(), ConstraintAnalysisError<A>> {
        let ps = self.oracle.page_size();
        #[derive(Debug)]
        struct MemoryGroup {
            fronts: Vec<usize>,
            backs: Vec<usize>,
        }

        let mut by_input = HashMap::new();
        for (index, access) in self.accesses.iter().enumerate() {
            let c = access.calculation.as_ref().unwrap();
            by_input
                .entry(&access.inputs).or_insert(HashMap::new())
                .entry((c.scale, c.scaled_index)).or_insert(Vec::new())
                .push((index, access));
        }

        let mut memory_groups = Vec::new();
        for (_, mut input_group) in by_input.drain() {
            let mut fronts = Vec::new();
            let mut backs = Vec::new();

            for (_, mut group) in input_group.drain() {
                group.sort_by_key(|(_, access)| access.calculation.as_ref().unwrap().offset);

                let mut lowest = i64::MIN;
                for (index, access) in group.iter() {
                    let v = access.calculation.as_ref().unwrap().offset;
                    if lowest + (ps as i64) < v {
                        fronts.push(*index);
                        lowest = v;
                    }
                }

                let mut highest = i64::MAX;
                for (index, access) in group.iter().rev() {
                    let v = access.calculation.as_ref().unwrap().offset;
                    if v < highest - ps as i64 {
                        backs.push(*index);
                        highest = v;
                    }
                }
            }

            memory_groups.push(MemoryGroup { fronts, backs });
        }

        info!("Memory groups: {:?}", memory_groups);
        for _ in 0..2000 {
            debug!("Generated {} bases so far... (max_memory_spacing={})", self.bases.len(), self.max_memory_spacing);
            for _ in 0..100 {
                if let Ok(base) = StateGen::randomize_new(self.accesses, self.rng, self.oracle) {
                    // First, we consider the completely randomly generated state.
                    // It usually has memory mapped somewhere near the middle or end of a page because of randomization weights
                    if self.consider_base(&base) {
                        // Now we try to generate a state where accesses are placed at the start (1/3) or the end of a page (1/3).
                        let mut state = base.clone();
                        trace!("");
                        for group in memory_groups.iter() {
                            match self.rng.gen_range(0, 3) {
                                // Leave the memory access alone
                                0 => {},
                                // Relocate a front to the start of a page
                                1 => {
                                    let index = self.rng.gen_range(0, group.fronts.len());
                                    let index = group.fronts[index];
                                    let access = &self.accesses[index];

                                    // Put this memory at the start of the page
                                    let addr = state.memory.data[index].0;
                                    let target = (addr / ps) * ps;
                                    let offset = target.wrapping_sub(addr) as i64;
                                    if offset != 0 {
                                        if let Some(new_state) = MemoryAccessAnalysis::relocate(self.oracle, &state, offset, self.accesses, &access.inputs, access.calculation.as_ref().unwrap())? {
                                            self.consider_base(&new_state);
                                            state = new_state;
                                        }
                                    }
                                },
                                // Relocate a back to the end of the page
                                2 => {
                                    let index = self.rng.gen_range(0, group.backs.len());
                                    let index = group.backs[index];
                                    let access = &self.accesses[index];

                                    // Put this memory at the end of the page
                                    let addr = state.memory.data[index].0;
                                    let target = (addr / ps + 1) * ps - access.size.end as u64;
                                    let offset = target.wrapping_sub(addr) as i64;
                                    if offset != 0 {
                                        if let Some(new_state) = MemoryAccessAnalysis::relocate(self.oracle, &state, offset, self.accesses, &access.inputs, access.calculation.as_ref().unwrap())? {
                                            self.consider_base(&new_state);
                                            state = new_state;
                                        }
                                    }
                                },
                                _ => unreachable!(),
                            }
                        }
                    }
                }
            }

            if self.instr_is_emulated && self.ignored > 0 {
                break;
            }

            // If memory accesses are closer together, we need more bases.
            // It is harder to generate useful states when the next memory access is close to an existing memory access.
            // Therefore, if we have found some memory access that is really close to an existing memory access,
            // we should do more work to make sure there is no memory access between the one we found and the existing one.
            let bases_needed = match self.max_memory_spacing {
                x if x < 32 => 10_000,
                x if x < 64 => 5000,
                x if x < 2 * ps as i64 => 2000,
                _ => 500,
            };

            // We need to get a good selection of randomized states. 
            // Most importantly, we need to have cases with many different values for registers.
            // This is necessary to be able to correctly synthesize the address expression.
            let enough_oks = self.ignored <= 0 && self.oks >= 2500 && self.bases.len() <= 0;
            let enough_bases = self.bases.len() >= bases_needed && A::Reg::iter().all(|reg| self.distinct_values.get(&reg)
                .map(|set| set.len() > 250)
                .unwrap_or(false)
            );
            let enough_unaddressable = self.unaddressable.len() >= 10_000 && self.oks <= 0 && self.ignored <= 0;
            if enough_oks || enough_bases || enough_unaddressable {
                break;
            }
        }

        info!("{} bases generated, {} ok, {} ignored", self.bases.len(), self.oks, self.ignored);

        Ok(())
    }
}

impl MemoryAccessAnalysis {
    /// Finds the calculation that computes the memory address for bases, if such a calculation exists.
    /// Calculations are a sum of inputs where one input might be scaled by a constant.
    fn find_calculation<A: Arch + 'static>(ps: u64, bases: &[(SystemState<A>, u64)]) -> Option<(Inputs<A>, BasicComputation)> {
        let registers = A::Reg::iter().map(|reg| Source::Dest(Dest::Reg(reg, Size::qword()))).sorted().collect::<Vec<_>>();
        for num_inputs in 0..4 {
            let input_iter = registers.iter().cloned().combinations(num_inputs);
            for inputs in input_iter {
                let inputs = Inputs::sorted(inputs);
                debug!("Inputs: {}", inputs);
                let possible_calculations = BasicComputationIterator::new(&inputs, bases)
                    .run(|calculation| {
                        let mut any_valid = false;
    
                        for (base, addr) in bases.iter() {
                            let v = calculation.compute(&inputs, &base);
                            if v == *addr {
                                any_valid = true;
                            } else if base.memory.iter().any(|(addr, _, _)| addr / ps == v / ps) {
                                // TODO: Take memory size into account as well...
                                // The new memory access overlaps a previous memory access, but not always
                            } else {
                                trace!("{:?} w/ {:?} eliminated because of access 0x{:X} in: {:X?}", inputs, calculation, addr, base);
                                return false;
                            }
                        }
    
                        debug!("{:?} w/ {:?} is acceptable for all {} bases", inputs, calculation, bases.len());
    
                        // If we only saw overlapping instances, we consider the calculation invalid
                        any_valid
                    });

                if possible_calculations.len() == 1 {
                    let c = possible_calculations.into_iter().next().unwrap();
                    info!("Address calculation: {:?} {:?}", c, inputs);
                    return Some((inputs, c));
                } else if possible_calculations.len() > 1 {
                    warn!("Multiple possible calculations: {:X?}", possible_calculations);
                    return None;
                }
            }
        }

        None
    }

    /// Finds a base state where there is at least 1 page between this memory access and any other memory access
    fn find_size_base<A: Arch + 'static, O: Oracle<A>, R: Rng>(rng: &mut R, o: &mut O, accesses: &MemoryAccesses<A, BasicComputation>, inputs: &Inputs<A>, calculation: &BasicComputation, before: bool) -> Result<Option<(SystemState<A>, u64)>, RandomizationError> {
        let ps = o.page_size();
        for _ in 0..10_000 {
            let state = StateGen::randomize_new(accesses, rng, o)?;
            let expected = calculation.compute(inputs, &state);
            match o.observe(&state) {
                Err(OracleError::MemoryAccess(new_addr)) if new_addr == expected 
                    && new_addr >= ps * 4 
                    && o.can_map(new_addr) 
                    && (o.can_map(new_addr + ps) || before)
                    && (o.can_map(new_addr - ps) || !before)
                    && state.memory.iter().all(|(addr, _, _)| {
                        let p_mapped = addr / ps;
                        let p_new = new_addr / ps;

                        p_mapped != p_new && if before {
                            p_new.wrapping_sub(1) != p_mapped
                        } else {
                            p_new.wrapping_add(1) != p_mapped
                        }
                    }) => {
                    let mut s = state.clone();
                    s.memory.push((new_addr / ps) * ps, Permissions::ReadWrite, vec![ 0 ]);

                    match o.observe(&s) {
                        Ok(_) | Err(OracleError::MemoryAccess(_)) | Err(OracleError::ComputationError) | Err(OracleError::InvalidInstruction) => {
                            return Ok(Some((state, new_addr)));
                        }
                        _ => {},
                    }
                }
                _ => {},
            }
        }

        Ok(None)
    }

    fn relocate<A: Arch + 'static, O: Oracle<A>>(o: &mut O, state: &SystemState<A>, offset: i64, accesses: &MemoryAccesses<A, BasicComputation>, inputs: &Inputs<A>, calculation: &BasicComputation) -> Result<Option<SystemState<A>>, ConstraintAnalysisError<A>> {
        if inputs.len() <= 0 {
            return Ok(None);
        }

        let mut state = state.clone();
        // We choose a single input to alter.
        // If possible, we choose an input with a scale of 1.
        // If there are multiple inputs with a scale of 1, we choose the input that occurs the least in other memory accesses.
        // If there is no input with a scale of 1, there is only 1 input. We must choose that input.
        let (relocation_index, relocation_loc) = inputs.iter().enumerate()
            .min_by_key(|(index, source)| if calculation.scaled_index != *index || calculation.scale == 1 {
                accesses.iter().filter(|a| a.inputs.contains(source)).count()
            } else {
                usize::MAX
            })
            .unwrap();
        let scale = if calculation.scaled_index == relocation_index {
            calculation.scale as i64
        } else {
            1
        };

        // If we are modifying a scaled input, we need the offset to be a multiple of the scale
        let offset = if offset % scale != 0 {
            return Ok(None);
        } else {
            offset / scale
        };

        let relocation_loc = Location::from(relocation_loc.clone().unwrap_dest());
        let base_value = if let Value::Num(n) = state.get_location(&relocation_loc).unwrap() {
            n
        } else {
            panic!("General-purpose register does not contain a number?");
        };

        let new_value = base_value.wrapping_add(offset as u64);
        state.set_location(&relocation_loc, Value::Num(new_value));

        debug!("Adapting state: {:?}", state);
        Ok(if StateGen::adapt(accesses, o, &mut state, &hashset![ relocation_loc ], false)? {
            Some(state)
        } else {
            None
        })
    }

    fn check_size<A: Arch + 'static, O: Oracle<A>, R: Rng>(rng: &mut R, o: &mut O, accesses: &MemoryAccesses<A, BasicComputation>, inputs: &Inputs<A>, calculation: &BasicComputation, size: SizeKind) -> Result<CheckSizeResult, ConstraintAnalysisError<A>> {
        if inputs.len() <= 0 {
            return Ok(CheckSizeResult::Impossible);
        }

        let ps = o.page_size();
        if let Some((base, base_addr)) = Self::find_size_base(rng, o, accesses, inputs, calculation, matches!(size, SizeKind::Before(_)))? {
            trace!("Choosing 0x{:X} as base address", base_addr);
            let page_index = base_addr / ps;
            let page_start = page_index * ps;
            let page_end = (page_index + 1) * ps;

            let (target_addr, expected_access) = match size {
                SizeKind::After(n) => (page_end - n, page_end),
                SizeKind::Before(n) => (page_start + n, page_start),
            };

            debug!("Checking offset={:?} at target address 0x{:X}", size, target_addr);
            let delta = target_addr.wrapping_sub(base_addr) as i64;
            Ok(if let Some(mut relocated) = Self::relocate(o, &base, delta, accesses, inputs, calculation)? {
                if relocated.memory.iter().any(|(addr, _, _)| addr / ps == page_index) {
                    // We cannot double-map the page
                    return Ok(CheckSizeResult::Failed);
                }

                // Map the page on which the access is occurring
                relocated.memory.push(page_start, Permissions::ReadWrite, vec![ 0 ]);

                debug!("Final state that we're observing: {:?}", relocated);

                match o.observe(&relocated) {
                    // Memory access at the end of the page, the memory is bigger
                    Err(OracleError::MemoryAccess(addr)) if addr == expected_access => CheckSizeResult::Increase,
    
                    // No memory error, we must have reached the max
                    Ok(_) | Err(OracleError::ComputationError) | Err(OracleError::MemoryAccess(_)) => CheckSizeResult::Ok,

                    // May be alignment instead of negative memory, so we can't return Ok/Increase
                    Err(OracleError::GeneralFault) => CheckSizeResult::Failed,
    
                    Err(err) => {
                        // TODO: Handle alignment?
                        error!("Unexpected oracle error: {}", err);
                        CheckSizeResult::Impossible
                    }
                }
            } else {
                CheckSizeResult::Failed
            })
        } else {
            Ok(CheckSizeResult::Impossible)
        }
    }

    fn is_written<A: Arch + 'static, O: Oracle<A>>(o: &mut O, bases: &[(SystemState<A>, u64)], inputs: &Inputs<A>, calculation: &BasicComputation) -> Result<bool, ConstraintAnalysisError<A>> {
        let mut num_write_observations = 0;
        for (base, addr) in bases.iter().filter(|(_, addr)| o.can_map(*addr)).collect::<Vec<_>>() {
            let reference_addr = calculation.compute(&inputs, &base);
            if reference_addr == *addr {
                let mut state = base.clone();
                state.memory.push(reference_addr, Permissions::Read, vec![ 0 ]);
    
                let after = o.observe(&state);
                match after {
                    Ok(_)
                    | Err(OracleError::ComputationError)
                    | Err(OracleError::GeneralFault) => return Ok(false),
                    | Err(OracleError::MemoryAccess(addr)) if addr == reference_addr => {
                        num_write_observations += 1;
                        if num_write_observations > 50 {
                            return Ok(true);
                        }
                    },
                    _ => return Ok(false),
                }
            }
        }

        Ok(true)
    }

    fn infer_alignment<A: Arch + 'static, O: Oracle<A>>(o: &mut O, inputs: &Inputs<A>, calculation: &BasicComputation, bases: &[(SystemState<A>, u64)], unaddressable: &[SystemState<A>]) -> usize {
        let mut alignments_ok: u128 = 0;
        let mut alignments_nok: u128 = 0;

        for (_, addr) in bases.iter() {
            let alignment = addr.trailing_zeros();
            alignments_ok |= 1 << alignment;
        }

        for base in unaddressable.iter() {
            let addr = calculation.compute(&inputs, base);

            if o.can_map(addr) {
                let alignment = addr.trailing_zeros();
                alignments_nok |= 1 << alignment;
            }
        }

        // Handle cases where we might not be able to observe all addresses.
        // For example, if the computation is x*2+20 we will never see (alignments_ok & 0b1) == 1.
        if inputs.len() == 1 && calculation.offset % calculation.scale as i64 == 0 {
            let minimum_forced_alignment = calculation.scale.trailing_zeros();
            let mask = (1u128 << (minimum_forced_alignment + 1)) - 1;
            debug!("Extending alignment_nok with: {:08b}", mask & 0xff);
            alignments_nok |= mask;
        }

        debug!("alignment  ok: {:08b}", alignments_ok & 0xff);
        debug!("alignment nok: {:08b}", alignments_nok & 0xff);

        match (alignments_ok & 0xff, alignments_nok & 0xff) {
            (0b11111110, 0b00000001) => 2,
            (0b11111100, 0b00000011) => 4,
            (0b11111000, 0b00000111) => 8,
            (0b11110000, 0b00001111) => 16,
            (0b11100000, 0b00011111) => 32,
            (0b11000000, 0b00111111) => 64,
            (0b10000000, 0b01111111) => 128,
            _ => 1,
        }
    }

    pub fn infer_quick<A: Arch + 'static, O: Oracle<A>>(o: &mut O, instr: Instr<'_>) -> Result<Option<MemoryAccesses<A, BasicComputation>>, ConstraintAnalysisError<A>> {
        let ps = o.page_size();
        let mut rng = rand::thread_rng();
        let mut accesses: MemoryAccesses<A, BasicComputation> = MemoryAccesses {
            instr: instr.into(),
            memory: vec! [
                MemoryAccess {
                    inputs: Inputs::sorted(vec! [ Source::Dest(Dest::Reg(A::Reg::pc(), Size::qword())) ]),
                    kind: AccessKind::Executable,
                    size: instr.byte_len()..instr.byte_len(),
                    calculation: Some(BasicComputation::unscaled_sum()),
                    alignment: 1,
                }
            ],
        };

        let mut may_error = false;

        // First we use page faults to find most (if not all) memory accesses, because page faults are relatively fast
        loop {
            info!("Generating bases...");
            info!("Accesses: {}", accesses);

            let mut base_gen = BaseGenerator::new(o, &accesses, &mut rng);
            base_gen.gen()?;
            let bases = base_gen.bases;
            let unaddressable = base_gen.unaddressable;
            info!("{} bases generated, {} ok, {} ignored", bases.len(), base_gen.oks, base_gen.ignored);

            if base_gen.instr_is_emulated {
                return Err(ConstraintAnalysisError::InstructionIsEmulated);
            } else if bases.len() <= 0 {
                if base_gen.oks >= 1_000 && base_gen.ignored <= 0 {
                    break;
                } else {
                    // We do not need to fall back to the slow algorithm here, because it will never work.
                    // We found 0 input states.
                    // If we ignored at least 1 state:
                        // We ignored it because it was a memory access, so we haven't been able to find all memory accesses.
                        // Yet, we are also unable to find good inputs via randomization that allow us to learn this memory access.
                        // The slow algorithm needs every memory access on a separate page. 
                        // It will terminate after finding 500 consecutive accesses on an already mapped page.
                        // We just tried 5_000 times to find good random input states, and didn't find any.
                        // So the slow algorithm will always* produce an error in this case.
                        // (* = assuming 5000 random cases is enough to cover the full input space)
                    // If we ignored no states:
                        // We were not able to generate any satisfactory randomized state.
                        // If we're not able to do that here, the slow algorithm will also not be able to do it.
                        // Therefore we can immediately produce an error here.
                    error!("Unable to generate useful random inputs: {} bases generated, {} ignored; Accesses: {:X?}", base_gen.oks, base_gen.ignored, accesses);
                    return Err(ConstraintAnalysisError::Randomization(RandomizationError::Unsatisfiable(if base_gen.ignored <= 0 && unaddressable.len() <= 0 {
                        // In this case we were not able to generate any state, so we were not able to see any memory access.
                        // We have an unsatisfiable state because of the last memory access, not a new one.
                        accesses.len() - 1
                    } else {
                        accesses.len()
                    })));
                }
            } else {
                info!("Memory access found");
                for (base, addr) in bases.iter().take(3) {
                    info!("EXAMPLE -- accesses 0x{:X}: {:X?}", addr, base);
                }

                let (inputs, calculation) = if let Some(result) = Self::find_calculation(ps, &bases) {
                    result
                } else {
                    error!("Could not find a good calculation for new access after {:?}, instruction {:02X?}", accesses, instr.bytes());
                    if may_error {
                        return Err(ConstraintAnalysisError::Randomization(RandomizationError::Unsatisfiable(accesses.len())));
                    } else {
                        return Ok(None);
                    }
                };

                let alignment = Self::infer_alignment(o, &inputs, &calculation, &bases, &unaddressable);
                info!("Alignment: {}", alignment);

                if accesses.memory.iter()
                    .any(|access| access.inputs == inputs && access.calculation.as_ref()
                        .unwrap()
                        .constant_offset_with(&calculation)
                        .map(|x| x.abs() < ps as i64)
                        .unwrap_or(false)) {
                    // We will always map two memory accesses on the same page, so the slow algorithm will always fail.
                    may_error = true;
                }

                let max_limit = accesses.memory.iter()
                    .filter(|access| access.inputs == inputs)
                    .flat_map(|access| calculation.constant_offset_with(&access.calculation.as_ref().unwrap()))
                    .filter(|&n| n > 0)
                    .min()
                    .unwrap_or(256)
                    .min(256) as u64;

                info!("Size limit is {}", max_limit);

                let (min_size, max_size) = if inputs.len() == 1 && calculation.scaled_index == 0 && calculation.scale != 1 {
                    // We cannot increment / decrement the memory access in single-byte increments
                    info!("The only available input has a scale factor");
                    (1, max_limit)
                } else {
                    let mut num_fails = 0;
                    let mut max_size = 1;
                    let mut min_size = 1;
                    loop {
                        let result = Self::check_size(&mut rng, o, &accesses, &inputs, &calculation, SizeKind::After(max_size))?;
                        debug!("Size check result: {:?}", result);
                        match result {
                            CheckSizeResult::Impossible => {
                                max_size = max_limit;
                                break;
                            }
                            CheckSizeResult::Failed => {
                                // Try again
                                num_fails += 1;
                                if num_fails >= 100 {
                                    num_fails = 0;
                                    max_size += 1;

                                    if max_size >= max_limit {
                                        // We will determine the actual size during careful observation
                                        break;
                                    }
                                }
                            }
                            CheckSizeResult::Increase => {
                                num_fails = 0;
                                max_size += 1;
                                min_size = max_size;
                            },
                            CheckSizeResult::Ok => break,
                        }
                    }

                    (min_size, max_size)
                };

                let access = MemoryAccess {
                    kind: if Self::is_written(o, &bases, &inputs, &calculation)? {
                        AccessKind::InputOutput
                    } else {
                        AccessKind::Input
                    },
                    inputs,
                    size: min_size as usize..max_size as usize,
                    calculation: Some(calculation),
                    alignment,
                };

                info!("New access added: {:?}", access);
                accesses.memory.push(access);
            }
        }

        info!("Accesses for careful checks: {:#X?}", accesses);

        // TODO: What if we're reading around RIP
        if accesses.len() <= 1 {
            return Ok(Some(accesses));
        }

        // Now, we use careful observations to make sure we did not miss any memory accesses.
        // NOTE: We have already found all memory accesses with independent variables. (i.e., they use at least 1 different register)
        // Therefore, every memory access that we find here can be computed by adding a static offset to one of the other memory accesses.
        let mut oks = 0;
        let mut n = 0;
        loop {
            info!("Doing careful checks for {:02X?} (oks={})", accesses.instr.bytes(), oks);
            let mut base = if let Ok(result) = StateGen::randomize_new(&accesses, &mut rng, o) {
                result
            } else {
                continue;
            };

            n += 1;
            if n > 5000 {
                error!("Unable to perform careful checks for {:02X?}", accesses.instr.bytes());
                return Ok(None);
            }
            
            let base_result = o.observe(&base);
            trace!("Base with result {:X?}: {:X?}", base_result, base);

            for (access, (_, _, data)) in accesses.memory.iter().zip(base.memory.data.iter_mut()) {
                data.resize(data.len().min(access.size.start), 0);
            }

            trace!("Resized memory to: {:X?}", base);

            // We don't expect memory accesses here, since we should have identified all memory accesses that we can observe with page faults!
            // randomize_new always produces a state where all pages are mappable
            if let Err(OracleError::MemoryAccess(_)) = base_result {
                panic!("This memory access should have been caught in the loop above");
            } else if let Err(OracleError::GeneralFault) = base_result {
                // This memory access might be caused by an alignment, so we cannot panic here. 
                // If it is impossible to generate valid states, we would have returned an error already.
                // Therefore, we can just retry until we eventually get an OK state.
                continue;
            };

            let mut found = o.scan_unspecified_memory_accesses(&base)?;
            found.sort();
            debug!("Found: {:X?}", found);
            if found.len() <= 0 {
                oks += 1;
                if oks >= 5 {
                    for access in accesses.memory.iter_mut() {
                        access.size.end = access.size.start;
                    }

                    break;
                }
            } else {
                oks = 0;
                'outer: for &addr in found.iter() {
                    for (access, (mapped_addr, _, _)) in accesses.memory.iter_mut().zip(base.memory.iter()) {
                        if addr == mapped_addr + access.size.start as u64 {
                            access.size.start += 1;
                            access.size.end = access.size.start.max(access.size.end);

                            continue 'outer;
                        }
                    }

                    // We found a new memory access that will always overlap with another access on the same page.
                    // The slow algorithm requires that each memory access can be placed on a different page.
                    // Therefore, we can safely fail here.
                    // TODO: Handle multiple memory accesses on the same page; Note that we can just assume the size = 1 here, and then use the same mechanism to expand.
                    error!("New memory access that we cannot map: {:X?} {:X?}", addr, base);
                    return Err(ConstraintAnalysisError::Randomization(RandomizationError::Unsatisfiable(accesses.len())));
                }
            }
        }

        Ok(Some(accesses))
    }

    pub fn infer<A: Arch + 'static, O: Oracle<A>>(o: &mut O, instr: Instr<'_>) -> Result<MemoryAccesses<A, BasicComputation>, ConstraintAnalysisError<A>> {
        if let Some(r) = Self::infer_quick(o, instr)? {
            return Ok(r);
        }

        warn!("Running slow memory access inference...");
        Self::infer_slow(o, instr)
    }

    pub fn infer_slow<A: Arch + 'static, O: Oracle<A>>(o: &mut O, instr: Instr<'_>) -> Result<MemoryAccesses<A, BasicComputation>, ConstraintAnalysisError<A>> {
        let mut rng = rand::thread_rng();
        let ps = o.page_size();
        let mut constraints: MemoryAccesses<A, BasicComputation> = MemoryAccesses {
            instr: instr.into(),
            memory: vec! [
                MemoryAccess {
                    inputs: Inputs::sorted(vec! [ Source::Dest(Dest::Reg(A::Reg::pc(), Size::qword())) ]),
                    kind: AccessKind::Executable,
                    size: instr.byte_len()..instr.byte_len(),
                    calculation: None,
                    alignment: 1,
                }
            ],
        };

        let mut tries = 0;
        let mut oks = 0;
        let mut total_oks = 0;
        let mut memory_errors = 0;
        let mut false_memory_accesses = 0;
        let mut computation_errors = 0;
        loop {
            debug!("Current constraints (tries={}, oks={}, memory errors={}, false accesses={}): {:X?}", tries, oks, memory_errors, false_memory_accesses, constraints);
            let state = StateGen::randomize_new(&constraints, &mut rng, &mut CarefulOracle::new(o))?;
            debug!("Testing: {:X?}", state);

            tries += 1;
            if tries >= 1_000 || memory_errors >= 500 || false_memory_accesses >= 500 || (tries >= 100 && total_oks <= 0) {
                if memory_errors >= tries * 8 / 10 {
                    // At least 80% are memory errors
                    return Err(ConstraintAnalysisError::UnaccessibleMemoryAccess(constraints.memory.len()));
                } else {
                    return Err(ConstraintAnalysisError::InstructionKeepsFaulting);
                }
            }
            
            let result = o.observe_carefully(&state);
            trace!("Execution result = {:X?}", result);
            if result.is_ok() {
                oks += 1;
                total_oks += 1;
                false_memory_accesses = 0;
            } else {
                match result {
                    // Don't reset oks when we encounter a computation error
                    // We will likely encounter a computation error somewhat regularly, because they occur depending on the input.
                    // For example, if the computation error occurs on a divide by zero, we might get one every ~100 observations.
                    // We just increase the number of oks we need a bit to compensate
                    Err(OracleError::ComputationError) => computation_errors += 1,
                    _ => oks = 0,
                }
            }

            debug!("oks={}, computation_errors={}, memory_errors={}", oks, computation_errors, memory_errors);

            match result {
                Ok(_) => if oks > 10 + computation_errors / 2 { break },
                Err(OracleError::GeneralFault) => { memory_errors += 1; warn!("UnadressableMemory with input {:#?}", state) },
                Err(OracleError::ComputationError) => { warn!("ComputationError with input (oks={}, computation_errors={}) {:#?}", oks, computation_errors, state) },
                Err(OracleError::MemoryAccess(addr)) if state.memory.iter().any(|(other_addr, _, _)| *other_addr == addr) => {
                    let prev = state.memory.iter().enumerate()
                        .filter(|(_, (other_addr, _, _))| *other_addr == addr)
                        .next()
                        .unwrap()
                        .0;
                    let constraint = &mut constraints.memory[prev];

                    match constraint.kind {
                        AccessKind::Input => {
                            constraint.kind = AccessKind::InputOutput;
                        }
                        AccessKind::InputOutput => {
                            error!("Still can't write to an already-writable memory region? (constraint: {:X?}, addr = {:X})", constraint, addr);
                            return Err(ConstraintAnalysisError::MemoryErrorOnWritableRegion);
                        }
                        AccessKind::Executable => {
                            // TODO: What do we do here?
                        }
                    }
                },
                Err(OracleError::MemoryAccess(reference_addr)) if !state.memory.iter().any(|(other_addr, _, _)| other_addr / ps == reference_addr / ps) => {
                    // TODO: What if the memory access is actually occurring on the executable page?
                    info!("Found new memory access at {:X} with inputs: {:X?}", reference_addr, state);
                    let bases = (0..1024).map(|_| {
                        let base = if let Ok(result) = StateGen::randomize_new(&constraints, &mut rng, o) {
                            result
                        } else { return None };
                        let base_result = o.observe(&base);

                        if let Err(OracleError::MemoryAccess(addr)) = base_result {
                            Some((base, addr))
                        } else {
                            None
                        }
                    }).flatten().collect::<Vec<_>>();

                    info!("Determining inputs...");
                    let locations: Vec<Location<A>> = A::Reg::iter()
                        .map(|reg| Location::Reg(reg))
                        .chain(constraints.memory.iter().enumerate().filter(|(_, c)| c.kind != AccessKind::Executable).map(|(index, _)| Location::Memory(index)))
                        .chain(A::Flag::iter().map(|flag| Location::Flag(flag)))
                        .collect::<Vec<_>>();
                    let mut fast_inputs = HashSet::new();
                    let mut not_input_locations = locations.clone();
                    let mut num_errors = 0;
                    for (base_in, base_addr) in bases.iter() {
                        for _ in 0..10 {
                            if let Some(r) = ModifySingleLocationIter::new(&constraints, &mut rng, o, base_in.clone(), &not_input_locations).next() {
                                match r {
                                    Ok((_new_in, new_out)) => {
                                        match new_out {
                                            Err(OracleError::MemoryAccess(new_addr)) if base_addr != &new_addr => {
                                                Self::find_input(&constraints, o, &mut rng, base_in, &not_input_locations, &mut fast_inputs, &|_o, new_in, new_out| {
                                                    // Special condition: if we map over the region that we were originally getting a memory error from, obviously the error is going to change. 
                                                    // Example:
                                                    // Original: (1000, A), (F805, B) gives MemoryAccess(9050)
                                                    // If we now change this to (9000, A), (F805, B), obviously the memory access error changes, but that has nothing to do with the register we modified. It has to do with the fact that we've now just double-mapped two memory accesses on the same memory page.
                                                    // Here, we make sure that in such cases we return that there has been no change.
                                                    if new_in.memory.data.iter().any(|m| m.0 / ps == base_addr / ps) {
                                                        return Ok(false);
                                                    }

                                                    match &new_out {
                                                        Err(OracleError::MemoryAccess(addr)) if addr != base_addr => {
                                                            // The exact opposite as above: when we originally mapped two memory accesses to the same page and just remapped that specific page causing us to see a difference
                                                            if base_in.memory.data.iter().any(|m| m.0 / ps == new_addr / ps) {
                                                                return Ok(false);
                                                            }

                                                            info!("Found input for memory #{} because of difference between {:X?} and {:X?}; Accessed memory addresses: {:X?} vs {:X?}", constraints.memory.len(), base_in, new_in, base_addr, addr);

                                                            Ok(true)
                                                        },
                                                        Ok(_) | Err(OracleError::GeneralFault) => Ok(true),
                                                        _ => Ok(false),
                                                    }
                                                }).map_err(|e| ConstraintAnalysisError::FindInputFailed(constraints.memory.len(), e))?;
                                                not_input_locations.retain(|loc| !fast_inputs.contains(loc));
                                            },
                                            _ => {},
                                        }
                                    },
                                    Err(e) => {
                                        debug!("Error (total seen={}) when randomizing values: {}", num_errors, e);
                                        num_errors += 1;

                                        // Abort if errors occur for more than 5% of the bases
                                        if num_errors > bases.len() / 20 {
                                            warn!("Terminating because more than 5% of the bases gives an error: {}/{}", num_errors, bases.len());
                                            Err(e)?;
                                        }

                                        break;
                                    }
                                }
                            }
                        }
                    }

                    let addr_inputs = fast_inputs;
                    
                    info!("Found new memory access via {:?}", addr_inputs);

                    const MIN_SIZE: usize = 1;
                    const MAX_SIZE: usize = 128;
                    // TODO: Find a more efficient way to determine the memory size
                    // TODO: Reference address might be unaddressable
                    info!("Determining memory size with reference address {:016X}", reference_addr);
                    let mem_size = if locations.len() == 0 {
                        // TODO: We can be slightly more precise if the fixed address is located at the end of a page
                        MIN_SIZE..MAX_SIZE
                    } else {
                        // TODO: Detect the common case where one of the inputs, say input I, is used as follows: addr = (...) + I. In this case, we can detect the memory size with just a few observations (log2(64) = 6, to be exact).
                        convert(bases.iter().map(|x| Ok(x)))
                        .map(|(base, _)| {
                            // TODO: Choose modified locations smartly, reducing the amount of enumeration we need to do here
                            // TODO: Choose the input with a linear relationship and just use that as a base
                            convert(ModifySingleLocationIter::new(&constraints, &mut rng, o, base.clone(), &locations)
                                .take(100)
                                // TODO: Resolve oracle issue, don't collect into a Vec here
                                .collect::<Vec<_>>()
                                .into_iter())
                                .map(|(new_state, output_state)| match &output_state {
                                    Err(OracleError::MemoryAccess(new_addr)) if o.can_map(*new_addr) => {
                                        let page_addr = (new_addr / ps) * ps;
                                        let addr_clearing_low = (new_addr.checked_sub(MAX_SIZE as u64).unwrap_or(0) / ps) * ps;
                                        let addr_clearing_high = ((new_addr + MAX_SIZE as u64) / ps + 1) * ps;
                                        let dist = page_addr + ps - new_addr;

                                        if dist < MAX_SIZE as u64  && !new_state.memory.data.iter().any(|(addr, _, _)| {
                                            *addr >= addr_clearing_low && *addr <= addr_clearing_high
                                        }) {
                                            let size_check_state = SystemState::new(new_state.cpu.clone(), {
                                                let mut m = new_state.memory.clone();
                                                m.push(*new_addr, Permissions::ReadWrite, vec! [ 0 ]);
                                                m
                                            });

                                            let output = o.observe(&size_check_state);
                                            let constraint = match output {
                                                // If we're accessing the page bound exactly, we are doing some kind of read that's now partially overlapping two pages
                                                Err(OracleError::MemoryAccess(new_addr)) if new_addr == page_addr + ps => Some(dist as usize+1..MAX_SIZE),
                                                // If we see an unrelated memory access, we have an upper bound
                                                Err(OracleError::MemoryAccess(new_addr)) if new_addr < page_addr || new_addr > page_addr + ps + MAX_SIZE as u64 => Some(MIN_SIZE..dist as usize),
                                                // If we no longer see a memory access, we also have an upper bound
                                                Ok(_) => Some(MIN_SIZE..dist as usize),
                                                // We assume that if we see a computation error, the instruction must have performed all its memory accesses already
                                                Err(OracleError::ComputationError) => Some(MIN_SIZE..dist as usize),
                                                _ => None,
                                            };

                                            Ok(constraint)
                                        } else {
                                            Ok(None)
                                        }
                                    },
                                    _ => Ok(None),
                                })
                                .distill_fallible(MIN_SIZE..MAX_SIZE)
                        })
                        .distill_fallible(MIN_SIZE..MAX_SIZE)?
                    };

                    let mem_size = if mem_size.start > mem_size.end {
                        mem_size.end..mem_size.end
                    } else {
                        mem_size
                    };

                    info!("Mem size for inputs {:?} is {:?}", addr_inputs, mem_size);

                    constraints.memory.push(MemoryAccess::<A, BasicComputation> {
                        kind: AccessKind::Input,
                        inputs: Inputs::sorted(addr_inputs.into_iter().map(|i| i.into_source_with_size(Size::qword())).collect::<Vec<_>>()),
                        size: mem_size,
                        calculation: None,
                        alignment: 1,
                    });
                }
                Err(OracleError::MemoryAccess(_)) => {
                    // We thought we found a memory access, but it was actually mapped onto a page we had already mapped. We can't be
                    // sure that this is actually a 'true' memory access, so let's hope we encounter it again in one of the next iterations we do.
                    warn!("We found a memory access, but it ended up being on an already mapped page");
                    false_memory_accesses += 1;
                }
                Err(OracleError::InvalidInstruction) => {
                    return Err(ConstraintAnalysisError::InvalidInstruction);
                }
                Err(e) => panic!("Unexpected error: {:#X?}", e),
            }
        }

        let bases = (0..1024).map(|_| -> Result<_, RandomizationError> {
            let base = StateGen::randomize_new(&constraints, &mut rng, o)?;
            Ok(base)
        })
        .collect::<Result<Vec<_>, _>>()?;
        
        info!("Checking phantom inputs...");
        // First input cannot be phantom inputs. 
        // The first input is the instruction address, which we know is located at RIP
        // We need at least 3 memory accesses, otherwise we would not have found any phantom accesses
        if constraints.memory.len() >= 2 {
            for index in 1..constraints.memory.len() {
                let inputs = constraints.memory[index].inputs.clone();
                for input in inputs.iter() {
                    info!("Checking access {} => {:?} for phantom inputs", index, input);
                    for base in bases.iter() {
                        let base_addr = base.memory.data[index].0;
                        let changes = ModifySingleLocationIter::new(&constraints, &mut rng, o, base.clone(), &[ input.try_into().unwrap() ])
                            .take(128)
                            .filter(|m| m.is_ok())
                            .any(|modified| modified.unwrap().0.memory.data[index].0 != base_addr);

                        if !changes {
                            warn!("Phantom input: {:?} for memory access {} {:?}", input, index, constraints.memory[index]);
                            constraints.memory[index].inputs.remove(input);

                            let base = StateGen::randomize_new(&constraints, &mut rng, o)?;
                            let mut new = base.clone();
                            new.memory.data[index].1 = Permissions::Read;

                            for _ in 0..10 {
                                let base_result = o.observe(&base);
                                let new_result = o.observe(&new);
                                match (base_result, new_result) {
                                    (Ok(_), Ok(_)) => {
                                        constraints.memory[index].kind = AccessKind::Input;
                                        break;
                                    }
                                    _ => {},
                                }
                            }

                            break;
                        }

                    }
                }
            }
        }

        info!("Attempting early synthesis of address computations");
        for index in 0..constraints.memory.len() {
            if constraints.memory[index].calculation.is_none() {
                constraints.memory[index].calculation = Self::try_infer_address_calculation(&bases, &constraints, index);
            }
        }

        info!("Checking for accesses incorrectly marked as outputs...");
        for index in 1..constraints.memory.len().checked_sub(1).unwrap_or(0) {
            if constraints.memory[index].kind == AccessKind::InputOutput {
                info!("Checking access {}", index);
                'outer: for base in bases.iter() {
                    let mut new = base.clone();
                    new.memory.data[index].1 = Permissions::Read;

                    let base_result = o.observe(&base);
                    if base_result.is_ok() {
                        let new_result = o.observe(&new);
                        if new_result.is_ok() {
                            constraints.memory[index].kind = AccessKind::Input;
                            break 'outer;
                        }
                    }
                }
            }
        }

        Ok(constraints)
    }

    fn try_infer_address_calculation<A: Arch>(bases: &[SystemState<A>], constraints: &MemoryAccesses<A, BasicComputation>, index: usize) -> Option<BasicComputation> {
        let base = &bases[0];
        let inputs = &constraints.memory[index].inputs;
        let mut possible_calculations = vec![ BasicComputation::new_with_inferred_offset(1, 0, inputs, &base, base.memory.data[index].0) ];
        for scale_index in 0..inputs.len() {
            for scale in [2, 4, 8].iter().copied() {
                possible_calculations.push(BasicComputation::new_with_inferred_offset(scale, scale_index, inputs, &base, base.memory.data[index].0));
            }
        }

        for base in bases.iter() {
            let addr = base.memory.data[index].0;
            possible_calculations.retain(|calculation| {
                calculation.compute(inputs, &base) == addr
            });
        }
        
        if possible_calculations.len() == 1 {
            info!("Found calculation {:?} for memory access address #{}: {}", possible_calculations[0], index, constraints.memory[index]);
            Some(possible_calculations[0])
        } else {
            None
        }
    }

    pub fn find_input<A: Arch + 'static, R: Rng, O: Oracle<A>>(accesses: &MemoryAccesses<A, BasicComputation>, o: &mut O, rng: &mut R, base_state: &SystemState<A>, locations: &[Location<A>], found: &mut HashSet<Location<A>>, has_change: &impl Fn(&mut O, &SystemState<A>, &Result<SystemState<A>, OracleError>) -> Result<bool, OracleError>) -> Result<(), FindInputError> {
        if locations.len() <= 0 {
            return Ok(());
        }
        
        if locations.len() == 1 {
            for _ in 0..200 {
                let new_in = StateGen::modify_locations(accesses, rng, o, base_state.clone(), &locations)?;
                let new_result = o.observe(&new_in);
                if has_change(o, &new_in, &new_result).map_err(|e| {
                    error!("has_change failed on new_in={:X?}, new_result={:X?}: {}", new_in, new_result, e);
                    FindInputError::HasInputFailed(e)
                })? {
                    debug!("{:?} is input because of new result: {:X?} on bases: {:X?} vs {:X?}", locations[0], new_result, base_state, new_in);
                    for _ in 0..50 {
                        let second_observation = o.observe(&new_in);
                        if second_observation.as_ref().ok() != new_result.as_ref().ok() {
                            warn!("This instruction uses external input that we cannot observe");
                            return Err(FindInputError::UnobservableExternalInputs);
                        }
                    }

                    found.insert(locations[0].clone());
                    return Ok(());
                }
            }
        } else {
            let split_size = (locations.len() / 2).max(1);
            let left = &locations[..split_size];
            let right = &locations[split_size..];

            for _ in 0..1000 {
                let left_is_input = convert(convert(ModifySingleLocationIter::new(&accesses, rng, o, base_state.clone(), &left))
                    .map_err(|e| FindInputError::RandomizationFailed(e))
                    .take(5).collect::<Vec<_>>()?.into_iter().map(|x| Ok(x)))
                    .any(|(new_in, new_result)| has_change(o, &new_in, &new_result).map_err(|e| {
                        warn!("has_change failed for left_is_input on new_in={:X?}, new_result={:X?}", new_in, new_result);
                        FindInputError::HasInputFailed(e)
                    }))?;
                let right_is_input = convert(convert(ModifySingleLocationIter::new(&accesses, rng, o, base_state.clone(), &right))
                    .map_err(|e| FindInputError::RandomizationFailed(e))
                    .take(5).collect::<Vec<_>>()?.into_iter().map(|x| Ok(x)))
                    .any(|(new_in, new_result)| has_change(o, &new_in, &new_result).map_err(|e| {
                        warn!("has_change failed for right_is_input  on new_in={:X?}, new_result={:X?}", new_in, new_result);
                        FindInputError::HasInputFailed(e)
                    }))?;

                if left_is_input {
                    Self::find_input(accesses, o, rng, base_state, left, found, has_change)?;
                }
                
                if right_is_input {
                    Self::find_input(accesses, o, rng, base_state, right, found, has_change)?;
                }

                if left_is_input || right_is_input {
                    return Ok(());
                }
            }

            warn!("Was not able to find an input even though we detected a change");
        }

        Ok(())
    }
}