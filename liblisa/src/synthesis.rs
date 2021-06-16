use std::collections::{HashMap, HashSet};
use std::error::Error;
use std::ops::Index;
use std::sync::atomic::{AtomicUsize, Ordering};
use liblisa_core::computation::BasicComputation;
use liblisa_core::encoding::PartValue;
use liblisa_core::{Dest, Encoding, FlowOutputLocation, FlowValueLocation, GetDest, Location, PartMapping, Source, randomized_value};
use liblisa_core::oracle::{Oracle, OracleError};
use liblisa_core::Computation;
use liblisa_core::arch::{Arch, InstructionInfo, Register, Value};
use liblisa_core::gen::{StateGen, RandomizationError, TryIntoBasicComputation}; 
use liblisa_enc::encoding::EncodingAnalysis;
use liblisa_synth::gen::{ArithOp, Const, Endianness, Expr, Input, InputMux, Operation, Sign};
use liblisa_synth::search::{DecisionTree, Id3, SynthesisTable};
use itertools::Itertools;
use liblisa_x64::{KmodPtraceOracle, X64Arch, x64_kmod_ptrace_oracle};
use log::trace;
use rand::Rng;
use serde::{Serialize, Deserialize};
use std::{fmt, iter};
use rayon::prelude::*;

use crate::OracleProvider;
use crate::enumeration::cleanup;
use crate::work::Worker;

pub fn preprocess_encodings<A: Arch + 'static, O: Oracle<A> + 'static>(fo: impl Fn() -> O + Sync, mut encodings: Vec<Encoding<A, BasicComputation>>) -> Vec<Encoding<A, BasicComputation>> {
    println!("Sorting {} encodings...", encodings.len());
    encodings.retain(|e| e.filters().len() > 0);
    encodings.sort_by_cached_key(|e| e.filters()[0].smallest_matching_instruction().bytes().to_vec());
    println!("Filtering overlapping encodings...");

    let mut encodings = cleanup(encodings);
    println!("Encodings remaining: {}", encodings.len());
    println!("Splitting flag outputs...");
    for encoding in encodings.iter_mut() {
        trace!("Splitting {}", encoding);
        encoding.split_flag_output();
    }

    for i in (0..encodings.len()).rev() {
        let encoding = &mut encodings[i];
        trace!("Trying to fix: {}", encoding);
        if !encoding.fix() {
            panic!("WARNING: Unable to fix: {}", encoding);
        }

        trace!("Fixed: {}", encoding);
        if !encoding.integrity_check() {
            panic!("WARNING: Integrity check failed: {}", encoding);
        }
    }

    let len = encodings.len();
    let processed = AtomicUsize::new(0);
    encodings.par_iter_mut().for_each(|encoding| {
        let before = format!("{}", encoding);
        let mut o = fo();
        if EncodingAnalysis::remove_incorrect_generalizations(&mut o, encoding) {
            println!("Removed incorrect generalizations from {}; New encoding: {}", before, encoding);
        }
        o.kill();

        let processed = processed.fetch_add(1, Ordering::SeqCst) + 1;
        if processed % 20 == 0 {
            println!("Removing incorrect generalizations: {} / {}", processed, len);
        }
    });

    encodings
}

pub fn extract_addr_output_groups(encodings: &Vec<Encoding<X64Arch, BasicComputation>>) -> Vec<OutputGroup> {
    println!("Extracting address computations...");
    let computations = encodings.iter().enumerate().flat_map(|(encoding_index, encoding)| {
        encoding.outputs().enumerate().filter(|(_, access)| access.memory_access && !access.has_computation).map(move |(output_index, output)| Output {
            encoding_index,
            output_index,
            num_inputs: output.num_inputs,
            fixed_instantiation_choices: encoding.find_best_reg_choices(true, |choices| {
                match encoding.instantiate(choices) {
                    Ok(dataflows) => {
                        // TODO: Try to pick non-overlapping sizes as well (if possible)

                        let dataflow = dataflows.iter_with_locations().nth(output_index).unwrap();
                        let others = dataflows.iter_with_locations().enumerate()
                            .filter(|(index, _)| *index != output_index)
                            .map(|(_, v)| v)
                            .collect::<Vec<_>>();
                        // Priority 1: Map all inputs to a different register
                        let registers = match dataflow.target() {
                            Some(Dest::Reg(reg, _)) => iter::once(Some(reg)),
                            _ => iter::once(None),
                        }.chain(dataflow.iter().map(|input| match input {
                            Source::Dest(Dest::Reg(reg, _)) => Some(reg),
                            _ => None,
                        })).flatten().collect::<Vec<_>>();
                        let registers_set = registers.iter().collect::<HashSet<_>>();

                        // Priority 2: Use registers that don't overlap with any other dataflow
                        let overlapping = others.iter().map(|flow| {
                            let s = match flow.target() {
                                Some(Dest::Reg(reg, _)) if registers_set.contains(&reg) => 1,
                                _ => 0,
                            };

                            s + dataflow.iter().filter(|input| match input {
                                Source::Dest(Dest::Reg(reg, _)) if registers_set.contains(&reg) => true,
                                _ => false,
                            }).count()
                        }).sum::<usize>();

                        (registers.len() - registers_set.len()) * 1_000 + overlapping
                    },
                    Err(_) => 999_999,
                }
            }).unwrap_or_else(|| encoding.parts.iter().map(|_| None).collect()),
        })
    }).sorted_by_key(|c| c.fixed_instantiation_choices.len()).collect::<Vec<_>>();
    println!("Extracted {} address computations...", computations.len());
    println!("Grouping computations by same number of inputs...");
    let mut computations_by_input_output_sizes = HashMap::new();
    for c in computations.into_iter() {
        let dc = c.with_encodings(&*encodings);
        computations_by_input_output_sizes.entry((dc.output_bit_size(), dc.input_bit_sizes().collect::<Vec<_>>())).or_insert(Vec::new()).push(c);
    }
    let mut computation_groups = computations_by_input_output_sizes.into_iter()
        .map(|((output_bit_size, input_sizes), v)| OutputGroup::new(v, &input_sizes, output_bit_size))
        .collect::<Vec<_>>();
    computation_groups.sort_by_key(|g| g.len() as i64 * -1);
    println!("Created {} groups", computation_groups.len());
    for (index, group) in computation_groups.iter().enumerate() {
        println!("============ Group {} ============", index);
        for computation in group.iter() {
            println!("Output {} (Chosen part values: {:?}) in", computation.output_index, computation.fixed_instantiation_choices);
            println!("{}", encodings[computation.encoding_index].instantiate_partially(&computation.fixed_instantiation_choices).unwrap());
        }
    }

    println!("Doing some initial splitting of the groups");
    const FACTOR: usize = 10;
    let len = computation_groups.len();
    let mut computation_group_groups = vec![ Vec::new(); 32 ];
    for (index, group) in computation_groups.into_iter().enumerate() {
        computation_group_groups[index % 32].push(group);
    }

    let remaining = AtomicUsize::new(len * FACTOR);
    computation_group_groups.par_iter_mut().for_each(|computation_groups| {
        let mut rng = rand::thread_rng();
        let mut oracle = x64_kmod_ptrace_oracle();
        let mut index = 0;
        let limit = computation_groups.len() * FACTOR;
        for n in 0..limit {
            let remaining = remaining.fetch_sub(1, Ordering::SeqCst);
            println!("Splitting iteration: {} / {} (remaining: {})", n, limit, remaining);

            if n % 1000 == 0 {
                oracle.restart();
            }

            let group = &mut computation_groups[index];
            if group.len() > 1 {
                let computation = &group[rng.gen_range(0, group.len())];
                let c = computation.with_encodings(&*encodings);
                println!("{}", c);

                // TODO: Re-infer memory accesses, and try to re-use address calculations if possible

                let inputs = c.input_bit_sizes().map(|size| randomized_value(&mut rng) & ((1 << size) - 1)).collect::<Vec<u64>>();
                match c.evaluate(&mut oracle, &inputs) {
                    Ok(_) => {
                        let mut additional_groups = group.split_differing(&*encodings, &mut oracle, &inputs, None);
                        if let Some(additional_groups) = &mut additional_groups {
                            println!("{} new groups", additional_groups.len());
                            computation_groups.append(additional_groups);
                        }
                    }
                    Err(_) => {},
                }
            }

            index += 1;
            if index >= computation_groups.len() {
                index = 0;
            }
        }

        oracle.kill();
    });

    let mut computation_groups = computation_group_groups.into_iter().flat_map(|x| x).collect::<Vec<_>>();
    computation_groups.sort_by_key(|g| g.len() as i64 * -1);
    println!("Group sizes: {:?}", computation_groups.iter().map(|g| g.len()).collect::<Vec<_>>());

    computation_groups
}

pub fn extract_dataflow_output_groups(encodings: &Vec<Encoding<X64Arch, BasicComputation>>, addr_computation_groups: Vec<OutputGroup>) -> (Vec<Encoding<X64Arch, DecisionTreeComputation>>, Vec<OutputGroup>) {
    println!("Number of encodings: {}", encodings.len());
    println!("Removing encodings without address computations...");
    let encodings = encodings.into_iter().enumerate().flat_map(|(encoding_index, e)| {
        let mut e: Encoding<_, DecisionTreeComputation> = e.map_computations(|inputs, computation| {
            Expr::new(
                inputs.iter().map(|input| Input {
                    sign: Sign::Unsigned,
                    endianness: Endianness::Big,
                    num_bits: input.size().unwrap().len() * 8,
                }).collect(),
                vec![ Const(computation.offset as i128), Const(computation.scale as i128) ],
                // Use all inputs + 1 const
                vec![ InputMux((1 << (inputs.len() + 2)) - 1) ],
                vec![
                    Operation::Arith(
                        ArithOp::new(
                            (0..inputs.len() + 1).map(|index| if index == computation.scaled_index {
                                1 << (((1 << index) | (2 << inputs.len())) - 1)
                            } else {
                                1 << ((1 << index) - 1)
                            }).fold(0, |acc, val| acc | val)
                        )
                    ),
                ],
            ).into()
        });

        // Insert address computations
        for (memory_index, _) in e.outputs().enumerate()
            .filter(|(_, o)| o.memory_access && !o.has_computation)
            .collect::<Vec<_>>() {
            let synthesized_computation = addr_computation_groups.iter()
                .find(|g| g.iter().any(|c| c.encoding_index == encoding_index && c.output_index == memory_index));
        
            if let Some(synthesized_computation) = synthesized_computation {
                e.set_computation(memory_index, (&synthesized_computation.table).into());
            } else {
                return None;
            }
        }

        Some(e)
    }).collect::<Vec<_>>();
    println!("Encodings remaining: {}", encodings.len());
    println!("Extracting computations...");
    let computations = encodings.iter().enumerate().flat_map(|(encoding_index, encoding)| {
        encoding.outputs().enumerate().filter(|(_, access)| !access.memory_access).map(move |(output_index, output)| Output {
            encoding_index,
            output_index,
            num_inputs: output.num_inputs,
            fixed_instantiation_choices: encoding.find_best_reg_choices(true, |choices| {
                match encoding.instantiate(choices) {
                    Ok(dataflows) => {
                        // TODO: Try to pick non-overlapping sizes as well (if possible)

                        let dataflow = dataflows.iter_with_locations().nth(output_index).unwrap();
                        let others = dataflows.iter_with_locations().enumerate()
                            .filter(|(index, _)| *index != output_index)
                            .map(|(_, v)| v)
                            .collect::<Vec<_>>();
                        // Priority 1: Map all inputs to a different register
                        let registers = match dataflow.target() {
                            Some(Dest::Reg(reg, _)) => iter::once(Some(reg)),
                            _ => iter::once(None),
                        }.chain(dataflow.iter().map(|input| match input {
                            Source::Dest(Dest::Reg(reg, _)) => Some(reg),
                            _ => None,
                        })).flatten().collect::<Vec<_>>();
                        let registers_set = registers.iter().collect::<HashSet<_>>();

                        // Priority 2: Use registers that don't overlap with any other dataflow
                        let overlapping = others.iter().map(|flow| {
                            let s = match flow.target() {
                                Some(Dest::Reg(reg, _)) if registers_set.contains(&reg) => 1,
                                _ => 0,
                            };

                            s + dataflow.iter().filter(|input| match input {
                                Source::Dest(Dest::Reg(reg, _)) if registers_set.contains(&reg) => true,
                                _ => false,
                            }).count()
                        }).sum::<usize>();

                        (registers.len() - registers_set.len()) * 1_000 + overlapping
                    },
                    Err(_) => 999_999,
                }
            }).unwrap_or_else(|| encoding.parts.iter().map(|_| None).collect()),
        })
    }).sorted_by_key(|c| c.fixed_instantiation_choices.len()).collect::<Vec<_>>();
    println!("Extracted {} computations...", computations.len());
    println!("Grouping computations by same number of inputs...");
    let mut computations_by_input_output_sizes = HashMap::new();
    for c in computations.into_iter() {
        let dc = c.with_encodings(&encodings);
        computations_by_input_output_sizes.entry((dc.output_bit_size(), dc.input_bit_sizes().collect::<Vec<_>>())).or_insert(Vec::new()).push(c);
    }
    let mut computation_groups = computations_by_input_output_sizes.into_iter()
        .map(|((output_bit_size, input_sizes), v)| OutputGroup::new(v, &input_sizes, output_bit_size))
        .collect::<Vec<_>>();
    println!("Created {} groups", computation_groups.len());
    for (index, group) in computation_groups.iter().enumerate() {
        println!("============ Group {} ============", index);
        for computation in group.iter() {
            println!("Output {} (Chosen part values: {:?}) in", computation.output_index, computation.fixed_instantiation_choices);
            println!("{}", encodings[computation.encoding_index].instantiate_partially(&computation.fixed_instantiation_choices).unwrap());
        }
    }
    println!("Doing some initial splitting of the groups");
    let mut rng = rand::thread_rng();
    let mut oracle = x64_kmod_ptrace_oracle();
    let mut index = 0;
    let limit = computation_groups.len() * 50_000;
    for n in 0..limit {
        if n % 10_000 == 0 {
            println!("Splitting iteration: {} / {}", n, limit);
        }

        let group = &mut computation_groups[index];
        if group.len() > 1 {
            let computation = &group[rng.gen_range(0, group.len())];
            let c = computation.with_encodings(&encodings);

            let inputs = c.input_bit_sizes().map(|size| randomized_value(&mut rng) & ((1 << size) - 1)).collect::<Vec<u64>>();
            match c.evaluate(&mut oracle, &inputs) {
                Ok(_) => {
                    let mut additional_groups = group.split_differing(&encodings, &mut oracle, &inputs, None);
                    if let Some(additional_groups) = &mut additional_groups {
                        println!("{} new groups", additional_groups.len());
                        computation_groups.append(additional_groups);
                    }
                }
                Err(_) => {},
            }
        }

        index += 1;
        if index >= computation_groups.len() {
            index = 0;
        }
    }
    computation_groups.sort_by_key(|g| g.len() as i64 * -1);
    println!("Group sizes: {:?}", computation_groups.iter().map(|g| g.len()).collect::<Vec<_>>());
    (encodings, computation_groups)
}

pub fn extract_semantics(partial: bool, encodings: Vec<Encoding<X64Arch, DecisionTreeComputation>>, dataflow_computation_groups: Vec<OutputGroup>) -> Vec<Encoding<X64Arch, DecisionTreeComputation>> {
    encodings.into_iter()
        .enumerate()
        .flat_map(|(encoding_index, mut e)| {
        for (output_index, _) in e.outputs().enumerate()
            .filter(|(_, o)| !o.has_computation)
            .collect::<Vec<_>>() {
            let synthesized_computation = dataflow_computation_groups.iter()
                .find(|g| g.iter().any(|c| c.encoding_index == encoding_index && c.output_index == output_index));
            
            if let Some(synthesized_computation) = synthesized_computation {
                e.set_computation(output_index, (&synthesized_computation.table).into());
            } else {
                if !partial {
                    panic!("Missing computation: output #{} of: {}", output_index, e);
                }

                return None;
            }
        }

        Some(e)
    }).collect::<Vec<_>>()
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DecisionTreeComputation {
    choices: Vec<Expr>,
    decision_tree: DecisionTree,
}

impl From<Expr> for DecisionTreeComputation {
    fn from(e: Expr) -> Self {
        DecisionTreeComputation {
            choices: vec![
                e,
            ],
            decision_tree: DecisionTree {
                predicates: vec![],
                tree: Id3::empty(0),
            },
        }
    }
}

impl From<&SynthesisTable> for DecisionTreeComputation {
    fn from(st: &SynthesisTable) -> Self {
        DecisionTreeComputation {
            choices: st.choices.iter().map(|c| c.expr.clone()).collect(),
            decision_tree: st.decision_tree.as_ref().unwrap().clone(),
        }
    }
}

impl Computation for DecisionTreeComputation {
    type D = String;

    fn display<'a, S: AsRef<str>>(&self, input_names: &[S]) -> Self::D {
        let exprs = self.choices.iter().map(|c| format!("{}", c.display_with_names(input_names))).collect::<Vec<_>>();
        let attributes = self.decision_tree.predicates.iter().map(|p| format!("{}", p.display_with_names(input_names))).collect::<Vec<_>>();

        format!("{}", self.decision_tree.tree.display(&attributes, &exprs))
    }

    fn evaluate(&self, inputs: &[u64]) -> u64 {
        let choice = self.decision_tree.tree.decide(|predicate_index| {
            self.decision_tree.predicates[predicate_index].evaluate(&inputs) == 0
        });

        self.choices[choice].evaluate(inputs) as u64
    }
}

impl TryIntoBasicComputation for DecisionTreeComputation {
    fn basic(&self) -> Option<&BasicComputation> {
        None
    }
}

impl fmt::Display for DecisionTreeComputation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let exprs = self.choices.iter().map(|c| format!("{}", c.display())).collect::<Vec<_>>();
        let attributes = self.decision_tree.predicates.iter().map(|p| format!("{}", p.display())).collect::<Vec<_>>();

        write!(f, "{}", self.decision_tree.tree.display(&attributes, &exprs))
    }
}


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SynthesisBase<A: Arch, C: Computation> {
    pub encodings: Vec<Encoding<A, C>>,
    pub computation_groups: Vec<OutputGroup>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Output {
    pub encoding_index: usize,
    pub output_index: usize,
    pub num_inputs: usize,
    pub fixed_instantiation_choices: Vec<Option<u64>>,
}

pub struct DecoratedOutput<'a, A: Arch, C: Computation> {
    computation: &'a Output,
    encoding: Encoding<A, C>,
}

impl<'a, A: Arch + 'static, C: Computation> fmt::Display for DecoratedOutput<'a, A, C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Output #{} of {}", self.computation.output_index, self.encoding)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutputGroup {
    computations: Vec<Output>,
    output_size: usize,
    #[serde(default)]
    pub failed: bool,
    pub table: SynthesisTable,
}

impl OutputGroup {
    pub fn new(computations: Vec<Output>, input_sizes: &[usize], output_size: usize) -> OutputGroup {
        assert!(computations.len() > 0);
        OutputGroup {
            computations,
            output_size,
            failed: false,
            table: SynthesisTable::new(input_sizes, output_size),
        }
    }

    pub fn given_up(&self) -> bool {
        self.failed
    }

    pub fn len(&self) -> usize {
        self.computations.len()
    }

    pub fn iter(&self) -> impl Iterator<Item = &Output> {
        self.computations.iter()
    }

    pub fn split_differing<A: Arch + 'static, O: Oracle<A>, C: Computation + TryIntoBasicComputation>(&mut self, encodings: &[Encoding<A, C>], o: &mut O, inputs: &[u64], expected_output: Option<Option<u64>>) -> Option<Vec<OutputGroup>> {
        if self.len() > 1 {
            let mut new_groups = Vec::new();
            let mut mapping = HashMap::new();
            for computation in self.computations.drain(0..) {
                let result = computation.with_encodings(&encodings).evaluate(o, &inputs);
                mapping.entry(result.ok()).or_insert(Vec::new()).push(computation);
            }

            if let Some(expected_output) = expected_output {
                if mapping.len() <= 1 && !mapping.keys().any(|k| k == &expected_output) {
                    self.computations = mapping.drain().next().unwrap().1;
                    return Some(Vec::new());
                }
            }

            // Grab the biggest set for this computation group, the rest for new groups
            let mut drain = mapping.drain()
                .map(|(_, c)| c)
                .sorted_by_key(|c| c.len() as i64 * -1);
            self.computations = drain.next().unwrap();
            assert!(self.computations.len() > 0);

            for value in drain {
                new_groups.push(OutputGroup::new(value, self.table.input_sizes(), self.output_size));
            }

            if new_groups.len() <= 0 {
                None
            } else {
                Some(new_groups)
            }
        } else {
            None
        }
    }
}

impl Index<usize> for OutputGroup {
    type Output = Output;

    fn index(&self, index: usize) -> &Self::Output {
        &self.computations[index]
    }
}

impl Output {
    pub fn with_encodings<'a, A: Arch + 'static, C: Computation>(&'a self, encodings: &'a [Encoding<A, C>]) -> DecoratedOutput<'a, A, C> {
        let encoding = encodings[self.encoding_index].instantiate_partially(&self.fixed_instantiation_choices).unwrap();
        DecoratedOutput {
            computation: self,
            encoding,
        }
    }
}

#[derive(thiserror::Error, Debug)]
pub enum EvaluationError {
    #[error("Randomization of the base state failed: {}", .0)]
    RandomizeFailed(RandomizationError),

    #[error("This evaluation involves a storage location that has not been implemented")]
    NotImplemented,

    #[error("Encountered an error while observing: {}", .0)]
    OracleError(OracleError),

    #[error("Memory size too big")]
    MemorySizeTooBig,

    #[error("Adapt failed")]
    AdaptFailed,

    #[error("Cannot change the value of the zero register to a non-zero value")]
    CannotSetZeroReg,

    #[error("Generic error (TODO: Error specialization)")]
    Generic,
}

impl<'a, A: Arch + 'static, C: Computation + TryIntoBasicComputation> DecoratedOutput<'a, A, C> {
    pub fn evaluate_once<O: Oracle<A>>(&self, oracle: &mut O, inputs: &[u64]) -> Result<u64, EvaluationError> {
        let mut rng = rand::thread_rng();
        let dataflow = self.encoding.dataflows.iter_with_locations().nth(self.computation.output_index).unwrap();
        let input_locations = dataflow.iter_with_locations()
            .map(|(loc, _)| loc.into())
            .collect::<HashSet<FlowValueLocation>>();
        let final_instantiations = self.encoding.parts.iter()
            .map(|part| Ok(match &part.mapping {
                // TODO: This is incorrect. What about 
                PartMapping::ValueImm { locations, mapping } => {
                    match locations.iter().find(|loc| input_locations.contains(loc)) {
                        Some(FlowValueLocation::InputForOutput { input_index, ..  }) | Some(FlowValueLocation::MemoryAddress { input_index, .. }) => {
                            let new_value = inputs[*input_index];
                            if mapping.as_ref().map(|mapping| mapping.get(new_value as usize) == Some(&PartValue::Valid)).unwrap_or(true) {
                                new_value
                            } else {
                                return Err(EvaluationError::Generic);
                            }
                        },
                        _ => part.value,
                    }
                },
                _ => part.value,
            }))
            .collect::<Result<Vec<_>, _>>()?;

        let dataflows = self.encoding.instantiate(&final_instantiations).unwrap_or_else(|_|
            panic!("Failed to instantiate with {:X?}: {}", final_instantiations, self.encoding)
        );

        let mut base = StateGen::randomize_new(&dataflows.addresses, &mut rng, oracle).map_err(EvaluationError::RandomizeFailed)?;
        let mut changed = HashSet::<Location<_>>::new();
        for (input, value) in dataflow.iter().zip(inputs.iter().copied()) {
            match input {
                Source::Dest(Dest::Flag(flag)) => {
                    base.set_flag(flag, value != 0);
                    changed.insert(Location::Flag(flag.clone()));
                },
                Source::Dest(Dest::Reg(reg, _)) if reg.is_zero() => if value != 0 {
                    return Err(EvaluationError::CannotSetZeroReg);
                },
                Source::Dest(dest) => {
                    let bytes = value.to_le_bytes();
                    base.set_dest(dest, &if let Dest::Mem(_, size) = dest {
                        if size.len() > 8 {
                            // TODO: More than 8 bytes?
                            return Err(EvaluationError::MemorySizeTooBig);
                        }

                        Value::Bytes(&bytes[0..size.len()])
                    } else {
                        Value::Num(value)
                    });
                    changed.insert(dest.into());
                },
                Source::Imm(_) | Source::Const { .. } => (), // We have already instantiated the instruction with this immediate value
            }
        }

        if !StateGen::adapt(&dataflows.addresses, oracle, &mut base, &changed, false).unwrap_or(false) {
            return Err(EvaluationError::AdaptFailed);
        }

        Ok(match dataflow.location() {
            FlowOutputLocation::Output(_) => {
                let result = oracle.observe(&base).map_err(EvaluationError::OracleError)?;

                // unwrap() is OK here: we always have a target for 'real' outputs
                result.get_dest(dataflow.target().unwrap(), |v| match v {
                    Value::Num(n) => Ok(*n),
                    Value::Bytes(m) if m.len() <= 8 => {
                        let mut n = 0;
                        for (i, b) in m.iter().enumerate() {
                            n |= (*b as u64) << (i * 8);
                        }

                        Ok(n)
                    },
                    Value::FlagBitmap(f) => Ok(*f),
                    _ => Err(EvaluationError::NotImplemented),
                })?
            }
            FlowOutputLocation::MemoryAccess(index) => base.memory.data[index].0,
        })
    }

    /// Runs evaluate_once multiple times, to hopefully filter out the occasional error because of (for example) remapping.
    pub fn evaluate<O: Oracle<A>>(&self, oracle: &mut O, inputs: &[u64]) -> Result<u64, EvaluationError> {
        for _ in 0..10 {
            if let Ok(result) = self.evaluate_once(oracle, inputs) {
                return Ok(result);
            }
        }

        self.evaluate_once(oracle, inputs)
    }

    pub fn input_bit_sizes(&self) -> impl Iterator<Item = usize> {
        let final_instantiations = self.encoding.parts.iter()
            .map(|part| part.value)
            .collect::<Vec<_>>();
        let dataflows = self.encoding.instantiate(&final_instantiations).unwrap(); // TODO: handle error
        let flow = dataflows.iter_with_locations().nth(self.computation.output_index).unwrap();
        flow.iter().map(|s| match s {
            Source::Imm(n) => {
                if *n as usize >= self.encoding.parts.len() {
                    panic!("Invalid encoding: {}", self.encoding);
                }

                self.encoding.parts[*n as usize].size
            },
            Source::Const { num_bits, .. } => *num_bits,
            Source::Dest(Dest::Flag(_)) => 1,
            Source::Dest(Dest::Flags) => panic!("Should have been removed during preparation"),
            s @ Source::Dest(Dest::Reg(_, _)) | s @ Source::Dest(Dest::Mem(_, _)) => s.size().unwrap().len() * 8,
        }).collect::<Vec<_>>().into_iter()
    }

    pub fn output_bit_size(&self) -> usize {
        // TODO: Do we need to instantiate for this?    
        let final_instantiations = self.encoding.parts.iter()
            .map(|part| part.value)
            .collect::<Vec<_>>();
        let dataflows = self.encoding.instantiate(&final_instantiations).unwrap(); // TODO: handle error
        let flow = dataflows.iter_with_locations().nth(self.computation.output_index).unwrap();

        flow.target().map(|target| target.size().unwrap().len() * 8)
            // If there is no target, it's a memory access for which we'll just assume 64-bit addreses for now
            // TODO: This should depend on Arch instead of being hardcoded
            .unwrap_or(64)
    }
}

#[derive(Clone, Debug)]
pub struct SynthesisRuntimeData<'a, A: Arch + 'a, C: Computation> {
    encodings: &'a [Encoding<A, C>],
}

impl<'a, A: Arch + 'static, C: Computation> SynthesisRuntimeData<'a, A, C> {
    pub fn new(encodings: &'a [Encoding<A, C>]) -> SynthesisRuntimeData<'a, A, C> {
        SynthesisRuntimeData {
            encodings,
        }
    }
}

impl<C: Computation> OracleProvider<X64Arch> for SynthesisRuntimeData<'_, X64Arch, C> {
    type O = KmodPtraceOracle;
    
    fn oracle(&self) -> Result<KmodPtraceOracle, Box<dyn Error>> {
        Ok(KmodPtraceOracle::new("utils/minimal-executable")?)
    }
}


#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SynthesisWorker<'a, A: Arch, C: Computation> {
    pub computation_groups: Vec<OutputGroup>,

    #[serde(default)]
    pub index: usize,

    #[serde(default)]
    pub _phantom: std::marker::PhantomData<&'a (A, C)>,
}

impl<'a, A: Arch + 'static, C: Computation + Sync + Send + TryIntoBasicComputation> Worker for SynthesisWorker<'a, A, C> where SynthesisRuntimeData<'a, A, C>: OracleProvider<A> {
    type LogEntry = ();
    type Artifact = ();
    type RuntimeData = SynthesisRuntimeData<'a, A, C>;

    fn run(&mut self, worker_id: usize, running: &std::sync::atomic::AtomicBool, runtime_data: &SynthesisRuntimeData<'a, A, C>, mut updater: crate::work::StateUpdater<Self>) -> Result<(), Box<dyn Error>> {
        let mut oracle = runtime_data.oracle()?;
        let mut rng = rand::thread_rng();

        if self.computation_groups.len() <= 0 {
            updater.done(self.clone());
            return Ok(());
        }

        println!("[{:02}] {} groups containing a total of {} computations", worker_id, self.computation_groups.len(), self.computation_groups.iter().map(|g| g.len()).sum::<usize>());
        'outer: loop {
            println!("[{:02}] Currently: {} / {} -- {}", worker_id, self.index, self.computation_groups.len(), self.computation_groups[self.index][0].with_encodings(&runtime_data.encodings));
            let mut num_observations = 0;
            for _ in 0..1_200_000 {
                if !running.load(Ordering::SeqCst) {
                    break 'outer;
                }

                if num_observations > 800_000 {
                    break;
                }
    
                let group = &mut self.computation_groups[self.index];
                if group.len() <= 0 {
                    panic!("[{:02}] Empty groups should not exist", worker_id);
                }

                let computation = &group[rng.gen_range(0, group.len())];
                let c = computation.with_encodings(&runtime_data.encodings);

                let inputs = c.input_bit_sizes().map(|size| randomized_value(&mut rng) & (((1u128 << size) - 1) as u64)).collect::<Vec<u64>>();
                match c.evaluate(&mut oracle, &inputs) {
                    Ok(result) => {
                        num_observations += 1;
                        if num_observations % 10_000 == 0 {
                            println!("[{:02}] Made {}k observations for group of size n={}", worker_id, num_observations / 1000, group.len());
                        }

                        let check = group.table.check(&inputs, result);
                        if group.len() > 1 && !check.is_ok() {
                            // This input required a new expression to be added to the synthesis table. We split the groups based on that expression.
                            if !check.is_ok() {
                                println!("[{:02}] Trying to split the group (n={}) on distinguishing input {:?} => {}", worker_id, group.len(), inputs, result);
                            }
                            let mut additional_groups = group.split_differing(&runtime_data.encodings, &mut oracle, &inputs, Some(Some(result)));

                            if let Some(additional_groups) = &mut additional_groups {
                                let len = additional_groups.len();
                                println!("[{:02}] Split into {} new groups + 1 existing because of distinguishing input", worker_id, len);

                                if len > 0 {
                                    group.table.clear();
                                    self.computation_groups.append(additional_groups);
                                }
                            } else {
                                if !check.is_ok() {
                                    println!("[{:02}] Split unneeded", worker_id);
                                }

                                if !group.table.process(check) {
                                    println!("[{:02}] Synthesis failed", worker_id);
                                    group.failed = true;
                                    break;
                                }
                            }
                        } else {
                            let c_str = format!("{}", c);
                            if !group.table.process(check) {
                                println!("[{:02}] Synthesis failed for {}", worker_id, c_str);
                                group.failed = true;
                                break;
                            }

                            if group.table.has_good_tree() {
                                println!("[{:02}] ================================================================", worker_id);
                                println!("[{:02}] We have a good tree: {}", worker_id, group.table);
                                println!("[{:02}] Corresponding computation: {}", worker_id, c_str);
                                println!("[{:02}] ================================================================", worker_id);
                                break;
                            }
                        }
                    },
                    Err(EvaluationError::MemorySizeTooBig) => break,
                    Err(_) => {},
                }
            }

            let group = &mut self.computation_groups[self.index];
            if group.failed {
                let c = group[0].with_encodings(&runtime_data.encodings);
                println!("[{:02}] ================================================================", worker_id);
                println!("[{:02}] Synthesis failed: {}", worker_id, group.table);
                println!("[{:02}] Corresponding computation: {}", worker_id, c);
                println!("[{:02}] ================================================================", worker_id);
            }

            self.index += 1;
            if self.index >= self.computation_groups.len() {
                self.index = 0;

                if self.computation_groups.iter().all(|g| g.given_up() || g.table.has_good_tree()) {
                    updater.done(self.clone());
                    return Ok(());
                }
            }

            oracle.restart();
            updater.update(self.clone());
        }

        updater.update(self.clone());

        Ok(())
    }
}