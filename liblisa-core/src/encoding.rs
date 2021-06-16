use crate::{Dest, FlowOutputLocation, FlowValueLocation, Inputs, Size, Source, Computation};
use crate::arch::{Arch, Instr, Register, Instruction, InstructionInfo};
use crate::accesses::AccessKind;
use crate::dataflow::Dataflows;
use crate::counter::{ByteFilter, InstructionFilter};
use itertools::Itertools;
use std::{collections::{HashMap, HashSet}, fmt::{Debug, Display}};
use serde::{Serialize, Deserialize};
use log::*;

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BitKind {
    Value(usize),
    Fixed(u8),
    DontCare,
}

const PART_NAMES: &'static [&'static str] = &[
    "a", "b", "c", "d", "e", "f", "g", "h", "j", "k", "m", "n", "p", "q", "r",
];

impl Debug for BitKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BitKind::Value(n) => f.write_str(
                PART_NAMES[*n],
            ),
            BitKind::Fixed(v) => write!(f, "{}", v),
            BitKind::DontCare => f.write_str("_"),
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PartValue {
    Valid,
    Invalid,
}

impl PartValue {
    pub fn is_valid(&self) -> bool {
        self == &PartValue::Valid
    }

    pub fn is_invalid(&self) -> bool {
        self == &PartValue::Invalid
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PartMapping<A: Arch> {
    #[serde(alias = "AddressImm")]
    ValueImm {
        #[serde(default)]
        mapping: Option<Vec<PartValue>>,
        locations: Vec<FlowValueLocation>,
    },
    Register {
        mapping: Vec<Option<A::Reg>>,
        locations: Vec<FlowValueLocation>,
    },
    Size {
        mapping: Vec<Option<Size>>,
        locations: Vec<FlowValueLocation>,
    },
}

impl<A: Arch> PartMapping<A> {
    pub fn register_mapping(&self) -> Option<&[Option<A::Reg>]> {
        match self {
            PartMapping::Register { mapping, .. } => Some(mapping),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Part<A: Arch> {
    pub size: usize,
    pub value: u64,
    pub mapping: PartMapping<A>,
}

impl<A: Arch> Part<A> {
    /// Get a reference to the part's size.
    pub fn size(&self) -> usize {
        self.size
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Encoding<A: Arch, C: Computation> {
    pub bits: Vec<BitKind>,
    pub parts: Vec<Part<A>>,
    pub dataflows: Dataflows<A, C>,
}

pub struct EncodingOutput {
    pub num_inputs: usize,
    pub memory_access: bool,
    pub has_computation: bool,
}

impl<A: Arch + 'static, C: Computation> Encoding<A, C> {
    pub fn instr<'a>(&'a self) -> Instr<'a> {
        self.dataflows.addresses.instr.as_instr()
    }

    pub fn filters(&self) -> Vec<InstructionFilter> {
        let incomplete_choices = self.parts.iter().enumerate()
            .flat_map(|(index, p)| match &p.mapping {
                PartMapping::Register { locations: _, mapping } if mapping.iter().any(Option::is_none) => {
                    Some((index, mapping.iter().map(Option::is_some).collect::<Vec<_>>()))
                },
                PartMapping::Size { locations: _, mapping } if mapping.iter().any(Option::is_none) => {
                    Some((index, mapping.iter().map(Option::is_some).collect::<Vec<_>>()))
                },
                PartMapping::ValueImm { locations: _, mapping: Some(mapping) } if mapping.iter().any(PartValue::is_valid) => {
                    Some((index, mapping.iter().map(PartValue::is_valid).collect::<Vec<_>>()))
                }
                _ => None,
            })
            .collect::<Vec<_>>();

        let incomplete_choices_map = {
            let mut m = HashMap::new();
            for (index, (n, _)) in incomplete_choices.iter().enumerate() {
                m.insert(*n, index);
            }

            m
        };
        let mut filters = Vec::new();
        let mut values = vec![ 0usize; incomplete_choices.len() ];
        loop {
            if incomplete_choices.iter().zip(values.iter()).all(|((_, valid), value)| valid[*value]) {
                let mut ks = vec![ 0; incomplete_choices.len() ];
                let mut byte_filters = Vec::with_capacity(self.bits.len() / 8);
                for byte in self.bits.chunks(8) {
                    let mvs = byte.iter().map(|b| match b {
                        BitKind::Fixed(v) => (1, *v),
                        BitKind::Value(n) => if let Some(&index) = incomplete_choices_map.get(n) {
                            let v = (values[index] >> ks[index]) as u8 & 1;
                            ks[index] += 1;

                            (1, v)
                        } else {
                            (0, 0)
                        },
                        BitKind::DontCare => (0, 0),
                    }).collect::<Vec<_>>();
                    let mask = mvs.iter().enumerate().map(|(i, (m, _))| m << i).fold(0, |a, b| a | b);
                    let value = mvs.iter().enumerate().map(|(i, (_, v))| v << i).fold(0, |a, b| a | b);

                    byte_filters.push(ByteFilter::new(mask, value));
                }

                // Reverse the filters because they are in the wrong order because self.bits is stored the other way round
                byte_filters.reverse();
                filters.push(InstructionFilter::new(byte_filters));
            }

            let mut carry = 1;
            for (index, val) in values.iter_mut().enumerate() {
                *val += carry;
                if *val >= incomplete_choices[index].1.len() {
                    *val = 0;
                    carry = 1;
                } else {
                    carry = 0;
                }
            }

            if carry > 0 {
                break;
            }
        }

        filters
    }

    fn value_bits(&self, n: usize) -> usize {
        let mut result = 0;
        for bit in self.bits.iter() {
            if let BitKind::Value(v) = bit {
                if n == *v {
                    result += 1;
                }
            }
        }

        result
    }

    pub fn instantiate_partially(&self, part_values: &[Option<u64>]) -> Result<Encoding<A, C>, InstantiationError> {
        let mut new_instr: Instruction = self.instr().into();
        let mut indices = vec![ 0; part_values.len() ];
        assert_eq!(self.parts.len(), part_values.len(), "A value must be specified for every part");

        for (index, kind) in self.bits.iter().enumerate() {
            match kind {
                BitKind::Value(n) => {
                    if let Some(part_value) = part_values[*n] {
                        new_instr = new_instr.with_bit(index, (part_value >> indices[*n]) as u8 & 1);
                        indices[*n] += 1;
                    }
                }
                _ => {},
            }
        }

        let mut new_indices = Vec::new();
        let mut n = 0;
        for part_value in part_values.iter() {
            if part_value.is_none() {
                new_indices.push(Some(n));
                n += 1;
            } else {
                new_indices.push(None);
            }
        }

        let dataflows = self.dataflows.map(new_instr, |loc, old| {
            let mut result = old.clone();
            for (part, part_value) in self.parts.iter().zip(part_values.iter().copied()) {
                if let Some(part_value) = part_value {
                    match &part.mapping {
                        PartMapping::Register { mapping, locations } if locations.contains(&loc) => {
                            match &mut result {
                                Source::Dest(Dest::Reg(reg, _)) => *reg = if let Some(value) = &mapping[part_value as usize] {
                                    value.clone()
                                } else {
                                    return Err(InstantiationError::MissingRegisterMapping)   
                                },
                                _ => {},
                            }
                        }
                        PartMapping::Size { mapping, locations } if locations.contains(&loc) => {
                            match &mut result {
                                Source::Dest(Dest::Reg(_, size)) => *size = if let Some(value) = &mapping[part_value as usize] {
                                    value.clone()
                                } else {
                                    return Err(InstantiationError::MissingRegisterSizeMapping)   
                                },
                                Source::Dest(Dest::Mem(_, size)) => *size = if let Some(value) = &mapping[part_value as usize] {
                                    value.clone()
                                } else {
                                    return Err(InstantiationError::MissingMemorySizeMapping)
                                },
                                _ => {},
                            }
                        }
                        PartMapping::ValueImm { locations, mapping } if locations.contains(&loc) => {
                            if mapping.as_ref().map(|m| m[part_value as usize].is_valid()).unwrap_or(true) {
                                result = Source::Const { value: part_value, num_bits: part.size };
                            } else {
                                return Err(InstantiationError::MissingImmValueMapping)
                            }
                        }
                        _ => {},
                    }
                }
            }

            if let Source::Imm(n) = &mut result {
                if let Some(val) = new_indices[*n] {
                    *n = val;
                } else {
                    // if new_indices[*n] is None, then it will be replaced with a Source::Const in the match above
                    panic!("Encoding is not valid: {} {:#?}; found {:?} at {:?} which is not being remapped to a new index", self, self, result, loc);
                }
            }

            Ok(Some(result))
        })?;

        let parts = self.parts.iter().cloned()
            .zip(part_values.iter().copied())
            .filter(|(_, p)| p.is_none())
            .map(|(p, _)| p)
            .collect::<Vec<_>>();

        let bits = self.bits.iter().cloned().enumerate()
            .map(|(i, b)| match b {
                BitKind::Value(n) => match new_indices[n] {
                    Some(new) => BitKind::Value(new),
                    None => BitKind::Fixed(dataflows.instr().bit_at(i)),
                },
                other => other,
            })
            .collect::<Vec<_>>();

        Ok(Encoding {
            dataflows,
            bits,
            parts,
        })
    }

    pub fn instantiate(&self, part_values: &[u64]) -> Result<Dataflows<A, C>, InstantiationError> {
        let part_values = part_values.iter().map(|&v| Some(v)).collect::<Vec<_>>();
        Ok(self.instantiate_partially(&part_values)?.dataflows)
    }

    pub fn iter<'a>(&'a self, values: &'a [Option<u64>]) -> impl Iterator<Item = Dataflows<A, C>> + 'a {
        EncodingIterator::<'a> {
            encoding: self,
            values,
            current: self.parts.iter().enumerate()
                .map(|(index, _)| if let Some(value) = values[index] {
                    value
                } else {
                    0
                })
                .collect::<Vec<_>>(),
            first: true,
        }
    }

    pub fn outputs(&self) -> impl Iterator<Item = EncodingOutput> + '_ {
        self.dataflows.iter_with_locations().map(|dataflow| EncodingOutput {
            num_inputs: dataflow.iter().count(),
            memory_access: matches!(dataflow.location(), FlowOutputLocation::MemoryAccess(_)),
            has_computation: dataflow.computation().is_some(),
        })
    }

    pub fn map_computations<CNew: Computation>(&self, f: impl Fn(&Inputs<A>, &C) -> CNew) -> Encoding<A, CNew> {
        Encoding {
            bits: self.bits.clone(),
            parts: self.parts.clone(),
            dataflows: self.dataflows.map_computations(f),
        }
    }

    pub fn set_computation(&mut self, index: usize, computation: C) {
        match index.checked_sub(self.dataflows.addresses.len()) {
            None => self.dataflows.addresses[index].calculation = Some(computation),
            Some(index) => self.dataflows[index].computation = Some(computation),
        }
    }

    fn fill_value_imms(&self, choices: &mut [u64], values: HashSet<usize>) {
        let mut base = vec![ 0; choices.len() ];
        for index in values.iter() {
            choices[*index] = 0;
        }

        for (index, kind) in self.bits.iter().enumerate() {
            match kind {
                BitKind::Value(n) if values.contains(n) => {
                    // If there are less than 6 bits, we're just going to set the lowest bit instead of doing a checkerboard pattern.
                    if self.bits.iter().filter(|b| b == &kind).count() >= 6 || base[*n] <= 1 {
                        choices[*n] |= ((1 ^ (index & 1)) as u64) << base[*n];
                    }

                    base[*n] += 1;
                }
                _ => {},
            }
        }
    }

    pub fn find_best_reg_choices(&self, alter_sizes: bool, eval: impl Fn(&[u64]) -> usize) -> Option<Vec<Option<u64>>> {
        let reg_choices = self.parts.iter()
            .map(|p| match &p.mapping {
                PartMapping::Register { mapping, .. } => Some(mapping.len()),
                PartMapping::Size { mapping, .. } if alter_sizes => Some(mapping.len()),
                _ => None,
            })
            .collect::<Vec<_>>();

        let current_choices = self.parts.iter().map(|p| p.value).collect::<Vec<_>>();
        if reg_choices.iter().filter(|x| x.is_some()).count() <= 0 {
            return None;
        }

        let mut perfect_choices = current_choices.clone();
        let mut perfect_score = eval(&current_choices);
        let mut new_choices = vec![0; reg_choices.len()];
        loop {
            let score = eval(&new_choices);
            if score < perfect_score {
                perfect_score = score;
                perfect_choices = new_choices.clone();
            }

            let mut carry = 1;
            for (val, choice) in new_choices.iter_mut().zip(reg_choices.iter()) {
                if let Some(choices_len) = choice {
                    *val += carry;
                    if *val >= *choices_len as u64 {
                        *val = 0;
                        carry = 1;
                    } else {
                        carry = 0;
                    }
                }
            }

            if carry > 0 {
                break;
            }
        }

        Some(perfect_choices.iter().copied().zip(reg_choices.iter()).map(|(c, r)| r.map(|_| c)).collect::<Vec<_>>())
    }

    pub fn best_instr(&self) -> Option<Instruction> {
        let reg_choice_locations = self.parts.iter()
            .flat_map(|p| match &p.mapping {
                PartMapping::Register { locations, mapping: _ } => {
                    locations.iter()
                },
                _ => [].iter(),
            })
            .collect::<Vec<_>>();
        let current_choices = self.parts.iter().map(|p| p.value).collect::<Vec<_>>();
        let fixed_register_use = {
            let mut h = HashMap::new();
            for reg in self.dataflows.values()
                .filter(|(loc, _)| !reg_choice_locations.contains(&loc))
                .flat_map(|(_, s)| match s {
                    Source::Dest(Dest::Reg(reg, _)) => Some(reg.clone()),
                    _ => None,
                }) {
                h.entry(reg).or_insert(1);
            }

            h
        };

        let compute_score = |new_choices: &[u64]| {
            let mut register_use = fixed_register_use.clone();
            let mut bad = false;
            for (part, choice) in self.parts.iter().zip(new_choices.iter()) {
                if let Some(values) = part.mapping.register_mapping() {
                    match &values[*choice as usize] {
                        Some(r) if r.is_zero() => bad = true,
                        Some(v) => *register_use.entry(v.clone()).or_insert(0) += 1,
                        None => bad = true,
                    }
                }
            }

            if !bad {
                let score = register_use.values().max().unwrap();
                *score
            } else {
                999_999
            }
        };

        let compute_full_score = |new_choices: &[u64]| {
            // Weigh the score of the current chosen encoding much heavier than that of the bitflips
            let mut score = compute_score(&new_choices) * 0x100;
            for (choice_index, part) in self.parts.iter().enumerate() {
                if part.mapping.register_mapping().is_some() {
                    for bit in 0..self.value_bits(choice_index) {
                        let mut choices_with_flipped_bit = new_choices.to_vec();
                        choices_with_flipped_bit[choice_index] ^= 1 << bit;

                        score += compute_score(&choices_with_flipped_bit);
                    }
                }
            }

            score
        };
        
        let mut perfect_choices = self.find_best_reg_choices(false, compute_full_score)
            .map(|choices| choices.iter().enumerate().map(|(index, value)| value.unwrap_or(current_choices[index])).collect())
            .unwrap_or(current_choices.clone());

        let value_imms = self.parts.iter().enumerate()
            .filter(|(_, p)| match &p.mapping {
                PartMapping::ValueImm { locations, .. } if locations.iter().any(|loc| matches!(loc, FlowValueLocation::InputForOutput { .. })) => true,
                _ => false,
            })
            .map(|(n, _)| n)
            .collect::<HashSet<_>>();
        self.fill_value_imms(&mut perfect_choices, value_imms);

        if perfect_choices == current_choices {
            None
        } else {
            if let Ok(dataflows) = self.instantiate(&perfect_choices) {
                Some(dataflows.addresses.instr)
            } else {
                error!("best_instr: unable to instantiate perfect instruction!");
                None
            }
        }
    }

    pub fn extract_parts(&self, instr: Instr<'_>) -> Vec<u64> {
        let mut parts = vec![0u64; self.parts.len()];
        let mut part_indices = vec![0usize; self.parts.len()];
        for (bit_index, bit) in self.bits.iter().enumerate() {
            match bit {
                BitKind::Value(n) => {
                    parts[*n] |= (instr.bit_at(bit_index) as u64) << part_indices[*n];
                    part_indices[*n] += 1; 
                }
                _ => {},
            }
        }

        parts
    }

    pub fn fix(&mut self) -> bool {
        // Make sure all immediate values are correctly numbered
        for (part_index, part) in self.parts.iter_mut().enumerate() {
            match &mut part.mapping {
                PartMapping::ValueImm { locations, .. } => {
                    for location in locations.iter_mut() {
                        match location {
                            FlowValueLocation::InputForOutput { output_index, input_index } => {
                                match &mut self.dataflows.outputs[*output_index].inputs.inputs[*input_index] {
                                    Source::Imm(n) => {
                                        *n = part_index;
                                    },
                                    _ => return false,
                                }
                            }
                            FlowValueLocation::MemoryAddress { memory_index, input_index } => {
                                match &mut self.dataflows.addresses.memory[*memory_index].inputs.inputs[*input_index] {
                                    Source::Imm(n) => {
                                        *n = part_index;
                                    },
                                    _ => return false,
                                }
                            }
                            FlowValueLocation::Output(_) => return false,
                        }
                    }
                }
                _ => {},
            }
        }

        // Make sure all immediate values are correctly registered in a part
        for (output_index, flow) in self.dataflows.outputs.iter().enumerate() {
            for (input_index, input) in flow.inputs.inputs.iter().enumerate() {
                match input {
                    Source::Imm(n) => {
                        if let PartMapping::ValueImm { locations, .. } = &mut self.parts[*n].mapping {
                            let loc = FlowValueLocation::InputForOutput { output_index, input_index };
                            if !locations.contains(&loc) {
                                locations.push(loc);
                            }
                        } else {
                            error!("Invalid PartMapping: {:?} {}", self, self);
                            return false;
                        }
                    }
                    _ => {},
                }
            }
        }

        true
    }

    pub fn integrity_check(&self) -> bool {
        if self.dataflows.iter_with_locations()
            .any(|flow|
                flow.iter().any(|s| match s {
                    Source::Imm(n) => self.parts.get(*n as usize).is_none(),
                    _ => false,
                })) {
            return false;
        }

        if self.parts.iter().any(|p| match &p.mapping {
            PartMapping::ValueImm { mapping: Some(mapping), .. } if mapping.iter().all(|x| x.is_invalid()) => true,
            _ => false,
        }) {
            return false;
        }

        true
    }

    pub fn split_flag_output(&mut self) {
        let index = self.dataflows.output_dataflows().position(|f| f.target == Dest::Flags);
        if let Some(removed_index) = index {
            let num_added = self.dataflows.split_flag_output();
            let n = self.dataflows.output_dataflows().count();
            let added_index_range = n - num_added..n;

            for part in self.parts.iter_mut() {
                match &mut part.mapping {
                    PartMapping::Register { locations, .. } 
                    | PartMapping::Size { locations, .. }
                    | PartMapping::ValueImm { locations, .. } => {
                        let mut new_locations = Vec::new();
                        let mut removed_indexes = Vec::new();
                        for (location_index, location) in locations.iter_mut().enumerate() {
                            match location {
                                FlowValueLocation::InputForOutput { output_index, .. } | FlowValueLocation::Output(output_index) => {
                                    if *output_index > removed_index {
                                        *output_index -= 1;
                                    } else if *output_index == removed_index {
                                        removed_indexes.push(location_index);
                                        for new_output_index in added_index_range.clone() {
                                            new_locations.push(match location {
                                                FlowValueLocation::InputForOutput { input_index, .. } => {
                                                    FlowValueLocation::InputForOutput { output_index: new_output_index, input_index: *input_index }
                                                }
                                                FlowValueLocation::Output(_) => {
                                                    FlowValueLocation::Output(new_output_index)
                                                }
                                                FlowValueLocation::MemoryAddress { .. } => unreachable!(),
                                            });
                                        }
                                    }
                                }
                                FlowValueLocation::MemoryAddress { .. } => {},
                            }
                        }

                        for &index in removed_indexes.iter().rev() {
                            locations.remove(index);
                        }

                        locations.extend(new_locations.into_iter());
                        locations.sort();
                    }
                }
            }
        }
    }

    pub fn remove_bit(&mut self, bit_index: usize) {
        let bit = self.bits[bit_index];
        let bit_value = self.instr().bit_at(bit_index);
        let new_bit = BitKind::Fixed(bit_value);

        match bit {
            BitKind::Value(part_index) => {
                let part = &mut self.parts[part_index];

                if part.size <= 1 {
                    // Remove the entire part
                    let values = self.extract_parts(self.instr()).into_iter().enumerate().map(|(n, v)| if n == part_index {
                        Some(v)
                    } else {
                        None
                    }).collect::<Vec<_>>();

                    *self = self.instantiate_partially(&values).unwrap();
                } else {
                    self.bits[bit_index] = new_bit;
                    part.size -= 1;

                    let bit_index_in_part = self.bits.iter().take(bit_index).filter(|b| b == &&BitKind::Value(part_index)).count();
                    match &mut part.mapping {
                        PartMapping::Register { mapping, .. } => *mapping = pick_bit_value(mapping, bit_index_in_part, bit_value),
                        PartMapping::Size { mapping, .. } => *mapping = pick_bit_value(mapping, bit_index_in_part, bit_value),
                        PartMapping::ValueImm { mapping, .. } => if let Some(mapping) = mapping {
                            *mapping = pick_bit_value(mapping, bit_index_in_part, bit_value)
                        },
                    }

                    let lower_value = part.value & ((1 << bit_index_in_part) - 1);
                    let upper_value = (part.value >> (bit_index_in_part + 1)) << bit_index_in_part;
                    part.value = lower_value | upper_value;
                }
            },
            BitKind::Fixed(_) => {},
            BitKind::DontCare => self.bits[bit_index] = new_bit,
        }
    }

    /// returns what kinds of mapping will be removed: (good_mapping, invalid_mapping)
    pub fn preview_remove_bit(&self, bit_index: usize) -> (usize, usize) {
        let bit = self.bits[bit_index];
        let bit_value = self.instr().bit_at(bit_index);
        match bit {
            BitKind::Value(part_index) => {
                let part = &self.parts[part_index];
                let bit_index_in_part = self.bits.iter().take(bit_index).filter(|b| b == &&BitKind::Value(part_index)).count();
                match &part.mapping {
                    PartMapping::Register { mapping, .. } => preview_pick_bit_value(mapping, |x| x.is_some(), bit_index_in_part, bit_value),
                    PartMapping::Size { mapping, .. } => preview_pick_bit_value(mapping, |x| x.is_some(), bit_index_in_part, bit_value),
                    PartMapping::ValueImm { mapping, .. } => if let Some(mapping) = mapping {
                        preview_pick_bit_value(mapping, |x| x.is_valid(), bit_index_in_part, bit_value)
                    } else {
                        (1, 0)
                    },
                }
            },
            BitKind::Fixed(_) => (0, 0),
            BitKind::DontCare => (1, 0),
        }
    }
}

fn preview_pick_bit_value<T: Clone>(vec: &Vec<T>, good: impl Fn(&T) -> bool, bit_index: usize, bit_value: u8) -> (usize, usize) {
    let good_removed = vec.iter()
        .enumerate()
        .filter(|(index, _)| ((index >> bit_index) & 1) as u8 != bit_value)
        .filter(|(_, x)| good(x))
        .count();
    (
        good_removed, 
        vec.len() / 2 - good_removed
    )
}

fn pick_bit_value<T: Clone>(vec: &Vec<T>, bit_index: usize, bit_value: u8) -> Vec<T> {
    vec.iter()
        .enumerate()
        .filter(|(index, _)| ((index >> bit_index) & 1) as u8 == bit_value)
        .map(|(_, x)| x.clone())
        .collect()
}

#[derive(Debug, Clone, thiserror::Error)]
pub enum InstantiationError {
    #[error("Invalid instantiation parameters: missing register mapping")]
    MissingRegisterMapping,

    #[error("Invalid instantiation parameters: missing register size mapping")]
    MissingRegisterSizeMapping,

    #[error("Invalid instantiation parameters: missing memory size mapping")]
    MissingMemorySizeMapping, 

    #[error("Invalid instantiation parameters: missing imm value mapping")]
    MissingImmValueMapping,
}

struct EncodingIterator<'a, A: Arch, C: Computation> {
    encoding: &'a Encoding<A, C>,
    values: &'a [Option<u64>],
    current: Vec<u64>,
    first: bool,
}

impl<'a, A: Arch + 'static, C: Computation> EncodingIterator<'a, A, C> {
    fn next_value(&mut self) -> bool {
        let mut carry = 1;
        for ((current, val), part) in self.current.iter_mut().zip(self.values).zip(self.encoding.parts.iter()) {
            if val.is_none() {
                *current += carry;
                if *current >= (1 << part.size) as u64 {
                    *current = 0;
                    carry = 1;
                } else {
                    carry = 0;
                }
            }
        }

        carry == 0
    }
}

impl<'a, A: Arch + 'static, C: Computation> Iterator for EncodingIterator<'a, A, C> {
    type Item = Dataflows<A, C>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if !self.first {
                if !self.next_value() {
                    return None;
                }
            }

            self.first = false;
            if let Ok(result) = self.encoding.instantiate(&self.current) {
                return Some(result);
            }
        }
    }
}

struct SourceWithParts<'a, A: Arch, C: Computation> {
    loc: FlowValueLocation,
    encoding: &'a Encoding<A, C>,
    input: &'a Source<A>,
}

impl<A: Arch, C: Computation> Display for SourceWithParts<'_, A, C> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self.input {
            Source::Dest(Dest::Reg(reg, size)) => {
                let mut found = false;
                for (part_index, part) in self.encoding.parts.iter().enumerate() {
                    match &part.mapping {
                        PartMapping::Register { locations, mapping: _ } if locations.contains(&self.loc) => {
                            write!(f, "<{}>", PART_NAMES[part_index])?;
                            found = true;
                        }
                        _ => {},
                    }
                }

                if !found {
                    write!(f, "{}", reg)?;
                }

                let mut found = false;
                for (part_index, part) in self.encoding.parts.iter().enumerate() {
                    match &part.mapping {
                        PartMapping::Size { locations, mapping: _ } if locations.contains(&self.loc) => {
                            write!(f, "[<{}>]", PART_NAMES[part_index])?;
                            found = true;
                        }
                        _ => {},
                    }
                }

                if !found {
                    write!(f, "[{}..{}]", size.start_byte, size.end_byte)?;
                }
            },
            Source::Dest(Dest::Mem(mem, size)) => {
                write!(f, "m{}", mem)?;

                let mut found = false;
                for (part_index, part) in self.encoding.parts.iter().enumerate() {
                    match &part.mapping {
                        PartMapping::Size { locations, mapping: _ } if locations.contains(&self.loc) => {
                            write!(f, "[<{}>]", part_index)?;
                            found = true;
                        }
                        _ => {},
                    }
                }

                if !found {
                    write!(f, "[{}..{}]", size.start_byte, size.end_byte)?;
                }
            },
            Source::Imm(imm) => {
                write!(f, "<{}>", PART_NAMES[*imm])?;
            },
            other => write!(f, "{}", other)?,
        }
        
        Ok(())
    }
}

struct InputsWithParts<'a, A: Arch, C: Computation> {
    loc: FlowOutputLocation,
    encoding: &'a Encoding<A, C>,
    inputs: &'a Inputs<A>,
    computation: Option<&'a C>,
}

impl<A: Arch, C: Computation> Display for InputsWithParts<'_, A, C> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self.computation {
            Some(computation) => {
                let names = self.inputs.iter().enumerate()
                    .map(|(index, input)| format!("{}", SourceWithParts { loc: self.loc.input(index).into(), encoding: self.encoding, input: input }))
                    .collect::<Vec<_>>();

                write!(f, "{}", computation.display(&names))?;
            }
            None => {
                for (index, input) in self.inputs.iter().enumerate() {
                    if index != 0 {
                        write!(f, ", ")?;
                    }

                    write!(f, "{}", SourceWithParts { loc: self.loc.input(index).into(), encoding: self.encoding, input: input })?;
                }
            }
        }
        
        Ok(())
    }
}

impl<A: Arch + 'static, C: Computation> Display for Encoding<A, C> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(
            f,
            "{} {:02X?}",
            self.bits
                .iter()
                .rev()
                .chunks(8)
                .into_iter()
                .map(|byte| byte.into_iter().map(|s| format!("{:?}", s)).join(""))
                .join(" "),
            self.dataflows.addresses.instr.bytes()
        )?;

        for (index, access) in self.dataflows.addresses.iter().enumerate() {
            writeln!(
                f,
                "{:10} = {}",
                format!("Addr{}(m{})", 
                    match access.kind {
                        AccessKind::Executable => "X ",
                        AccessKind::Input => "R ",
                        AccessKind::InputOutput => "RW",
                    },
                    index
                ),
                InputsWithParts { 
                    encoding: &self, 
                    inputs: &access.inputs, 
                    loc: FlowOutputLocation::MemoryAccess(index), 
                    computation: access.calculation.as_ref(),
                }
            )?;
        }

        for (index, output) in self.dataflows.output_dataflows().enumerate() {
            writeln!(
                f,
                "{:10} = {}",
                format!("{}", SourceWithParts { encoding: &self, input: &Source::Dest(output.target.clone()), loc: FlowValueLocation::Output(index) }),
                InputsWithParts { 
                    encoding: &self, 
                    inputs: &output.inputs, 
                    loc: FlowOutputLocation::Output(index), 
                    computation: output.computation.as_ref(),
                }
            )?;
        }

        for (index, part) in self.parts.iter().enumerate() {
            writeln!(f, "<{}>{}", PART_NAMES[index], part)?;
        }

        Ok(())
    }
}

struct DisplayPartMapping<'a, A: Arch> {
    mapping: &'a PartMapping<A>,
    value: u64,
    size: usize,
}

impl<'a, A: Arch> Display for DisplayPartMapping<'a, A> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.mapping {
            PartMapping::Register { locations: _, mapping } => {
                for (key, value) in mapping.iter().enumerate() {
                    if key != 0 {
                        write!(f, ", ")?;
                    }

                    write!(f, "{:0pad$b} => ", key, pad = self.size)?;
                    if let Some(reg) = value {
                        if key as u64 == self.value {
                            write!(f, "[ {} ]", reg)?;
                        } else {
                            write!(f, "{}", reg)?;
                        }
                    } else {
                        write!(f, "-")?;
                    }
                }
            },
            PartMapping::Size { locations: _, mapping } => {
                for (key, value) in mapping.iter().enumerate() {
                    if key != 0 {
                        write!(f, ", ")?;
                    }
                    
                    write!(f, "{:0pad$b} => ", key, pad = self.size)?;
                    if let Some(size) = value {
                        if key as u64 == self.value {
                            write!(f, "[ {}..{} ]", size.start_byte, size.end_byte)?;
                        } else {
                            write!(f, "{}..{}", size.start_byte, size.end_byte)?;
                        }
                    } else {
                        write!(f, "-")?;
                    }
                }
            },
            PartMapping::ValueImm { locations: _, mapping } => {
                write!(f, "immediate = 0x{:X}", self.value)?;

                if let Some(mapping) = mapping {
                    if mapping.iter().any(PartValue::is_invalid) {
                        for (value, item) in mapping.iter().enumerate() {
                            if item.is_invalid() {
                                write!(f, " exclude {}", value)?;
                            }
                        }
                    }
                }
            },
        }

        Ok(())
    }
}

impl<A: Arch> Display for Part<A> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[{} bits]: {}", self.size, DisplayPartMapping {
            mapping: &self.mapping,
            value: self.value,
            size: self.size,   
        })
    }
}

#[allow(unused)]
#[cfg(test)]
mod tests {
    use crate::arch::Instr;
    use crate::{Size, Dest, Source};
    use crate::dataflow::{Dataflows, Flow};
    use crate::accesses::{MemoryAccesses, MemoryAccess, AccessKind};
    use crate::encoding::{Encoding, BitKind, Part, PartMapping, FlowValueLocation};
    use crate::counter::{ByteFilter, InstructionFilter};
    use crate::fake::*;
    use crate::Inputs;

    #[test_env_log::test]
    pub fn generate_filters() {
        let instr = Instr::new(&[ 0x01, 0xD0 ]);
        let dataflows = Dataflows::<FakeArch, crate::computation::BasicComputation> {
            addresses: MemoryAccesses {
                instr: instr.into(),
                memory: vec! [
                    MemoryAccess {
                        kind: AccessKind::Executable,
                        inputs: Inputs::sorted(vec! [ Dest::Reg(R0, Size::qword()).into() ]),
                        size: 2..2,
                        calculation: None,
                        alignment: 1,
                    }
                ]
            },
            outputs: vec! [
                Flow {
                    target: Dest::Reg(R1, Size::qword()),
                    inputs: Inputs::sorted(vec! [ Dest::Reg(R1, Size::new(0, 3)).into(), Dest::Reg(R2, Size::new(0, 3)).into() ]),
                    unobservable_external_inputs: false,
                    computation: None,
                },
                Flow {
                    target: Dest::Reg(R0, Size::qword()),
                    inputs: Inputs::sorted(vec! [ Dest::Reg(R0, Size::new(0, 5)).into() ]),
                    unobservable_external_inputs: false,
                    computation: None,
                },
                Flow {
                    target: Dest::Flags,
                    inputs: Inputs::sorted(vec! [ Dest::Reg(R1, Size::new(0, 3)).into(), Dest::Reg(R2, Size::new(0, 3)).into() ]),
                    unobservable_external_inputs: false,
                    computation: None,
                }
            ],
        };

        let encoding = Encoding {
            bits: vec! [
                BitKind::Value(0),
                BitKind::Value(0),
                BitKind::Fixed(0),
                BitKind::Value(1),
                BitKind::Value(1),
                BitKind::Value(1),
                BitKind::Fixed(1),
                BitKind::Fixed(1),

                BitKind::Fixed(1),
                BitKind::Fixed(0),
                BitKind::Fixed(0),
                BitKind::Value(0),
                BitKind::Fixed(0),
                BitKind::Fixed(0),
                BitKind::Fixed(0),
                BitKind::Fixed(0),
            ],
            dataflows,
            parts: vec! [
                Part {
                    size: 3,
                    value: 0b000,
                    mapping: PartMapping::Register {
                        mapping: vec! [Some(R0), Some(R1), Some(R2), Some(R3), None, Some(R4), Some(R5), Some(R6)], 
                        locations: vec! [
                            FlowValueLocation::Output(0), 
                            FlowValueLocation::InputForOutput { output_index: 0, input_index: 0 }, 
                            FlowValueLocation::InputForOutput { output_index: 2, input_index: 0 }
                        ]
                    },
                },
                Part {
                    size: 3,
                    value: 0b010,
                    mapping: PartMapping::Register {
                        mapping: vec! [Some(R0), Some(R1), Some(R2), Some(R3), Some(R4), Some(R5), Some(R6), Some(R7)], 
                        locations: vec! [
                            FlowValueLocation::InputForOutput { output_index: 0, input_index: 1 }, 
                            FlowValueLocation::InputForOutput { output_index: 2, input_index: 1 }
                        ]
                    }
                }
            ]
        };

        println!("Encoding: {}", encoding);

        let filters = encoding.filters();
        for filter in filters.iter() {
            println!("Filter: {:?}", filter);
        }

        assert_eq!(filters[0],
            InstructionFilter::new(vec![ ByteFilter::new(0b1111_1111, 0b0000_0001), ByteFilter::new(0b1100_0111, 0b1100_0000), ])
        );
        assert_eq!(filters[1],
            InstructionFilter::new(vec![ ByteFilter::new(0b1111_1111, 0b0000_0001), ByteFilter::new(0b1100_0111, 0b1100_0001), ])
        );
        assert_eq!(filters[2],
            InstructionFilter::new(vec![ ByteFilter::new(0b1111_1111, 0b0000_0001), ByteFilter::new(0b1100_0111, 0b1100_0010), ])
        );
        assert_eq!(filters[3],
            InstructionFilter::new(vec![ ByteFilter::new(0b1111_1111, 0b0000_0001), ByteFilter::new(0b1100_0111, 0b1100_0011), ])
        );
        assert_eq!(filters[4],
            InstructionFilter::new(vec![ ByteFilter::new(0b1111_1111, 0b0000_1001), ByteFilter::new(0b1100_0111, 0b1100_0001), ])
        );
        assert_eq!(filters[5],
            InstructionFilter::new(vec![ ByteFilter::new(0b1111_1111, 0b0000_1001), ByteFilter::new(0b1100_0111, 0b1100_0010), ])
        );
        assert_eq!(filters[6],
            InstructionFilter::new(vec![ ByteFilter::new(0b1111_1111, 0b0000_1001), ByteFilter::new(0b1100_0111, 0b1100_0011), ])
        );
    }

    #[test]
    pub fn split_flags_output() {
        let instr = Instr::new(&[ 0x01, 0xD0 ]);
        let mut encoding = Encoding {
            bits: vec! [
                BitKind::Value(0),
                BitKind::Value(0),
                BitKind::Fixed(0),
                BitKind::Value(1),
                BitKind::Value(1),
                BitKind::Value(1),
                BitKind::Fixed(1),
                BitKind::Fixed(1),

                BitKind::Fixed(1),
                BitKind::Fixed(0),
                BitKind::Fixed(0),
                BitKind::Value(0),
                BitKind::Fixed(0),
                BitKind::Fixed(0),
                BitKind::Fixed(0),
                BitKind::Fixed(0),
            ],
            dataflows: Dataflows::<FakeArch, crate::computation::BasicComputation> {
                addresses: MemoryAccesses {
                    instr: instr.into(),
                    memory: vec! [
                        MemoryAccess {
                            kind: AccessKind::Executable,
                            inputs: Inputs::sorted(vec! [ Dest::Reg(R0, Size::qword()).into() ]),
                            size: 2..2,
                            calculation: None,
                            alignment: 1,
                        }
                    ]
                },
                outputs: vec! [
                    Flow {
                        target: Dest::Reg(R1, Size::qword()),
                        inputs: Inputs::sorted(vec! [ Dest::Reg(R1, Size::new(0, 3)).into(), Dest::Reg(R2, Size::new(0, 3)).into(), Source::Imm(0), Source::Imm(1) ]),
                        unobservable_external_inputs: false,
                        computation: None,
                    },
                    Flow {
                        target: Dest::Flags,
                        inputs: Inputs::sorted(vec! [ Dest::Reg(R1, Size::new(0, 3)).into(), Dest::Reg(R2, Size::new(0, 3)).into(), Source::Imm(0) ]),
                        unobservable_external_inputs: false,
                        computation: None,
                    },
                    Flow {
                        target: Dest::Reg(R0, Size::qword()),
                        inputs: Inputs::sorted(vec! [ Dest::Reg(R0, Size::new(0, 5)).into(), Source::Imm(0) ]),
                        unobservable_external_inputs: false,
                        computation: None,
                    },
                ],
            },
            parts: vec! [
                Part {
                    size: 3,
                    value: 0b000,
                    mapping: PartMapping::ValueImm {
                        mapping: None, 
                        locations: vec! [
                            FlowValueLocation::InputForOutput { output_index: 0, input_index: 2 }, 
                            FlowValueLocation::InputForOutput { output_index: 1, input_index: 2 },
                            FlowValueLocation::InputForOutput { output_index: 2, input_index: 1 },
                        ]
                    },
                },
                Part {
                    size: 3,
                    value: 0b010,
                    mapping: PartMapping::ValueImm {
                        mapping: None, 
                        locations: vec! [
                            FlowValueLocation::InputForOutput { output_index: 0, input_index: 3 },
                        ]
                    }
                }
            ]
        };

        println!("Encoding: {}", encoding);

        encoding.split_flag_output();

        println!("After split: {}", encoding);

        assert_eq!(encoding, Encoding {
            bits: vec! [
                BitKind::Value(0),
                BitKind::Value(0),
                BitKind::Fixed(0),
                BitKind::Value(1),
                BitKind::Value(1),
                BitKind::Value(1),
                BitKind::Fixed(1),
                BitKind::Fixed(1),

                BitKind::Fixed(1),
                BitKind::Fixed(0),
                BitKind::Fixed(0),
                BitKind::Value(0),
                BitKind::Fixed(0),
                BitKind::Fixed(0),
                BitKind::Fixed(0),
                BitKind::Fixed(0),
            ],
            dataflows: Dataflows::<FakeArch, crate::computation::BasicComputation> {
                addresses: MemoryAccesses {
                    instr: instr.into(),
                    memory: vec! [
                        MemoryAccess {
                            kind: AccessKind::Executable,
                            inputs: Inputs::sorted(vec! [ Dest::Reg(R0, Size::qword()).into() ]),
                            size: 2..2,
                            calculation: None,
                            alignment: 1,
                        }
                    ]
                },
                outputs: vec! [
                    Flow {
                        target: Dest::Reg(R1, Size::qword()),
                        inputs: Inputs::unsorted(vec! [ Dest::Reg(R1, Size::new(0, 3)).into(), Dest::Reg(R2, Size::new(0, 3)).into(), Source::Imm(0), Source::Imm(1) ].into()),
                        unobservable_external_inputs: false,
                        computation: None,
                    },
                    Flow {
                        target: Dest::Reg(R0, Size::qword()),
                        inputs: Inputs::unsorted(vec! [ Dest::Reg(R0, Size::new(0, 5)).into(), Source::Imm(0) ].into()),
                        unobservable_external_inputs: false,
                        computation: None,
                    },
                    Flow {
                        target: Dest::Flag(F0),
                        inputs: Inputs::unsorted(vec! [ Dest::Reg(R1, Size::new(0, 3)).into(), Dest::Reg(R2, Size::new(0, 3)).into(), Source::Imm(0), Dest::Flag(F0).into() ]),
                        unobservable_external_inputs: false,
                        computation: None,
                    },
                    Flow {
                        target: Dest::Flag(F1),
                        inputs: Inputs::unsorted(vec! [ Dest::Reg(R1, Size::new(0, 3)).into(), Dest::Reg(R2, Size::new(0, 3)).into(), Source::Imm(0), Dest::Flag(F1).into() ]),
                        unobservable_external_inputs: false,
                        computation: None,
                    },
                    Flow {
                        target: Dest::Flag(F2),
                        inputs: Inputs::unsorted(vec! [ Dest::Reg(R1, Size::new(0, 3)).into(), Dest::Reg(R2, Size::new(0, 3)).into(), Source::Imm(0), Dest::Flag(F2).into() ]),
                        unobservable_external_inputs: false,
                        computation: None,
                    },
                ],
            },
            parts: vec! [
                Part {
                    size: 3,
                    value: 0b000,
                    mapping: PartMapping::ValueImm {
                        mapping: None, 
                        locations: vec! [
                            FlowValueLocation::InputForOutput { output_index: 0, input_index: 2 },
                            FlowValueLocation::InputForOutput { output_index: 1, input_index: 1 },
                            FlowValueLocation::InputForOutput { output_index: 2, input_index: 2 },
                            FlowValueLocation::InputForOutput { output_index: 3, input_index: 2 },
                            FlowValueLocation::InputForOutput { output_index: 4, input_index: 2 },
                        ]
                    },
                },
                Part {
                    size: 3,
                    value: 0b010,
                    mapping: PartMapping::ValueImm {
                        mapping: None, 
                        locations: vec! [
                            FlowValueLocation::InputForOutput { output_index: 0, input_index: 3 },
                        ]
                    }
                }
            ]
        })
    }
}