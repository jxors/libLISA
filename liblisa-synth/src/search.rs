use std::{collections::{HashMap, HashSet}, fmt, marker::PhantomData};
use itertools::Itertools;
use bumpalo::Bump;
use crate::gen::StepGenerator;

use super::gen::{Expr, ExprEnumerator};
use serde::{Serialize, Deserialize};
use log::{debug, trace};

#[derive(Clone, Serialize, Deserialize)]
pub struct SynthesisTable {
    pub choices: Vec<SynthesisChoice>,
    input_sizes: Vec<usize>,
    output_size: usize,
    pub decision_tree: Option<DecisionTree>,
    oks: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DecisionTree {
    pub predicates: Vec<Expr>,
    pub tree: Id3,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SynthesisChoice {
    pub expr: Expr,
    cases: Vec<Vec<u64>>,
}

impl SynthesisChoice {
    pub fn made_redundant_by(&self, expr: &Expr, output_size: usize) -> bool {
        for case in self.cases.iter() {
            if SynthesisTable::sized(output_size, expr.evaluate(&case)) != SynthesisTable::sized(output_size, self.expr.evaluate(&case)) {
                return false;
            }
        }

        true
    }
}

#[derive(Copy, Clone, Debug)]
enum AddAction {
    Ok,
    AddChoice(usize),
    SynthesizeNew,
}

#[derive(Copy, Clone, Debug)]
pub struct Check<'a> {
    inputs: &'a [u64], 
    output: u64,
    action: AddAction,
}

#[derive(PartialEq, Eq, Hash, Clone)]
struct Bitmap<'a> {
    data: &'a [u8]
}

impl<'a> Bitmap<'a> {
    pub fn create(data: &'a mut [u8], mut values: impl Iterator<Item = bool>) -> Self {
        let mut index = 0;
        'outer: loop {
            let mut b = 0;
            for n in 0..8 {
                if let Some(v) = values.next() {
                    b |= if v { 1 } else { 0 } << n;
                } else {
                    if n != 0 {
                        data[index] = b;
                    }

                    break 'outer;
                }
            }

            data[index] = b;
            index += 1;
        }

        Bitmap {
            data,
        }
    }

    pub fn get(&self, index: usize) -> bool {
        (self.data[index / 8] >> (index & 7)) & 1 == 1
    }

    pub fn clone_to<'b>(&self, data: &'b mut [u8]) -> Bitmap<'b> {
        data.copy_from_slice(self.data);
        Bitmap {
            data,
        }
    }
}

impl fmt::Display for Bitmap<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for n in 0..self.data.len() * 8 {
            f.write_str(if self.get(n) {
                "1"
            } else {
                "0"
            })?;
        }

        Ok(())
    }
}

impl<'a> Check<'a> {
    pub fn is_ok(&self) -> bool {
        matches!(self.action, AddAction::Ok)
    }
}

impl SynthesisTable {
    pub fn new(input_sizes: &[usize], output_size: usize) -> Self {
        SynthesisTable {
            choices: Vec::new(),
            input_sizes: input_sizes.iter().copied().collect(),
            output_size,
            decision_tree: None,
            oks: 0,
        }
    }

    pub fn clear(&mut self) {
        self.choices.clear();
        self.decision_tree = None;
        self.oks = 0;
    }

    pub fn input_sizes(&self) -> &[usize] {
        &self.input_sizes
    }

    fn sized(output_size: usize, value: i128) -> u64 {
        (value & ((1i128 << output_size) - 1)) as u64
    }

    pub fn has_good_tree(&self) -> bool {
        self.oks >= 50_000 && self.decision_tree.is_some()
    }

    pub fn has_tree(&self) -> bool {
        self.decision_tree.is_some()
    }

    pub fn tree(&self) -> Option<DecisionTree> {
        self.decision_tree.clone()
    }

    /// Checks the currently learned (partial?) decision tree against the new example. Returns a Check struct, which can be used to process() this new result.
    pub fn check<'a>(&self, inputs: &'a [u64], output: u64) -> Check<'a> {
        let had_decision_tree = if let Some(tree) = &self.decision_tree {
            let expr_index = tree.tree.decide(|predicate_index| {
                tree.predicates[predicate_index].evaluate(&inputs) == 0
            });

            let expected = Self::sized(self.output_size, self.choices[expr_index].expr.evaluate(&inputs));
            if expected == output {
                return Check {
                    inputs,
                    output,
                    action: AddAction::Ok,
                };
            }

            true
        } else {
            false
        };
        
        for (index, choice) in self.choices.iter().enumerate() {
            if Self::sized(self.output_size, choice.expr.evaluate(&inputs)) == output {
                if had_decision_tree {
                    // Our decision tree is incorrect, as demonstrated by this (inputs, output).
                    
                    return Check {
                        inputs,
                        output,
                        action: AddAction::AddChoice(index),
                    };
                } else {
                    return Check {
                        inputs,
                        output,
                        action: AddAction::Ok,
                    };
                }
            }
        }

        return Check {
            inputs,
            output,
            action: AddAction::SynthesizeNew,
        };
    }

    pub fn process(&mut self, check: Check<'_>) -> bool {
        let (inputs, output) = (check.inputs, check.output);

        match check.action {
            AddAction::Ok => {
                self.oks += 1;
    
                if self.oks >= 500 {
                    if self.decision_tree.is_none() {
                        debug!("Saw {} oks, trying to learn a decision tree", self.oks);
                        if !self.find_predicates() {
                            self.oks = 0;
                            debug!("Learning the decision tree failed");

                            return false;
                        } else {
                            debug!("Found: {}", self);
                        }
                    }
                }

                true
            },
            AddAction::AddChoice(index) => {
                self.oks = 0;
                self.decision_tree = None;
                self.choices[index].cases.push(check.inputs.to_vec());

                true
            }
            AddAction::SynthesizeNew => {
                self.oks = 0;
                self.decision_tree = None;

                trace!("Finding a new choice for {:X?} -> {:X}", inputs, output);
                let mut e = ExprEnumerator::new(&self.input_sizes, StepGenerator::new().steps(self.output_size <= 1));
                let mut has_found_choice = false;
                let mut remaining = 1_000_000_000usize;
                for n in 0..100_000_000_000usize {
                    if n % 10_000_000 == 1 {
                        trace!("{}M", n / 1_000_000);
                    }

                    if let Some(n) = remaining.checked_sub(1) {
                        remaining = n;
                    } else {
                        break
                    }
        
                    let expr = e.next();
                    if Self::sized(self.output_size, expr.evaluate(&inputs)) == output {
                        if !has_found_choice || self.choices.iter().filter(|c| c.made_redundant_by(expr, self.output_size)).count() >= 2 {
                            trace!("Adding a choice: {}", expr.display());
            
                            // Remove all choices that have become redundant
                            let output_size = self.output_size;
                            let mut cases = vec![
                                inputs.to_vec(),
                            ];
                            self.choices.retain(|choice| if choice.made_redundant_by(expr, output_size) {
                                trace!("{} made redundant", choice.expr.display());
                                cases.extend_from_slice(&choice.cases);

                                false
                            } else {
                                true
                            });
            
                            self.choices.push(SynthesisChoice {
                                expr: expr.clone(),
                                cases,
                            });

                            has_found_choice = true;
                            remaining = 100_000_000;
                            if self.choices.len() <= 1 {
                                break;
                            }
                        }
                    }
                }

                has_found_choice
            }
        }
    }

    pub fn find_predicates(&mut self) -> bool {
        // TODO: Cache predicates if we can
        trace!("Learning a decision tree with {:?}", self.choices.iter().map(|c| format!("{}", c.expr.display())).collect::<Vec<_>>());
        if self.choices.len() == 1 {
            self.decision_tree = Some(DecisionTree {
                predicates: Vec::new(),
                tree: Id3 {
                    tree: vec![
                        Id3Node::Leaf(0),
                    ],
                },
            });

            true
        } else {
            let mut e = ExprEnumerator::new(&self.input_sizes, StepGenerator::new().steps(false));
            let mut predicates = Vec::new();

            let alo = Bump::new();
            let num_examples = self.choices.iter().map(|c| c.cases.len()).sum::<usize>();
            let bitmap_bytes = (num_examples + 7) / 8;
            let mut tmp = alo.alloc_slice_fill_copy(bitmap_bytes, 0u8);
            let mut seen = HashSet::new();

            let cases = self.choices.iter().enumerate()
                .flat_map(|(choice_index, choice)| choice.cases.iter()
                    .map(move |case| (choice_index, case))
                ).collect::<Vec<_>>();
            let mut last_predicate_len = 0;
            for n in 0..100_000_000 {
                if n % 2_000_000 == 0 {
                    debug!("Predicates search: {:.1}M; {} predicates found", n as f64 / 1_000_000., predicates.len());
                }

                let expr = e.next();
                // map.get(case_n) == true iff expr.evaluate(case_n) == 0
                let map = Bitmap::create(&mut tmp, cases.iter()
                    .map(|(_, case)| expr.evaluate(case) == 0)
                );

                if !seen.contains(&map) {
                    trace!("Possible predicate: {} [{}]", expr.display(), map);
                    let map = map.clone_to(alo.alloc_slice_fill_copy(bitmap_bytes, 0u8));
                    predicates.push((expr.clone(), map.clone()));
                    seen.insert(map);
                }

                if n % 1_000_000 == 500_000 && predicates.len() > last_predicate_len {
                    last_predicate_len = predicates.len();
                    let entropy = |m: &HashMap<usize, usize>, sum: usize| -> f64 {
                        if m.len() == 1 {
                            0.
                        } else {
                            m.iter()
                                .map(|(_, &v)| {
                                    let p = v as f64 / sum as f64;
                                    p * p.log2()
                                })
                                .sum::<f64>() * -1.
                        }
                    };

                    let id3 = Id3::construct(
                        predicates.iter().enumerate().map(|(index, p)| (index, &p.1)).collect::<Vec<_>>(), 
                        cases.iter().enumerate().map(|(case_index, (choice_index, _))| (*choice_index, case_index)).collect::<Vec<_>>(),
                        |(choice_index, _)| *choice_index,
                        |(_, map), es| {
                            let mut yes = HashMap::new();
                            let mut no = HashMap::new();
                            let mut num_yes = 0;
                            let mut num_no = 0;
                            for (choice, case_index) in es.iter() {
                                if map.get(*case_index) {
                                    *yes.entry(*choice).or_insert(0) += 1;
                                    num_yes += 1;
                                } else {
                                    *no.entry(*choice).or_insert(0) += 1;
                                    num_no += 1;
                                }
                            }

                            let n = es.len() as f64;
                            let yes_rate = num_yes as f64 / n;
                            let no_rate = num_no as f64 / n;
                            // We don't compute the entropy of the entire set, since we don't need it to compare the information gain of the different attributes
                            let relative_gain = -1. * (yes_rate * entropy(&yes, num_yes) + no_rate * entropy(&no, num_no));

                            if num_yes == 0 || num_no == 0 {
                                f64::MIN
                            } else {
                                relative_gain
                            }
                        },
                        |(_, case_index), (_, map)| map.get(*case_index),
                        |(index, _)| *index
                    );

                    if let Ok(id3) = id3 {
                        let attributes_used = id3.attributes_used().copied().collect::<Vec<_>>();
                        let predicates = attributes_used.iter()
                            .map(|&index| predicates[index].0.clone())
                            .collect::<Vec<_>>();

                        let attribute_map = attributes_used.iter()
                            .copied()
                            .enumerate()
                            .map(|(new_index, original_index)| (original_index, new_index))
                            .collect::<HashMap<_, _>>();
                        let tree = {
                            let mut id3 = id3;
                            id3.map_attributes(&attribute_map);
                            id3
                        };

                        self.decision_tree = Some(DecisionTree {
                            predicates,
                            tree,
                        });

                        return true;
                    }
                }
            }

            false
        }
    }

    /// Get a reference to the synthesis table's oks.
    pub fn oks(&self) -> usize {
        self.oks
    }
}

impl fmt::Display for SynthesisTable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(table) = &self.decision_tree {
            let exprs = self.choices.iter().map(|c| format!("{}", c.expr.display())).collect::<Vec<_>>();
            let attributes = table.predicates.iter().map(|p| format!("{}", p.display())).collect::<Vec<_>>();

            write!(f, "{}", table.tree.display(&attributes, &exprs))
        } else {
            write!(f, "<incomplete with choices: {:?}>", self.choices)
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
enum Id3Node {
    Leaf(usize),
    /// The 'no' choice is stored at index + 1, the 'yes' choice is stored at `right`.
    Branch {
        attribute: usize,
        right: usize,
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Id3 {
    tree: Vec<Id3Node>
}

struct Id3Builder<P, E, FK: Fn(&E) -> usize, FE: Fn(&P, &[E]) -> f64, FH: Fn(&E, &P) -> bool, FI: Fn(&P) -> usize> {
    example_kind: FK,
    attribute_entropy: FE,
    example_has_attribute: FH,
    attribute_index: FI,
    tree: Vec<Id3Node>,
    _phantom: PhantomData<(P, E)>,
}

impl<P, E, FK: Fn(&E) -> usize, FE: Fn(&P, &[E]) -> f64, FH: Fn(&E, &P) -> bool, FI: Fn(&P) -> usize> Id3Builder<P, E, FK, FE, FH, FI> {
    fn best_attribute(&self, examples: &[E], attributes: &[P]) -> Result<usize, ()> {
        let mut best_gain = f64::MIN;
        let mut best_index = Err(());
        for (index, attribute) in attributes.iter().enumerate() {
            let gain = (self.attribute_entropy)(attribute, examples);
            if gain > best_gain {
                best_gain = gain;
                best_index = Ok(index);
            }
        }

        best_index
    }

    fn build(&mut self, attributes: &mut Vec<P>, examples: Vec<E>) -> Result<(), ()> {
        if examples.len() <= 0 {
            return Err(());
        }

        let k = (self.example_kind)(&examples[0]);
        if examples.iter().all(|e| (self.example_kind)(e) == k) {
            self.tree.push(Id3Node::Leaf(k));
        } else {
            let best_attribute_index = self.best_attribute(&examples, &attributes)?;
            let attribute = attributes.remove(best_attribute_index);

            let index = self.tree.len();
            self.tree.push(Id3Node::Branch {
                attribute: (self.attribute_index)(&attribute),
                right: 0,
            });

            let (left, right) = examples.into_iter().partition(|e| !(self.example_has_attribute)(e, &attribute));
            self.build(attributes, left)?;

            let len = self.tree.len();
            match &mut self.tree[index] {
                Id3Node::Branch { right, .. } => *right = len,
                _ => unreachable!(),
            }

            self.build(attributes, right)?;
        }

        Ok(())
    }
}

impl fmt::Debug for Id3 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.fmt_node(0, 0, f)
    }
}

pub struct DisplayId3<'a> {
    id3: &'a Id3,
    attributes: &'a [String],
    exprs: &'a [String],
}

impl DisplayId3<'_> {
    fn fmt_node(&self, index: usize, depth: usize, node_kind: &'static str, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.id3.tree[index] {
            Id3Node::Leaf(n) => write!(f, "{}{}{}", " ".repeat(depth * 4), node_kind, self.exprs[*n]),
            Id3Node::Branch { attribute, right } => {
                writeln!(f, "{}{}choose {}", " ".repeat(depth * 4), node_kind, self.attributes[*attribute])?;
                self.fmt_node(index + 1, depth + 1, "!=0: ", f)?;
                writeln!(f)?;
                self.fmt_node(*right, depth + 1, "==0: ", f)
            }
        }
    }
}

impl fmt::Display for DisplayId3<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.fmt_node(0, 0, "", f)
    }
}

impl Id3 {
    pub fn construct<P, E>(mut attributes: Vec<P>, examples: Vec<E>, example_kind: impl Fn(&E) -> usize, attribute_entropy: impl Fn(&P, &[E]) -> f64, example_has_attribute: impl Fn(&E, &P) -> bool, attribute_index: impl Fn(&P) -> usize) -> Result<Id3, ()> {
        let mut builder = Id3Builder {
            example_kind,
            attribute_entropy,
            example_has_attribute,
            attribute_index,
            tree: Vec::new(),
            _phantom: PhantomData,
        };

        builder.build(&mut attributes, examples)?;

        Ok(Id3 {
            tree: builder.tree,
        })
    }

    pub fn empty(default_index: usize) -> Id3 {
        Id3 {
            tree: vec![ Id3Node::Leaf(default_index) ],
        }
    }

    fn fmt_node(&self, index: usize, depth: usize, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.tree[index] {
            Id3Node::Leaf(n) => writeln!(f, "{}- {}", " ".repeat(depth * 4), n),
            Id3Node::Branch { attribute, right } => {
                writeln!(f, "{}[?] attribute[{}]", " ".repeat(depth * 4), attribute)?;
                self.fmt_node(index + 1, depth + 1, f)?;
                self.fmt_node(*right, depth + 1, f)
            }
        }
    }

    pub fn display<'a>(&'a self, attributes: &'a [String], exprs: &'a [String]) -> DisplayId3<'a> {
        DisplayId3 {
            id3: self,
            attributes,
            exprs,
        }
    }

    pub fn attributes_used<'a>(&'a self) -> impl Iterator<Item = &'a usize> {
        self.tree.iter()
            .flat_map(|n| match n {
                Id3Node::Leaf(_) => None,
                Id3Node::Branch { attribute, .. } => Some(attribute),
            })
            .unique()
    }

    pub fn map_attributes(&mut self, attribute_map: &HashMap<usize, usize>) {
        for node in self.tree.iter_mut() {
            match node {
                Id3Node::Leaf(_) => {}
                Id3Node::Branch { attribute, .. } => *attribute = attribute_map[attribute],
            }
        }
    }

    pub fn decide(&self, f: impl Fn(usize) -> bool) -> usize {
        let mut index = 0;
        loop {
            match &self.tree[index] {
                Id3Node::Leaf(n) => return *n,
                Id3Node::Branch { attribute, right } => index = if f(*attribute) {
                    *right
                } else {
                    index + 1
                },
            }
        }
    }
}

impl fmt::Debug for SynthesisTable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut d = f.debug_list();

        for choice in self.choices.iter() {
            d.entry(&choice.expr.display());
        }

        d.finish()
    }
}

#[allow(unused)]
#[cfg(test)]
mod tests {
    use liblisa_core::randomized_value;
    use rand::Rng;
    use super::{Bitmap, Id3, SynthesisTable};
    use test_env_log::test;

    fn cases(output_size: usize, input_sizes: &[usize], f: impl Fn(&[u64]) -> u64) -> SynthesisTable {
        let mut table = SynthesisTable::new(input_sizes, output_size);
        let mut rng = rand::thread_rng();
        for i in 0..1_000_000 {
            let inputs = input_sizes.iter().map(|&s| randomized_value(&mut rng) & ((1u128 << s) - 1) as u64).collect::<Vec<u64>>();
            let output = f(&inputs);
            let check = table.check(&inputs, output);
            table.process(check);
            
            if i % 100_000 == 0 {
                println!("{}k", i / 1000);
            }
        }

        assert!(table.has_good_tree());
        println!("Found table: {}", table);
        
        table
    }

    #[test]
    pub fn id3() {
        let id3 = Id3::construct(
            vec![ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 ], 
            vec![ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 ],
            |&e| if e < 5 { 0 } else { 1 },
            |attr, es| 5. - ((5 - attr) as f64).abs(),
            |&e, attr| e < *attr,
            |n| *n
        );
        println!("{:?}", id3);


        let id3 = Id3::construct(
            vec![ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 ], 
            vec![ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 ],
            |&e| if e < 5 { 0 } else { 1 },
            |attr, es| 5. - ((5 - attr) as f64).abs(),
            |&e, attr| e == *attr,
            |n| *n
        );
        println!("{:?}", id3);
    }

    #[test]
    pub fn array_indexing() {
        let table = cases(64, &[ 64, 64 ], |x| x[0] + x[1] * 8);
    }

    #[test]
    pub fn sub_const() {
        let table = cases(64, &[ 64 ], |x| x[0] - 32);
    }

    #[test]
    pub fn conditional() {
        let table = cases(64, &[ 64, 64 ], |x| if x[0] < 32 {
            x[0] + x[1]
        } else {
            x[0].checked_div(x[1]).unwrap_or(0)
        });
    }

    #[test]
    pub fn add_parity() {
        let table = cases(1, &[ 64, 64 ], |x| (x[0].wrapping_add(x[1]) & 0xFF).count_ones() as u64 & 1);
    }

    #[test]
    pub fn memory_addresses() {
        cases(64, &[ 64, 64, 2 ], |x| match x[2] {
            0 => x[0].wrapping_add(x[1].wrapping_mul(1)),
            1 => x[0].wrapping_add(x[1].wrapping_mul(2)),
            2 => x[0].wrapping_add(x[1].wrapping_mul(4)),
            3 => x[0].wrapping_add(x[1].wrapping_mul(8)),
            _ => unreachable!(),
        });
    }

    #[test]
    pub fn overflow() {
        let mut table = cases(64, &[ 64, 64 ], |x| x[0].checked_add(x[1]).map(|_| 0).unwrap_or(1));

    }

    #[test]
    pub fn shl_nowrapping() {
        let mut table = cases(64, &[ 64, 64 ], |x| x[0].checked_shl(x[1] as u32).unwrap_or(0));
    }

    #[test]
    pub fn shl_wrapping() {
        let mut table = cases(64, &[ 64, 64 ], |x| x[0].wrapping_shl(x[1] as u32));
    }

    #[test]
    pub fn jmp_cc() {
        // If x[0] == 0, we jump to x[2], otherwise we increase the IP by 6
        let mut table = cases(64, &[ 64, 64, 64 ], |x| if x[0] == 0 {
            x[1].wrapping_add(x[2])
        } else {
            x[1].wrapping_add(6)
        });
    }

    #[test_env_log::test]
    pub fn carry_sbb() {
        // Checks if (x0 - x1 - c) carries
        cases(1, &[ 64, 64, 1, 1 ], |x| x[0].checked_sub(x[1]).map(|n| n.checked_sub(x[2])).flatten().map(|_| 0).unwrap_or(1));

        // Checks if 32-bit (x0 - x1 - c) carries
        cases(1, &[ 32, 32, 1, 1 ], |x| (x[0] as u32).checked_sub(x[1] as u32).map(|n| n.checked_sub(x[2] as u32)).flatten().map(|_| 0).unwrap_or(1));

        // Different way to check if 32-bit (x0 - x1 - c) carries
        cases(1, &[ 32, 32, 1, 1 ], |x| if (x[0].wrapping_sub(x[1]).wrapping_sub(x[2]) >> 32) == 0 { 0 } else { 1 });
    }

    #[test_env_log::test]
    pub fn overflow_sbb() {
        // Check if 32-bit (x0 - x1 - c) overflows
        cases(1, &[ 32, 32, 1, 1 ], |x| {
            let result = x[0].wrapping_sub(x[1]).wrapping_sub(x[2]);

            let a = x[0] >> 31;
            let b = x[1] >> 31;
            let r = (result >> 31) & 1;

            // 1 if and only if the sign bit on both inputs was the same, and the sign bit changed for the result
            !(a ^ b) & (r ^ a)
        });
    }

    #[test_env_log::test]
    pub fn overflow_add() {
        // Check if 32-bit (x0 + x1) overflows
        cases(1, &[ 32, 32, 1 ], |x| {
            let result = x[0].wrapping_add(x[1]);

            let a = x[0] >> 31;
            let b = x[1] >> 31;
            let r = (result >> 31) & 1;

            // 1 if and only if the sign bit on both inputs was the same, and the sign bit changed for the result
            !(a ^ b) & (r ^ a)
        });
    }

    #[test_env_log::test]
    pub fn add_sign() {
        // Checks if 32-bit (x0 + x1) is negative
        cases(1, &[ 32, 32, 1 ], |x| ((x[0] as u32).wrapping_add(x[1] as u32) >> 31) as u64);
    }

    #[test_env_log::test]
    pub fn zero_adc() {
        // Checks if (x0 - x1 - c) overflows
        cases(1, &[ 64, 64, 1, 1 ], |x| if x[0].wrapping_add(x[1].wrapping_add(x[2])) == 0 {
            1
        } else {
            0
        });
    }

    #[test]
    pub fn pre_1_10() {
        // CVC4 says: (im (bvand #b0000000000000000000000000000000000000000000000000000000000000001 (bvnot x)) (smol (bvxor x (arba x))) (smol x)))
        // = if (x & 1 == 0) then (x xor (x >> 4)) << 1 else x << 1
        let mut table = SynthesisTable::new(&[ 64 ], 64);
        for (inputs, output) in &[
            (&[ 0x6bedbd49e6e3b640 ], 0xdaa6cd3af11b1a48),
            (&[ 0x3433b756b98b2a5b ], 0x68676ead731654b6),
            (&[ 0x3166448e9564eb01 ], 0x62cc891d2ac9d602),
        ] {
            let check = table.check(*inputs, *output);
            table.process(check);
        }
    }

    #[test]
    pub fn bitmap_create() {
        let mut data = [0u8; 4];
        let mut b = Bitmap::create(&mut data, (0..32).map(|n| n % 3 == 0 && n % 12 != 0));

        for n in 0..32 {
            assert_eq!(b.get(n), n % 3 == 0 && n % 12 != 0);
        }
    }
}