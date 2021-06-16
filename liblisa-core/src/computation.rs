use std::fmt::{Debug, Display};
use crate::{GetDest, Inputs, Source, Value};
use crate::arch::{SystemState, Arch};
use serde::{Serialize, Deserialize};
pub trait Computation: Debug + Clone {
    type D: Display;

    fn compute<A: Arch>(&self, inputs: &Inputs<A>, state: &SystemState<A>) -> u64 {
        let mut values = Vec::new();
        for input in inputs.iter() {
            let v = match input {
                Source::Dest(d) => state.get_dest(d, |v| match v {
                    Value::Num(n) => *n,
                    _ => 0,
                }),
                Source::Const { value, .. } => *value,
                Source::Imm { .. } => panic!("Cannot evaluate an expression that contains immediate value references"),
            };

            values.push(v);
        }

        self.evaluate(&values)
    }

    fn evaluate(&self, inputs: &[u64]) -> u64;
    fn display<'a, S: AsRef<str>>(&self, input_names: &[S]) -> Self::D;
}


#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize, PartialOrd, Ord, Hash)]
pub struct BasicComputation {
    pub offset: i64,
    pub scale: u64,
    pub scaled_index: usize,
}

impl Computation for BasicComputation {
    type D = DisplayBasicComputation;

    fn compute<A: Arch>(&self, inputs: &Inputs<A>, state: &SystemState<A>) -> u64 {
        let mut sum = 0u64;
        for (index, input) in inputs.iter().enumerate() {
            let v = match input {
                Source::Dest(d) => state.get_dest(d, |v| match v {
                    Value::Num(n) => *n,
                    _ => 0,
                }),
                Source::Const { value, .. } => *value,
                Source::Imm { .. } => panic!("Cannot evaluate an expression that contains immediate value references"),
            };

            if index == self.scaled_index {
                sum = sum.wrapping_add(v.wrapping_mul(self.scale));
            } else {
                sum = sum.wrapping_add(v);
            }
        }

        sum.wrapping_add(self.offset as u64)
    }

    fn evaluate(&self, inputs: &[u64]) -> u64 {
        let mut sum = 0u64;
        for (index, &v) in inputs.iter().enumerate() {
            if index == self.scaled_index {
                sum = sum.wrapping_add(v.wrapping_mul(self.scale));
            } else {
                sum = sum.wrapping_add(v);
            }
        }

        sum.wrapping_add(self.offset as u64)
    }

    fn display<S: AsRef<str>>(&self, input_names: &[S]) -> Self::D {
        DisplayBasicComputation {
            calculation: self.clone(),
            inputs: input_names.iter().map(|n| n.as_ref().to_string()).collect::<Vec<_>>(),
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct DisplayBasicComputation {
    calculation: BasicComputation,
    inputs: Vec<String>,
}

impl Display for DisplayBasicComputation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for (index, input) in self.inputs.iter().enumerate() {
            if self.calculation.scaled_index == index && self.calculation.scale != 1 {
                write!(f, "{} * ", self.calculation.scale)?;
            }

            write!(f, "{} + ", input)?;
        }

        if self.calculation.offset < 0 {
            write!(f, "-0x{:X}", -self.calculation.offset)?;
        } else {
            write!(f, "0x{:X}", self.calculation.offset)?;
        }

        Ok(())
    }
}

impl BasicComputation {
    pub fn offset(&self, offset: i64) -> BasicComputation {
        BasicComputation {
            offset: self.offset + offset,
            scale: self.scale,
            scaled_index: self.scaled_index,
        }
    }

    pub fn unscaled_sum() -> BasicComputation {
        BasicComputation {
            offset: 0,
            scale: 1,
            scaled_index: 0,
        }
    }

    pub fn new_with_inferred_offset<A: Arch>(scale: u64, scaled_index: usize, inputs: &Inputs<A>, state: &SystemState<A>, expected: u64) -> BasicComputation {
        let mut result = BasicComputation {
            scale,
            scaled_index,
            offset: 0,
        };

        let actual = result.compute(inputs, state);
        result.offset = expected.wrapping_sub(actual) as i64;

        result
    }

    /// Returns the fixed difference (other - self) between two address calculations, if they are given the same inputs
    pub fn constant_offset_with(&self, other: &BasicComputation) -> Option<i64> {
        if self.scale == other.scale && self.scaled_index == other.scaled_index {
            Some(other.offset.wrapping_sub(self.offset) as i64)
        } else {
            None
        }
    }
}
