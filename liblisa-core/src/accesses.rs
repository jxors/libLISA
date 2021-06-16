use std::{fmt::{Debug, Display}, ops::{Index, IndexMut, Range}};
use serde::{Serialize, Deserialize};
use crate::{arch::{Arch, Instruction, SystemState}, oracle::OracleError};
use crate::{FlowValueLocation, Inputs, Location, Source, Computation};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemoryAccesses<A: Arch, C: Computation> {
    pub instr: Instruction,
    pub memory: Vec<MemoryAccess<A, C>>,
}

impl<A: Arch, C: Computation> Index<usize> for MemoryAccesses<A, C> {
    type Output = MemoryAccess<A, C>;

    fn index(&self, index: usize) -> &MemoryAccess<A, C> {
        &self.memory[index]
    }
}

impl<A: Arch, C: Computation> IndexMut<usize> for MemoryAccesses<A, C> {
    fn index_mut(&mut self, index: usize) -> &mut MemoryAccess<A, C> {
        &mut self.memory[index]
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AccessKind {
    Input,
    InputOutput,
    Executable,
}

fn none<T>() -> Option<T> { None }

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemoryAccess<A: Arch, C: Computation> {
    pub kind: AccessKind,
    pub inputs: Inputs<A>,
    pub size: Range<usize>,

    #[serde(default = "none")]
    /// A simple expression for the calculation of the address of the form i1 + i2 + .. + i_k * c + i_k+1 + i_k+1 .. i_n + c.
    /// That is, all inputs are summed, one input can be multiplied by a certain factor, which is then offset by a constant value c.
    /// This allows for the computation of most common addresses. It speeds up enumeration by ~20% on average up to ~40% in extreme 
    /// cases. Obviously the speedup gets bigger if the amount of memory accesses increases or if the number of randomize_new() and
    /// adapt() calls is greater.
    pub calculation: Option<C>,

    #[serde(default = "default_alignment")]
    /// An alignment of 1 means that every address is OK. An alignment of 2 means that only addresses of the form 2n are ok. 
    /// An alignment of 4 means that addresses of the form 4n are OK. Etc.
    /// WARNING: Only powers of 2 are acceptable values. Setting an alignment of, for example, 5, will give you randomly aligned states.
    pub alignment: usize,
}

fn default_alignment() -> usize { 1 }

impl<A: Arch, C: Computation> MemoryAccess<A, C> {
    pub fn inputs(&self) -> &Inputs<A> {
        &self.inputs
    }

    pub fn compute_address(&self, state: &SystemState<A>) -> Option<u64> {
        self.calculation.as_ref().map(|calculation| {
            calculation.compute(&self.inputs, state)
        })
    }

    pub fn compute_memory_access(&self, state: &SystemState<A>) -> Option<OracleError> {
        self.calculation.as_ref().map(|calculation| {
            let addr = calculation.compute(&self.inputs, state);
            // This computes the bit mask of bits that must be set to 0 for the alignment to be OK.
            // Only powers of 2 are supported. Anything else breaks.
            let align_bits = addr & (self.alignment as u64 - 1);
            if align_bits != 0 {
                OracleError::GeneralFault
            } else {
                OracleError::MemoryAccess(addr)
            }
        })
    }
}

impl<A: Arch + 'static, C: Computation> MemoryAccesses<A, C> {
    pub fn max_size_of(&self, location: &Location<A>) -> usize {
        match location {
            Location::Reg(_) => 8,
            Location::Memory(index) => self.memory[*index].size.end,
            Location::Flags => 8,
            Location::Flag(_) => 1,
        }
    }

    pub fn slice(&self, length: usize) -> MemoryAccesses<A, C> {
        MemoryAccesses {
            instr: self.instr.clone(),
            memory: self.memory[..length].to_vec(),
        }
    }

    pub fn iter(&self) -> impl Iterator<Item = &MemoryAccess<A, C>> {
        self.memory.iter()
    }

    pub fn len(&self) -> usize {
        self.memory.len()
    }

    pub fn map<E>(&self, instr: Instruction, f: impl Fn(FlowValueLocation, &Source<A>) -> Result<Option<Source<A>>, E>) -> Result<MemoryAccesses<A, C>, E> {
        Ok(MemoryAccesses {
            instr,
            memory: self.memory.iter().enumerate()
                .map(|(memory_index, ma)| {
                    let inputs = Inputs::unsorted(ma.inputs.iter().enumerate()
                        .map(|(input_index, input)| f(FlowValueLocation::MemoryAddress {
                            memory_index,
                            input_index,
                        }, input))
                        .flat_map(|v| match v {
                            Ok(Some(v)) => Some(Ok(v)),
                            Ok(None) => None,
                            Err(e) => Some(Err(e)),
                        })
                        .collect::<Result<Vec<_>, E>>()?);

                    Ok(MemoryAccess {
                        kind: ma.kind,
                        size: ma.size.clone(),
                        // We keep the calculation if the number of inputs remains the same
                        calculation: if ma.inputs.len() == inputs.len() {
                            ma.calculation.clone()
                        } else {
                            None
                        },
                        inputs,
                        alignment: ma.alignment,
                    })
                })
                .collect::<Result<Vec<_>, E>>()?,
        })
    }

    pub fn map_computations<CNew: Computation>(&self, f: impl Fn(&Inputs<A>, &C) -> CNew) -> MemoryAccesses<A, CNew> {
        MemoryAccesses {
            instr: self.instr.clone(),
            memory: self.memory.iter()
                .map(|ma| MemoryAccess {
                    kind: ma.kind,
                    size: ma.size.clone(),
                    calculation: ma.calculation.as_ref().map(|c| f(&ma.inputs, c)),
                    inputs: ma.inputs.clone(),
                    alignment: ma.alignment.clone(),
                })
                .collect(),
        }
    }
}

impl Display for AccessKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AccessKind::Input => f.write_str("input"),
            AccessKind::InputOutput => f.write_str("input/output"),
            AccessKind::Executable => f.write_str("executable"),
        }
    }
}

impl<A: Arch, C: Computation> Display for MemoryAccesses<A, C> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[")?;

        for (index, constraint) in self.memory.iter().enumerate() {
            write!(f, "{}", constraint)?;
            if index != self.memory.len() - 1 {
                write!(f, ", ")?;
            }
        }

        write!(f, "]")?;

        Ok(())
    }
}

impl<A: Arch, C: Computation> Display for MemoryAccess<A, C> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} ", self.kind)?;

        if let Some(calculation) = &self.calculation {
            write!(f, "= ")?;

            let input_names = self.inputs.iter().map(|i| format!("{}", i)).collect::<Vec<_>>();
            write!(f, "{}", calculation.display(&input_names))?;
        } else {
            write!(f, "via {:?}", self.inputs)?;
        }

        Ok(())
    }   
}