use std::fmt::{Debug, Display};
use crate::Computation;
use crate::GetDest;
use crate::arch::SystemState;
use crate::arch::Value;
use crate::{arch::{Arch, Flag, Instruction, Instr, InstructionInfo}, accesses::{AccessKind, MemoryAccesses, MemoryAccess}};
use super::{Dest, FlowInputLocation, FlowOutputLocation, FlowValueLocation, Inputs, Location, Source};
use serde::{Serialize, Deserialize};
use std::ops::{Index, IndexMut};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Dataflows<A: Arch, C: Computation> {
    pub addresses: MemoryAccesses<A, C>,
    pub outputs: Vec<Flow<A, C>>,
}

fn none<T>() -> Option<T> { None }

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Flow<A: Arch, C: Computation> {
    pub target: Dest<A>,
    pub inputs: Inputs<A>,

    #[serde(default = "none")]
    pub computation: Option<C>,

    #[serde(default)]
    pub unobservable_external_inputs: bool,
}

impl<A: Arch, C: Computation> Flow<A, C> {
    pub fn inputs(&self) -> &Inputs<A> {
        &self.inputs
    }

    pub fn target(&self) -> &Dest<A> {
        &self.target
    }
}

impl<A: Arch, C: Computation> Index<usize> for Dataflows<A, C> {
    type Output = Flow<A, C>;

    fn index(&self, index: usize) -> &Flow<A, C> {
        &self.outputs[index]
    }
}

impl<A: Arch, C: Computation> IndexMut<usize> for Dataflows<A, C> {
    fn index_mut(&mut self, index: usize) -> &mut Flow<A, C> {
        &mut self.outputs[index]
    }
}

impl<A: Arch, C: Computation> Debug for Flow<A, C> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[{:?}] <= {{ ", self.target)?;

        for input in self.inputs.iter() {
            write!(f, "{:?} ", input)?;
        }

        write!(f, "}}")?;

        Ok(())
    }
}

impl<A: Arch + 'static, C: Computation> Dataflows<A, C> {
    pub fn instr(&self) -> Instr<'_> {
        self.addresses.instr.as_instr()
    }

    pub fn output_dataflows(&self) -> impl Iterator<Item = &Flow<A, C>> {
        self.outputs.iter()
    }

    pub fn address_dataflows(&self) -> impl Iterator<Item = &MemoryAccess<A, C>> {
        self.addresses.iter()
    }

    pub fn iter_with_locations<'a>(&'a self) -> impl Iterator<Item = FlowGroup<'a, A, C>> {
        self.addresses.iter().enumerate()
            .map(|(memory_index, ma)| FlowGroup {
                inputs: &ma.inputs,
                target: None,
                location: FlowOutputLocation::MemoryAccess(memory_index),
                computation: ma.calculation.as_ref(),
            })
            .chain(
                self.outputs.iter().enumerate()
                    .map(|(output_index, output)| FlowGroup {
                        inputs: &output.inputs,
                        target: Some(&output.target),
                        location: FlowOutputLocation::Output(output_index),
                        computation: output.computation.as_ref(),
                    })
            )
    }

    pub fn inputs(&self) -> impl Iterator<Item = (FlowInputLocation, &Source<A>)> {
        self.iter_with_locations().flat_map(|g| g.iter_with_locations())
    }

    pub fn outputs(&self) -> impl Iterator<Item = (FlowOutputLocation, Option<&Dest<A>>)> {
        self.iter_with_locations().map(|g| (g.location(), g.target()))
    }

    pub fn values(&self) -> impl Iterator<Item = (FlowValueLocation, Source<A>)> + '_ {
        self.inputs().map(|(loc, input)| (loc.into(), input.clone()))
            .chain(self.outputs().map(|x| match x {
                (FlowOutputLocation::Output(output_index), Some(dest)) => Some((FlowValueLocation::Output(output_index), Source::Dest(dest.clone()))),
                (FlowOutputLocation::MemoryAccess(_), None) => None,
                _ => unreachable!(),
            }).flatten())
    }

    pub fn get(&self, loc: &Location<A>) -> Option<&Flow<A, C>> {
        self.outputs.iter().filter(|flow| &flow.target == loc).next()
    }

    pub fn insert_value(&mut self, locations: impl Iterator<Item = FlowOutputLocation>, new_value: Source<A>) -> Vec<FlowInputLocation> {
        let mut result = Vec::new();
        for location in locations {
            let values = match location {
                FlowOutputLocation::Output(index) => &mut self.outputs[index].inputs,
                FlowOutputLocation::MemoryAccess(index) => {
                    self.addresses[index].calculation = None;
                    
                    &mut self.addresses[index].inputs
                },
            };

            result.push(location.input(values.len()));
            values.push(new_value.clone());
        }

        result
    }

    pub fn execute(&self, state: &mut SystemState<A>) {
        // TODO: Verify addresses are mapped correctly
        let outputs = self.outputs.iter()
            .map(|flow| {
                let inputs = flow.inputs.iter()
                    .map(|input| match input {
                        Source::Dest(dest) => state.get_dest(dest, |value| match value {
                            Value::Num(n) => *n,
                            Value::Bytes(b) => if b.len() > 8 {
                                unimplemented!()
                            } else {
                                b.iter().enumerate().fold(0, |acc, (index, value)| acc | (*value as u64) << (index * 8))
                            },
                            Value::FlagBitmap(f) => *f,
                        }),
                        Source::Imm(_) => panic!("No imms should be here"),
                        Source::Const { value, .. } => *value,
                    })
                    .collect::<Vec<_>>();
                (flow.target.clone(), flow.computation.as_ref().unwrap().evaluate(&inputs))
            })
            .collect::<Vec<_>>();
        
        for (target, value) in outputs {
            let bytes;
            state.set_dest(&target, &match &target {
                Dest::Mem(_, size) => {
                    bytes = value.to_le_bytes();
                    Value::Bytes(&bytes[0..size.len()])
                },
                _ => Value::Num(value),
            });
        }
    }

    pub fn map<E>(&self, instr: Instruction, f: impl Fn(FlowValueLocation, &Source<A>) -> Result<Option<Source<A>>, E>) -> Result<Dataflows<A, C>, E> {
        let addresses = self.addresses.map(instr, &f)?;
        let outputs = self.outputs.iter().enumerate()
            .map(|(output_index, flow)| Ok(Flow {
                target: f(FlowValueLocation::Output(output_index), &Source::Dest(flow.target.clone()))?.unwrap().unwrap_dest(),
                inputs: Inputs::unsorted(flow.inputs.iter().enumerate()
                    .map(|(input_index, input)| f(FlowValueLocation::InputForOutput {
                        output_index,
                        input_index,
                    }, input))
                    .flat_map(|v| match v {
                        Ok(Some(v)) => Some(Ok(v)),
                        Ok(None) => None,
                        Err(e) => Some(Err(e)),
                    })
                    .collect::<Result<Vec<_>, E>>()?),
                unobservable_external_inputs: flow.unobservable_external_inputs,
                computation: flow.computation.clone(),
            }))
            .collect::<Result<Vec<_>, E>>()?;
        
        Ok(Dataflows {
            addresses,
            outputs,
        })
    }

    pub fn map_computations<CNew: Computation>(&self, f: impl Fn(&Inputs<A>, &C) -> CNew) -> Dataflows<A, CNew> {
        let addresses = self.addresses.map_computations(&f);
        let outputs = self.outputs.iter()
            .map(|flow| Flow {
                target: flow.target.clone(),
                inputs: flow.inputs.clone(),
                unobservable_external_inputs: flow.unobservable_external_inputs,
                computation: flow.computation.as_ref().map(|c| f(&flow.inputs, c)),
            })
            .collect();
        
        Dataflows {
            addresses,
            outputs,
        }
    }

    pub fn split_flag_output(&mut self) -> usize {
        let mut new_outputs = Vec::new();
        self.outputs.retain(|output| {
            match output.target {
                Dest::Flags => {
                    for flag in A::Flag::iter() {
                        let mut inputs = output.inputs.clone();
                        let s = Source::Dest(Dest::Flag(flag.clone()));
                        if !inputs.inputs.contains(&s) {
                            inputs.push(s);
                        }

                        new_outputs.push(Flow {
                            target: Dest::Flag(flag),
                            inputs,
                            unobservable_external_inputs: output.unobservable_external_inputs,
                            computation: None,
                        });
                    }
                    
                    false
                },
                _ => true, 
            }
        });

        let num = new_outputs.len();
        self.outputs.append(&mut new_outputs);

        num
    }
}

pub struct FlowGroup<'a, A: Arch, C: Computation> {
    inputs: &'a Inputs<A>,
    target: Option<&'a Dest<A>>,
    location: FlowOutputLocation,
    computation: Option<&'a C>,
}

impl<'a, A: Arch, C: Computation> FlowGroup<'a, A, C> {
    pub fn iter(&self) -> impl Iterator<Item = &Source<A>> {
        self.inputs.iter()
    }

    pub fn location(&self) -> FlowOutputLocation {
        self.location
    }

    pub fn iter_with_locations(&self) -> impl Iterator<Item = (FlowInputLocation, &'a Source<A>)> {
        let location = self.location;
        self.inputs.iter().enumerate().map(move |(index, el)| (location.input(index), el))
    }

    pub fn target(&self) -> Option<&'a Dest<A>> {
        self.target
    }

    pub fn computation(&self) -> Option<&'a C> {
        self.computation
    }
}

impl<A: Arch + 'static, C: Computation> Display for Dataflows<A, C> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(
            f,
            "{:?} {:02X?}",
            self.instr(),
            self.instr().bytes()
        )?;

        for (index, access) in self.addresses.iter().enumerate() {
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
                access.inputs
            )?;
        }

        for output in self.output_dataflows() {
            writeln!(
                f,
                "{:10} = {}",
                format!("{}", output.target.clone()),
                output.inputs
            )?;
        }

        Ok(())
    }
}
