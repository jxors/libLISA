use std::{collections::HashMap, sync::Mutex};
use liblisa_core::oracle::Oracle;
use liblisa_core::arch::{Arch, Instr, Instruction};
use liblisa_core::accesses::MemoryAccesses;
use liblisa_core::dataflow::Dataflows;
use liblisa_core::computation::BasicComputation;
use crate::accesses::{MemoryAccessAnalysis, ConstraintAnalysisError};
use crate::dataflow::{DataflowAnalysis, DataflowError};

pub struct Cache<T: Clone> {
    data: Mutex<HashMap<Instruction, T>>,
}

impl<T: Clone> Cache<T> {
    pub fn new() -> Cache<T> {
        Cache { 
            data: Mutex::new(HashMap::new()),
        }
    }

    pub fn get_or_insert<I: Into<Instruction>>(&self, instruction: I, mut f: impl FnMut() -> T) -> T {
        let instruction = instruction.into();
        let lock = self.data.lock().unwrap();
        if let Some(result) = lock.get(&instruction) {
            result.clone()
        } else {
            drop(lock);
            let new = f();
            let mut lock = self.data.lock().unwrap();
            lock.insert(instruction, new.clone());
            new
        }
    }
}

pub struct CombinedCache<A: Arch> {
    constraints: Cache<Result<MemoryAccesses<A, BasicComputation>, ConstraintAnalysisError<A>>>,
    dataflow: Cache<Result<Dataflows<A, BasicComputation>, DataflowError<A>>>,
}

impl<A: Arch + 'static> CombinedCache<A> {
    pub fn new() -> CombinedCache<A> {
        CombinedCache { 
            constraints: Cache::new(),
            dataflow: Cache::new(),
        }
    }

    pub fn infer_constraints<O: Oracle<A>>(&self, o: &mut O, instr: Instr<'_>) -> Result<MemoryAccesses<A, BasicComputation>, ConstraintAnalysisError<A>> {
        self.constraints.get_or_insert(instr, || MemoryAccessAnalysis::infer(o, instr))
    }

    pub fn infer_dataflow<O: Oracle<A>>(&self, o: &mut O, memory_accesses: &MemoryAccesses<A, BasicComputation>) -> Result<Dataflows<A, BasicComputation>, DataflowError<A>> {
        self.dataflow.get_or_insert(memory_accesses.instr, || DataflowAnalysis::infer(o, &memory_accesses))
    }
}