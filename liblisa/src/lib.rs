use std::{convert::TryInto, error::Error, sync::{atomic::AtomicBool, mpsc::channel}};
use liblisa_core::{Encoding, arch::{Arch, Instr, InstructionInfo}, computation::BasicComputation, counter::InstructionFilter, oracle::Oracle};
use liblisa_enc::cache::CombinedCache;
use liblisa_x64::{X64Arch, x64_kmod_ptrace_oracle};
use synthesis::DecisionTreeComputation;

use crate::{correctness::{Correctness, CorrectnessWorker}, enumeration::{Analysis, analyze_instr}, synthesis::{SynthesisRuntimeData, SynthesisWorker, extract_addr_output_groups, extract_dataflow_output_groups, extract_semantics, preprocess_encodings}, work::StateUpdater, work::Worker};

pub mod synthesis;
pub mod work;
pub mod enumeration;
pub mod correctness;

pub trait OracleProvider<A: Arch> {
    type O: Oracle<A> + 'static;

    fn oracle(&self) -> Result<Self::O, Box<dyn Error>>;
}

pub struct FilterMap<T> {
    filters: [[Vec<(InstructionFilter, T)>; 256]; 16],
}

impl<T: Clone + std::fmt::Debug> FilterMap<T> {
    pub fn new() -> FilterMap<T> {
        FilterMap {
            filters: vec![vec![Vec::new(); 256].try_into().unwrap(); 16].try_into().unwrap(),
        }
    }

    pub fn add(&mut self, filter: InstructionFilter, data: T) {
        let len = filter.len();
        let b = &filter.data[0];
        if let Some(index) = b.as_value() {
            self.filters[len][index as usize].push((filter, data));
        } else {
            for index in 0..256 {
                if b.matches(index as u8) {
                    self.filters[len][index].push((filter.clone(), data.clone()));
                }
            }
        }
    }

    pub fn filters(&self, instruction: Instr<'_>) -> Option<&T> {
        for (filter, data) in self.filters[instruction.byte_len()][instruction.bytes()[0] as usize].iter() {
            if filter.matches(&instruction) {
                return Some(data);
            }
        }

        None
    }
}

pub fn learn_instr(instr: Instr<'_>) -> Result<Encoding<X64Arch, DecisionTreeComputation>, ()> {
    let encoding = {
        let cache = CombinedCache::new();
        let mut o = x64_kmod_ptrace_oracle();
        let result = analyze_instr(0, &mut o, &cache, None, instr, 0);

        let encoding = if let Analysis::Ok(encoding) = result {
            if let Some(perfect_instr) = encoding.best_instr() {
                let result = analyze_instr(0, &mut o, &cache, None, perfect_instr.as_instr(), 0);
                if let Analysis::Ok(best_encoding) = result {
                    best_encoding
                } else {
                    encoding
                }
            } else {
                encoding
            }
        } else {
            todo!()
        };

        o.kill();

        encoding
    };

    let encodings = preprocess_encodings(|| x64_kmod_ptrace_oracle(), vec![ encoding ]);
    let computation_groups = extract_addr_output_groups(&encodings);

    let addr_computation_groups = {
        let mut worker = SynthesisWorker::<_, BasicComputation> {
            computation_groups,
            index: 0,
            _phantom: Default::default(),
        };

        let (sender, _r) = channel();
        let (artifact_sender, _) = channel();
        let (log_sender, _r) = channel();
        let updater = StateUpdater::new(0, sender, artifact_sender, log_sender);
        let rd = SynthesisRuntimeData::new(&encodings);

        let running = AtomicBool::new(true);
        worker.run(0, &running, &rd, updater).unwrap();

        worker.computation_groups
    };

    let (encodings, computation_groups) = extract_dataflow_output_groups(&encodings, addr_computation_groups);

    let computation_groups = {
        let mut worker = SynthesisWorker::<_, DecisionTreeComputation> {
            computation_groups,
            index: 0,
            _phantom: Default::default(),
        };

        let (sender, _r) = channel();
        let (artifact_sender, _) = channel();
        let (log_sender, _r) = channel();
        let updater = StateUpdater::new(0, sender, artifact_sender, log_sender);
        let rd = SynthesisRuntimeData::new(&encodings);

        let running = AtomicBool::new(true);
        worker.run(0, &running, &rd, updater).unwrap();

        worker.computation_groups
    };

    let semantics = extract_semantics(false, encodings, computation_groups);
    for encoding in semantics.iter() {
        println!("Semantics: {}", encoding);
    }

    println!();
    println!();
    println!();
    
    let mut worker = CorrectnessWorker::<'_, _, _> {
        encodings: semantics.iter().cloned().map(|e| Correctness::new(e)).collect(),
        index: 0,
        num_checks: 100_000,
        _phantom: Default::default(),
    };

    let (sender, _r) = channel();
    let (artifact_sender, _) = channel();
    let (log_sender, _r) = channel();
    let updater = StateUpdater::new(0, sender, artifact_sender, log_sender);
    let rd = SynthesisRuntimeData::new(&[]);

    let running = AtomicBool::new(true);
    worker.run(0, &running, &rd, updater).unwrap();

    // Since we only input a single encoding, `semantics` will always contain a single encoding.
    Ok(semantics[0].clone())
}