use std::time::{Duration, Instant};
use std::{collections::HashSet, error::Error, io::Write, sync::atomic::Ordering};
use liblisa_core::arch::{Arch, Instr, Instruction, InstructionInfo};
use liblisa_core::oracle::Oracle;
use liblisa_core::computation::{Computation, BasicComputation};
use liblisa_x64::{KmodPtraceOracle, arch::X64Arch};
use liblisa_core::counter::{InstructionCounter, InstructionFilter};
use liblisa_core::Encoding;
use liblisa_enc::{cache::CombinedCache, Validity, encoding::EncodingAnalysis};
use log::{error, trace};
use serde::{Serialize, Deserialize, de::DeserializeOwned};
use crate::OracleProvider;
use crate::work::{BroadcastQueue, Worker};

pub fn cleanup<A: Arch + 'static, C: Computation>(encodings: Vec<Encoding<A, C>>) -> Vec<Encoding<A, C>> {
    // TODO: This might not be picking the optimal candidates
    let mut result = Vec::new();
    let encoding_filters = encodings.iter().map(|e| e.filters()).collect::<Vec<_>>();
    for (index, (encoding, filters)) in encodings.into_iter().zip(encoding_filters.iter()).enumerate() {
        trace!("Considering {}", encoding);
        // We only add this function if at least one of the filters is not covered by another filter.
        if !filters.iter().all(|f| {
            encoding_filters.iter().enumerate()
                .any(|(n, other_filters)| n != index && other_filters.iter().any(|g| if f.covers(g) {
                    if f == g {
                        n < index
                    } else {
                        true
                    }
                } else {
                    false
                }))
            }) {
            result.push(encoding);
        }
    }

    result
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EnumWorker<A: Arch> {
    pub counter: InstructionCounter,
    pub unique_sequences: u128,
    pub next: Option<Instruction>,
    pub instrs_seen: HashSet<Instruction>,
    pub fast_tunnel: bool,
    #[serde(default)]
    pub instrs_failed: Vec<Instruction>,
    #[serde(default)]
    pub _phantom: std::marker::PhantomData<A>,
}

pub struct RuntimeWorkerData<A: Arch> {
    pub cache: CombinedCache<A>,
    pub filter_broadcast: BroadcastQueue<InstructionFilter>,
    pub instr_broadcast: BroadcastQueue<Instruction>,
}

impl<A: Arch + 'static> RuntimeWorkerData<A> {
    pub fn new() -> RuntimeWorkerData<A> {
        RuntimeWorkerData {
            cache: CombinedCache::new(),
            filter_broadcast: BroadcastQueue::new(),
            instr_broadcast: BroadcastQueue::new(),
        }
    }
}

impl OracleProvider<X64Arch> for RuntimeWorkerData<X64Arch> {
    type O = KmodPtraceOracle;
    
    fn oracle(&self) -> Result<KmodPtraceOracle, Box<dyn Error>> {
        Ok(KmodPtraceOracle::new("utils/minimal-executable")?)
    }
}

pub enum Analysis<A: Arch, C: Computation> {
    Ok(Encoding<A, C>),
    SkipInvalid,
    SkipError,
    Extend,
    Reduce,
}

fn analyze<A: Arch + 'static, O: Oracle<A> + 'static>(thread_id: usize, o: &mut O, cache: &CombinedCache<A>, instr: Instr<'_>) -> Result<Encoding<A, BasicComputation>, Box<dyn Error>> {
    std::io::stdout().flush().ok().expect("Could not flush stdout");
    let memory_accesses = cache.infer_constraints(o, instr)
        .map_err(|e| { error!("[{:02}] MemoryAccesses failed: {}", thread_id, e); e })?;
    println!("[{:02}]    Constraints: {}", thread_id, memory_accesses);

    std::io::stdout().flush().ok().expect("Could not flush stdout");
    let dataflow = cache.infer_dataflow(o, &memory_accesses)
        .map_err(|e| { error!("[{:02}] Dataflow failed: {}", thread_id, e); e })?;
    println!("[{:02}]    Dataflow: {:?}", thread_id, dataflow);

    std::io::stdout().flush().ok().expect("Could not flush stdout");
    let encoding = EncodingAnalysis::infer(o, cache, &dataflow)
        .map_err(|e| { error!("[{:02}] Encoding failed: {}", thread_id, e); e })?;
    println!("[{:02}]    Encoding: {}", thread_id, format!("{}", encoding).replace("\n", "\n        "));

    Ok(encoding)
}

pub fn analyze_instr<A: Arch + 'static, O: Oracle<A> + 'static>(thread_id: usize, o: &mut O, cache: &CombinedCache<A>, name: Option<&str>, instr: Instr<'_>, num_skipped: usize) -> Analysis<A, BasicComputation> {
    let validity = Validity::infer(o, instr);
    if num_skipped < 10 || validity != Validity::InvalidInstruction {
        println!();
    
        println!("[{:02}] Instruction: {} {:02X?} = {:?}", thread_id, name.unwrap_or(""), instr.bytes(), instr);
        println!("[{:02}]    Validity: {}", thread_id, validity);
    }

    match validity {
        Validity::Ok => {
            match analyze(thread_id, o, cache, instr) {
                Ok(encoding) => Analysis::Ok(encoding),
                Err(e) => {
                    error!("[{:02}] Analysis failed: {}", thread_id, e);
                    Analysis::SkipError
                },
            }
        },
        Validity::TooShort => Analysis::Extend,
        Validity::TooLong => Analysis::Reduce,
        Validity::Excluded | Validity::InvalidInstruction => Analysis::SkipInvalid,
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum EnumerationLog {
    Failed(Instruction),
    Extend(Instruction),
    Reduce(Instruction),
    Ok {
        analyzed: Instruction,
        next: Option<Instruction>,
    },
    Complete(Instruction),
}

impl<A: Arch + 'static + Serialize + DeserializeOwned + Send> Worker for EnumWorker<A> where RuntimeWorkerData<A>: OracleProvider<A> {
    type LogEntry = EnumerationLog;
    type Artifact = Encoding<A, BasicComputation>;
    type RuntimeData = RuntimeWorkerData<A>;

    fn run(&mut self, worker_id: usize, running: &std::sync::atomic::AtomicBool, runtime_data: &RuntimeWorkerData<A>, mut updater: crate::work::StateUpdater<Self>) -> Result<(), Box<dyn Error>> {
        // rebuild^5() since a single rebuild might not remove all redundancy
        
        let mut incoming_filters = runtime_data.filter_broadcast.read();
        let mut incoming_instrs = runtime_data.instr_broadcast.read();
        self.counter.rebuild_inplace();
        let mut encodings_found = 0;
        let mut num_skipped = 0;
        let mut num_errors = 0;

        self.instrs_failed.clear();

        let mut last_restart = Instant::now();

        let mut o = runtime_data.oracle()?;
        loop {
            if incoming_filters.available() {
                println!("[{:02}] Adding new filters", worker_id);
                while let Some(filter) = incoming_filters.next() {
                    println!("[{:02}] Adding filter {:?}", worker_id, filter);
                    self.counter.filter(filter);
                }

                if !self.counter.apply_filters_to_current() {
                    break;
                }
            }

            if incoming_instrs.available() {
                while let Some(instr) = incoming_instrs.next() {
                    println!("[{:02}] Saw instruction: {:?} {:02X?}", worker_id, instr, instr.bytes());
                    self.instrs_seen.insert(instr);
                }
            }

            updater.update(self.clone());
            if !running.load(Ordering::SeqCst) {
                return Ok(());
            }

            let instr = self.next.as_ref()
                .map(Instruction::as_instr)
                .unwrap_or_else(|| self.counter.current());

            let instruction = instr.as_instruction();
            if self.instrs_seen.contains(&instruction) {
                // If we have already processed this exact instruction (in the context of a perfect instruction)
                if self.next.is_some() {
                    self.next = None;
                } else {
                    self.counter.filter(instruction.as_instr().into());
                    if !self.counter.apply_filters_to_current() {
                        break;
                    }
                }

                continue;
            }

            if Instant::now() - last_restart >= Duration::from_secs(30) {
                o.restart();
                last_restart = Instant::now();
            }

            match analyze_instr(worker_id, &mut o, &runtime_data.cache, None, instr, num_skipped) {
                Analysis::Ok(encoding) => {
                    num_skipped = 0;
                    num_errors = 0;
                    self.fast_tunnel = false;
                    
                    let filters = encoding.filters();
                    let perfect_instr = encoding.best_instr();
                    updater.publish_artifact(encoding);

                    if let Some(perfect_instr) = &perfect_instr {
                        println!("[{:02}] Perfect instr: {:?} {:02X?}", worker_id, perfect_instr, perfect_instr.bytes());
                    }

                    for filter in filters {
                        println!("[{:02}] Broadcasting filter {:?}", worker_id, filter);
                        self.unique_sequences += 1 << filter.num_wildcard_bits();
                        runtime_data.filter_broadcast.push(filter);
                    }

                    runtime_data.instr_broadcast.push(instruction);
                    encodings_found += 1;
                    if self.next.is_none() {
                        // If we didn't just analyze a custom requested instruction, we can try to analyze the perfect instruction
                        self.next = perfect_instr;

                        // We do not call `self.counter.next()` here.
                        // The filters themselves will ensure we do not analyze the same instruction again.
                    } else {
                        // To prevent endless loops, we skip analyzing the perfect instruction if we just analyzed a custom instruction
                        self.next = None;
                    }

                    if encodings_found % 10 == 0 {
                        println!("Rebuilding filters:");
                        println!("{:?}", self.counter);

                        self.counter.rebuild_inplace();
                        println!("Rebuilt: {:?}", self.counter);
                    }

                    o.restart();
                    last_restart = Instant::now();
                    updater.log(EnumerationLog::Ok {
                        analyzed: instruction,
                        next: self.next.clone(),
                    });
                }
                Analysis::Extend => {
                    updater.log(EnumerationLog::Extend(instr.as_instruction()));

                    if self.next.is_none() {
                        self.counter.extend(self.fast_tunnel);
                    } else {
                        self.next = None;
                    }
                }
                Analysis::Reduce => {
                    updater.log(EnumerationLog::Reduce(instr.as_instruction()));

                    if self.next.is_none() {
                        self.counter.reduce(self.fast_tunnel);
                    } else {
                        self.next = None;
                    }
                }
                Analysis::SkipInvalid => {
                    num_skipped += 1;
                    num_errors = 0;
                    self.fast_tunnel = false;
                    if self.next.is_none() {
                        if !self.counter.tunnel_next(200) {
                            break;
                        }
                    } else {
                        self.next = None;
                    }
                }
                Analysis::SkipError => {
                    updater.log(EnumerationLog::Failed(instr.as_instruction()));

                    num_skipped = 0;
                    num_errors += 1;
                    if num_errors % 200 == 1 {
                        o.restart();
                        last_restart = Instant::now();
                    }

                    self.fast_tunnel = true;
                    if self.next.is_none() {
                        if num_errors >= 500_000 {
                            // If we have seen half a million errors, we might have a bad filter. 
                            // Keep in mind that errors are encoding analysis failures, NOT excluded instructions or invalid instructions.
                            // To mitigate the bad filter, we just tunnel unconditionally until we find something that does not error.
                            if !self.counter.tunnel_next_ignore_filters() {
                                break;
                            }
                        } else {
                            if !self.counter.tunnel_next(200) {
                                break;
                            }
                        }
                    } else {
                        self.next = None;
                    }
                }
            }
        }

        updater.log(EnumerationLog::Complete(self.counter.current().as_instruction()));

        // TODO: Analyze self.next if it is not None? The last one is now skipped if the counter has finished.

        updater.done(self.clone());

        Ok(())
    }
}
