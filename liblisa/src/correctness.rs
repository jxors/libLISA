use std::{error::Error, sync::atomic::Ordering};
use crate::OracleProvider;
use crate::work::Worker;
use liblisa_core::arch::Arch;
use liblisa_core::oracle::Oracle;
use liblisa_core::computation::Computation;
use liblisa_core::gen::TryIntoBasicComputation;
use crate::synthesis::SynthesisRuntimeData;
use liblisa_core::{Encoding, StateGen};
use rand::Rng;
use serde::{Serialize, Deserialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Correctness<A: Arch, C: Computation> {
    pub encoding: Encoding<A, C>,
    pub checks: usize,
    pub ignored: usize,
    pub correct: bool,
}

impl<A: Arch, C: Computation> Correctness<A, C> {
    pub fn new(encoding: Encoding<A, C>) -> Correctness<A, C> {
        Correctness {
            encoding,
            checks: 0,
            ignored: 0,
            correct: true,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CorrectnessWorker<'a, A: Arch, C: Computation> {
    pub encodings: Vec<Correctness<A, C>>,

    pub index: usize,

    pub num_checks: usize,

    #[serde(default)]
    pub _phantom: std::marker::PhantomData<&'a (A, C)>,
}

impl<'a, A: Arch + 'static, C: Computation + Sync + Send + TryIntoBasicComputation> Worker for CorrectnessWorker<'a, A, C> where SynthesisRuntimeData<'a, A, C>: OracleProvider<A> {
    type LogEntry = ();
    type Artifact = ();
    type RuntimeData = SynthesisRuntimeData<'a, A, C>;

    fn run(&mut self, worker_id: usize, running: &std::sync::atomic::AtomicBool, runtime_data: &SynthesisRuntimeData<'a, A, C>, mut updater: crate::work::StateUpdater<Self>) -> Result<(), Box<dyn Error>> {
        let mut oracle = runtime_data.oracle()?;
        let mut rng = rand::thread_rng();

        println!("[{:02}] {} encodings to verify", worker_id, self.encodings.len());
        'outer: loop {
            println!("[{:02}] Restarting oracle...", worker_id);
            oracle.restart();
            for _ in 0..10 {
                println!("[{:02}] Currently: {} / {}", worker_id, self.index, self.encodings.len());
                if !running.load(Ordering::SeqCst) {
                    break 'outer;
                }
    
                let c = &mut self.encodings[self.index];
                // Only verify encodings that we still believe to be correct
                if c.correct {   
                    for _ in 0..20_000 {
                        if !running.load(Ordering::SeqCst) {
                            break 'outer;
                        }

                        let part_values = c.encoding.parts.iter()
                            .map(|part| rng.gen::<u64>() & ((1 << part.size) - 1))
                            .collect::<Vec<_>>();
                        if let Ok(instance) = c.encoding.instantiate(&part_values) {
                            match StateGen::randomize_new(&instance.addresses, &mut rng, &mut oracle) {
                                Ok(state) => {
                                    let mut expected_output = state.clone();
                                    instance.execute(&mut expected_output);

                                    match oracle.observe(&state) {
                                        Ok(output) => {
                                            if output == expected_output {
                                                c.checks += 1;
                                            } else {
                                                c.correct = false;
                                                println!("[{:02}] Correctness verification failed: Input: {:X?}; Expected: {:X?}; But found: {:X?}; For encoding: {} instantiated with {:X?}: {}; {:?}", worker_id, state, expected_output, output, c.encoding, part_values, instance, c.encoding);
                                                break;
                                            }
                                        },
                                        Err(_) => c.ignored += 1,
                                    }
                                },
                                Err(_err) => {}
                            }
                        }
                    }
                }

                self.index += 1;
                if self.index >= self.encodings.len() {
                    self.index = 0;

                    if self.encodings.iter().all(|c| !c.correct || c.checks >= self.num_checks) {
                        updater.done(self.clone());
                        return Ok(());
                    }
                }
            }

            updater.update(self.clone());
        }

        updater.update(self.clone());

        Ok(())
    }
}