use std::{collections::{HashMap, HashSet}, error::Error, fs::File, io::{BufReader, Write}, marker::PhantomData, path::PathBuf, sync::atomic::{AtomicUsize, Ordering}};
use colored::Colorize;
use liblisa::{FilterMap, enumeration::{EnumWorker, RuntimeWorkerData}, synthesis::preprocess_encodings, work::Work};
use lisacli::SavePath;
use structopt::StructOpt;
use liblisa_x64::{arch::X64Arch, x64_kmod_ptrace_oracle};
use liblisa_core::arch::{Arch, Instruction, InstructionInfo};
use liblisa_core::counter::InstructionCounter;
use itertools::Itertools;
use rayon::prelude::*;

#[global_allocator]
static GLOBAL: jemallocator::Jemalloc = jemallocator::Jemalloc;

#[derive(StructOpt)]
enum Verb {
    #[structopt(help = "Creates a new enumeration")]
    Create {
        #[structopt(long = "workers", default_value = "1")]
        num_workers: usize,

        #[structopt(long = "scan")]
        scan: Option<PathBuf>,
    },
    
    #[structopt(help = "Runs a previously created enumeration")]
    Run,

    #[structopt(help = "Prints the status of the enumeration")]
    Status {
        #[structopt(long = "scan")]
        scan: Option<PathBuf>,
    },

    #[structopt(help = "Dumps all encodings found during enumeration")]
    Dump,

    #[structopt(help = "Resets a worker, restarting it from the beginning of its range. Will not remove encodings already generated by this worker.")]
    ResetWorker { num: usize },

    #[structopt(help = "Resets the 'done' state of a worker. This is only useful if a worker entered the 'done' state too early, which normally should not happen.")]
    ResumeWorker { num: usize },

    #[structopt(help = "Resets the instructions that workers will skip because they have already been enumerated.")]
    ResetInstrsSeen,

    #[structopt(help = "Rebuilds all filters based on the encodings found.")]
    RebuildFilters,

    Extract { path: PathBuf },
}

#[derive(StructOpt)]
struct Args {
    dir: PathBuf,

    #[structopt(subcommand)]
    verb: Verb,
}

#[derive(Copy, Clone, Default, Debug)]
struct Stats {
    found: usize,
    missed: usize,
    total: usize,
}

fn run() -> Result<(), Box<dyn Error>> {
    let args = Args::from_args();
    let save_paths = SavePath::from(args.dir);
    match args.verb {
        Verb::Create { num_workers: threads, scan } => {
            let work = if let Some(scan_file) = scan {
                let mut v: Vec<Instruction> = serde_json::from_reader(BufReader::new(File::open(&scan_file)?))?;
                v.retain(|instr| {
                    X64Arch::is_instruction_included(instr.bytes())
                });

                // Trim some of the REX prefixes, since they often get enumerated faster.
                // The REX prefix often contains a few DontCare / register bits.
                let mut k = 0;
                let mut n = v.len();
                v.retain(|instr| { 
                    n -= 1;
                    if n % 1000_000 == 0 {
                        println!("{:.1}k processed", n as f64 / 1000.);
                    }

                    match instr.bytes() {
                        [0xf0, 0x66, rex, ..] | [0xf0, rex, ..] | [0x66, rex, ..] | [0xf2, 0x66, rex, ..] | [0xf3, 0x66, rex, ..] | [0xf2, rex, ..] | [0xf3, rex, ..] | [rex, ..] if rex & 0xf0 == 0x40 => {
                            k += 1;
                            // We're removing 7/8 entries, so we keep 2 entries per 16, accounting for 1 out of 4 bits not being DontCare or a register.
                            if k % 8 != 0 {
                                return false;
                            }
                        }
                        _ => {},
                    }

                    true
                });

                v.insert(0, Instruction::new(&[ 0 ]));
                v
            } else {
                (0..=255u8).map(|i| Instruction::new(&[ i ])).collect::<Vec<_>>()
            };

            Work::create(save_paths, &work, threads, |from, to| {
                EnumWorker {
                    counter: InstructionCounter::range(from.as_instr(), to.cloned()),
                    unique_sequences: 0,
                    next: None,
                    instrs_seen: HashSet::new(),
                    instrs_failed: Vec::new(),
                    fast_tunnel: false,
                    _phantom: PhantomData,
                }
            })?;

            println!("State created!");
        }
        Verb::Run => {
            let mut runner = Work::<EnumWorker<X64Arch>, Instruction, _>::load(save_paths)?;
            runner.run(&RuntimeWorkerData::new())?;
        }
        Verb::Status { scan } => {
            let runner = Work::<EnumWorker<X64Arch>, Instruction, _>::load(save_paths)?;
            let workers = runner.workers();
            let unique_sequences: u128 = workers.iter().map(|s| s.inner().unique_sequences).sum();
            let seconds_running: u64 = runner.seconds_running();

            let mut filter_map = FilterMap::new();
            let num_encodings = {
                let encodings = if scan.is_some() {
                    println!("Loading encodings...");
                    runner.artifacts().iter().collect::<Vec<_>>()
                } else { 
                    Vec::new()
                };

                for (index, e) in encodings.iter().enumerate() {
                    let filters = e.filters();

                    if filters.len() <= 0 {
                        panic!("No filters for {}", e);
                    }
                    
                    for filter in filters {
                        filter_map.add(filter, index);
                    }
                }

                encodings.len()
            };

            let (counts, encodings_seen) = if let Some(scan) = scan {
                let v: Vec<Instruction> = serde_json::from_reader(BufReader::new(File::open(&scan)?))?;
                print!("Checking progress");

                let (counts, encodings_seen) = v.par_iter().chunks(5000)
                    .map(|chunk| {
                        let mut counts = vec![Stats::default(); workers.len()];
                        let mut encodings_seen = vec![ false; num_encodings ];

                        for instr in chunk {
                            let worker = workers.iter()
                                .position(|w| instr >= w.from() && w.to().as_ref().map(|to| instr <= to).unwrap_or(true))
                                .unwrap();
    
                            let mut match_found = false;
                            if let Some(index) = filter_map.filters(instr.as_instr()) {
                                match_found = true;
                                encodings_seen[*index] = true;
                            }
                            
                            if match_found {
                                counts[worker].found += 1;
                            } else if workers[worker].inner().counter.current() > instr.as_instr() {
                                counts[worker].missed += 1;
                                println!("Worker {:02} has MISSED {:02X?}", worker, instr.bytes());
                            }
    
                            counts[worker].total += 1;
                        }
    
                        print!(".");
                        std::io::stdout().lock().flush().expect("Could not flush stdout");

                        (counts, encodings_seen)
                    }).reduce(|| (vec![Stats::default(); workers.len()], vec![ false; num_encodings ]),
                    |(mut counts, mut seen), (other_counts, other_seen)| {
                        for (count, other_count) in counts.iter_mut().zip(other_counts.iter()) {
                            count.missed += other_count.missed;
                            count.total += other_count.total;
                            count.found += other_count.found;
                        }

                        for (seen, other_seen) in seen.iter_mut().zip(other_seen.iter()) {
                            *seen = *seen || *other_seen;
                        }

                        (counts, seen)
                    });

                println!();

                (Some(counts), encodings_seen)
            } else {
                (None, Vec::new())
            };

            println!("Found {} instruction encodings (=2^{:.2} bitstrings) in {}h {}m {}s (approx. 2^{:.2} bitstrings/hour)", runner.artifacts().len(), (unique_sequences as f64).log2(), seconds_running / 3600, (seconds_running / 60) % 60, seconds_running % 60, (unique_sequences as f64 / (seconds_running as f64 / (3600.0))).log2());
            println!();

            let current_pad = workers.iter().map(|s| s.inner().counter.current().bytes().len() * 4).max().unwrap();
            let from_pad = workers.iter().map(|s| s.from().bytes().len() * 4).max().unwrap();
            let to_pad = workers.iter().map(|s| s.to().map(|s| s.bytes().len() * 4).unwrap_or(0)).max().unwrap();
            for worker in workers.iter() {
                print!("Worker #{:2} {{ {:from_pad$} → {:to_pad$} }} ", worker.id(), format!("{:02X?}", worker.from().bytes()).dimmed(), worker.to().map(|x| format!("{:02X?}", x.bytes().to_vec())).unwrap_or(String::new()).dimmed(), from_pad = from_pad, to_pad = to_pad);
                
                if let Some(counts) = &counts {
                    let Stats { found, missed, total } = &counts[*worker.id()];
                    print!("{:>4.1}% (miss: {:>4.1}%) ", (found + missed) as f64 / *total as f64 * 100., *missed as f64 / (found + missed) as f64 * 100.);
                }

                if worker.done() {
                    print!("done: ");
                } else if let Some(next) = &worker.inner().next {
                    print!("^ {:pad$}: ", format!("{:02X?}", next.bytes()).bold(), pad = current_pad);
                } else {
                    print!("@ {:pad$}: ", format!("{:02X?}", worker.inner().counter.current().bytes()).bold(), pad = current_pad);
                }

                println!("found {} encodings", worker.artifacts_produced());
            }

            if let Some(counts) = counts {
                let found = counts.iter().map(|s| s.found).sum::<usize>();
                let total = counts.iter().map(|s| s.total).sum::<usize>();
                let missed = counts.iter().map(|s| s.missed).sum::<usize>();

                println!();
                println!("Overall progress: {:3.1}%, {:3.1}% missed ({}:{} / {})", (found + missed) as f64 / total as f64 * 100., missed as f64 / (found + missed) as f64 * 100., found, missed, total);
                let encodings_seen = encodings_seen.iter().filter(|s| **s).count();
                println!("Our scan contains entries for {} / {} encodings that we found => {:3.1} ", encodings_seen, num_encodings, encodings_seen as f64 / num_encodings as f64 * 100.);
            }
        }
        Verb::ResetWorker { num } => {
            let mut runner = Work::<EnumWorker<X64Arch>, Instruction, _>::load(save_paths)?;
            let workers = runner.workers_mut();
            let worker = &mut workers[num];

            let new_counter = InstructionCounter::range(worker.from().as_instr(), worker.to().clone());
            worker.inner_mut().counter = new_counter;
            worker.inner_mut().instrs_seen.clear();
            worker.reset_done();

            runner.save_all().unwrap();
        }
        Verb::RebuildFilters => {
            let mut runner = Work::<EnumWorker<X64Arch>, Instruction, _>::load(save_paths)?;
            let encodings = runner.artifacts();

            println!("Indexing filters...");
            let mut filters = Vec::new();
            for (index, encoding) in encodings.iter().enumerate() {
                if index % 1000 == 0 {
                    println!("{} / {}", index, encodings.len());
                }

                filters.extend(encoding.filters().into_iter());
            }

            filters.sort_by_cached_key(|f| f.smallest_matching_instruction());
            
            let workers = runner.workers_mut();
            for worker in workers.iter_mut() {
                worker.inner_mut().counter.clear_filters();
            }

            println!("Inserting filters...");
            let num_remaining = AtomicUsize::new(workers.len());
            workers.par_iter_mut().for_each(|worker| {
                let filters = filters.clone();
                let len = filters.len();
                for (index, filter) in filters.into_iter().enumerate() {
                    if index % 10_000 == 0 {
                        println!("Worker #{}: {} / {} -- {} filters added", worker.id(), index, len, worker.inner().counter.num_filters());
                    }

                    worker.inner_mut().counter.filter(filter);
                }

                println!("Starting optimization of worker #{}", worker.id());

                for n in 0..10 {
                    println!("Worker #{}: optimization at {}%...", worker.id(), n * 10);
                    worker.inner_mut().counter.rebuild_inplace();
                }

                let remaining = num_remaining.fetch_sub(1, Ordering::SeqCst).checked_sub(1).unwrap_or(0);
                println!("Remaining workers: {}", remaining);
            });

            println!("Saving...");

            runner.save_all().unwrap();
        }
        Verb::ResumeWorker { num } => {
            let mut runner = Work::<EnumWorker<X64Arch>, Instruction, _>::load(save_paths)?;
            let workers = runner.workers_mut();
            let worker = &mut workers[num];

            worker.reset_done();

            runner.save_all().unwrap();
        }
        Verb::ResetInstrsSeen => {
            let mut runner = Work::<EnumWorker<X64Arch>, Instruction, _>::load(save_paths)?;
            let workers = runner.workers_mut();
            for worker in workers.iter_mut() {
                worker.inner_mut().instrs_seen = HashSet::new();
            }

            runner.save_all().unwrap();
        }
        Verb::Dump => {
            let runner = Work::<EnumWorker<X64Arch>, Instruction, _>::load(save_paths)?;
            let encodings = runner.artifacts().iter().collect::<Vec<_>>();
            let mut seen = HashSet::new();

            // .sorted_by_key(|(_, e)| e.instr().bytes())
            for (index, encoding) in encodings.iter()
                .enumerate() {
                println!("Encoding #{:5}: {}", index, encoding);
                println!("Perfect variant: {:02X?}", encoding.best_instr());
                println!();
                println!();

                if !seen.contains(encoding.instr().bytes()) {
                    seen.insert(encoding.instr().bytes());
                }
            }

            println!("Unique encodings: {} out of {} ({} duplicates)", seen.len(), encodings.len(), encodings.len() - seen.len());

            let mut counts = HashMap::new();
            for encoding in encodings.iter() {
                let num = encoding.outputs().filter(|o| o.memory_access).count();
                *counts.entry(num).or_insert(0) += 1;
            }

            println!("Counts per number of memory accesses: {:?}", counts);

            let mut counts = HashMap::new();
            for encoding in encodings.iter() {
                let num = encoding.outputs().map(|o| o.num_inputs).max().unwrap_or(0);
                *counts.entry(num).or_insert(0) += 1;
            }

            println!("Counts per number of inputs: {:?}", counts.iter().sorted_by_key(|(n, _)| *n).collect::<Vec<_>>());
        },
        Verb::Extract { path } => {
            let runner = Work::<EnumWorker<X64Arch>, Instruction, _>::load(save_paths)?;
            let encodings = runner.artifacts().iter().cloned().collect::<Vec<_>>();
            let encodings = preprocess_encodings(|| x64_kmod_ptrace_oracle(), encodings);
            
            println!("Saving results...");
            serde_json::to_writer(File::create(path)?, &encodings)?;
        }
    }

    Ok(())
}

fn main () { 
    env_logger::init();
    run().unwrap() 
}