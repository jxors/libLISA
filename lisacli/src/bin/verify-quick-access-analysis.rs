use std::{error::Error, io::Write, path::PathBuf, time::Instant};
use liblisa::{enumeration::EnumWorker, work::Work};
use liblisa_enc::accesses::{ConstraintAnalysisError, MemoryAccessAnalysis};
use lisacli::SavePath;
use structopt::StructOpt;
use liblisa_x64::{arch::X64Arch, x64_kmod_ptrace_oracle};
use liblisa_core::{RandomizationError, arch::Instruction};

#[derive(StructOpt)]
struct Args {
    #[structopt(long = "dir")]
    dir: PathBuf,
}

fn run() -> Result<(), Box<dyn Error>> {
    let args = Args::from_args();
    let save_paths = SavePath::from(args.dir);
    let runner = Work::<EnumWorker<X64Arch>, Instruction, _>::load(save_paths)?;
    let encodings = runner.artifacts().iter().collect::<Vec<_>>();
    let instrs = encodings.iter().map(|e| e.instr()).collect::<Vec<_>>();
    let mut oracle = x64_kmod_ptrace_oracle();

    let mut slow_time = 0;
    let mut fast_time = 0;

    let mut critical_fails = 0;
    let mut fails = 0;

    println!("Running...");
    for (instr_index, instr) in instrs.iter().copied().enumerate() {
        print!("Considering {} / {}: {:02X?} ", instr_index, instrs.len(), instr.bytes());
        std::io::stdout().lock().flush()?;

        let start = Instant::now();
        let slow = MemoryAccessAnalysis::infer_slow(&mut oracle, instr);
        slow_time += (Instant::now() - start).as_millis();

        print!(".");
        std::io::stdout().lock().flush()?;

        let start = Instant::now();
        let fast = MemoryAccessAnalysis::infer_quick(&mut oracle, instr);
        fast_time += (Instant::now() - start).as_millis();

        println!(".");

        println!("Time spent: slow={:8.1}m, fast={:8.1}m, speedup={:1.3}x", slow_time as f64 / 60_000.0, fast_time as f64 / 60_000.0, slow_time as f64 / fast_time as f64);
        println!("Differences: {} critical, {} will fall back to slow algorithm", critical_fails, fails);
        println!();

        match slow {
            Ok(slow) => if let Ok(Some(fast)) = fast {
                if slow.memory.len() != fast.memory.len() 
                    || slow.memory.iter().zip(fast.memory.iter()).any(|(slow, fast)| {
                        slow.inputs != fast.inputs
                        || fast.size.start < slow.size.start
                        || fast.size.end > slow.size.end
                        || slow.calculation.as_ref().map(|c| Some(c) != fast.calculation.as_ref()).unwrap_or(false)
                        || slow.kind != fast.kind
                    }) {
                    println!();
                    println!("DIFFERENCE for {:02X?}:", instr.bytes());
                    println!("Slow: {:X?}", slow);
                    println!("Fast: {:X?}", fast);
                    println!();

                    critical_fails += 1;
                }
            } else if let Ok(None) = fast {
                println!("NOTE: Fast analysis gracefully failed for {:02X?}; Slow gave: {:X?}", instr.bytes(), slow);

                fails += 1;
            } else {
                println!("ERROR: Fast analysis gave an incorrect error for {:02X?}; Slow gave: {:X?}", instr.bytes(), slow);

                critical_fails += 1;
            },

            Err(ConstraintAnalysisError::Randomization(RandomizationError::UnmappableFixedOffset(index)))
            | Err(ConstraintAnalysisError::Randomization(RandomizationError::CannotFillState(index)))
            | Err(ConstraintAnalysisError::Randomization(RandomizationError::NoMemoryAccess(index)))
            | Err(ConstraintAnalysisError::Randomization(RandomizationError::Unsatisfiable(index)))
            | Err(ConstraintAnalysisError::UnaccessibleMemoryAccess(index)) => {
                match fast {
                    Ok(_) => {},
                    Err(ConstraintAnalysisError::Randomization(RandomizationError::UnmappableFixedOffset(fast_index)))
                    | Err(ConstraintAnalysisError::Randomization(RandomizationError::CannotFillState(fast_index)))
                    | Err(ConstraintAnalysisError::Randomization(RandomizationError::NoMemoryAccess(fast_index)))
                    | Err(ConstraintAnalysisError::Randomization(RandomizationError::Unsatisfiable(fast_index)))
                    | Err(ConstraintAnalysisError::UnaccessibleMemoryAccess(fast_index)) => {
                        if index != fast_index {
                            println!("DIFFERENCE for {:02X?}: {:X?} vs {:X?}", instr, slow, fast);
                            critical_fails += 1;
                        }
                    },
                    // If quick fails as well, we did not miss any information.
                    // If quick doesn't fail, we can analyze more instructions.
                    // In either case, this is good.
                    Err(_) => {},
                }
            }
            // See above.
            Err(_) => {},
        }
    }

    Ok(())
}

fn main () { 
    env_logger::init();
    run().unwrap() 
}