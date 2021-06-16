use std::{error::Error, fs::File, io::BufReader, path::PathBuf};
use liblisa::{correctness::{Correctness, CorrectnessWorker}, synthesis::{DecisionTreeComputation, SynthesisRuntimeData}, work::Work};
use liblisa_core::Encoding;
use liblisa_x64::X64Arch;
use lisacli::SavePath;
use structopt::StructOpt;

#[global_allocator]
static GLOBAL: jemallocator::Jemalloc = jemallocator::Jemalloc;

#[derive(StructOpt)]
enum Verb {
    Create {
        encodings_path: PathBuf,

        #[structopt(long = "workers")]
        num_workers: usize,
    },
    Run,
    Status,
    Dump { 
        #[structopt(long)]
        all: bool,
    },
    Extract {
        output: PathBuf,
    }
}

#[derive(StructOpt)]
struct Args {
    dir: PathBuf,

    #[structopt(subcommand)]
    verb: Verb,
}

fn run() -> Result<(), Box<dyn Error>> {
    let args = Args::from_args();
    let save_paths = SavePath::from(args.dir);
    match args.verb {
        Verb::Create { encodings_path, num_workers } => {
            println!("Reading: {:?}", encodings_path);
            let encodings: Vec<Encoding<X64Arch, DecisionTreeComputation>> = serde_json::from_reader(BufReader::new(File::open(&encodings_path)?))?;

            let mut worker_data = vec![ Vec::new(); num_workers ];
            let mut worker_index = 0;
            for computation in encodings.into_iter() {
                worker_data[worker_index].push(Correctness::new(computation));
                worker_index = (worker_index + 1) % worker_data.len();
            }

            println!("Saving results...");
            let group_ids = worker_data.iter().enumerate().map(|(x, _)| x).collect::<Vec<_>>();
            Work::create(save_paths, &group_ids, num_workers, |from, _| {
                CorrectnessWorker::<'_, _, _> {
                    encodings: worker_data[*from].clone(),
                    index: 0,
                    num_checks: 10_000_000,
                    _phantom: Default::default(),
                }
            })?;
        },
        Verb::Run => {
            println!("Running workers...");
            let mut runner = Work::<CorrectnessWorker<'_, X64Arch, DecisionTreeComputation>, u64, _>::load(save_paths)?;
            runner.run(&SynthesisRuntimeData::new(&[]))?;
        },
        Verb::Status => {
            let runner = Work::<CorrectnessWorker<'_, X64Arch, DecisionTreeComputation>, u64, _>::load(save_paths.clone())?;
            let num_correct = runner.workers().iter()
                .flat_map(|w| w.inner().encodings.iter())
                .filter(|g| g.correct && g.checks > 100)
                .count();
            let num_unchecked = runner.workers().iter()
                .flat_map(|w| w.inner().encodings.iter())
                .filter(|g| g.checks == 0)
                .count();
            let num_incorrect = runner.workers().iter()
                .flat_map(|w| w.inner().encodings.iter())
                .filter(|g| !g.correct)
                .count();

            println!("Found {} encodings correct, {} unchecked, {} incorrect", num_correct, num_unchecked, num_incorrect);
        },
        Verb::Dump { all } => {
            let runner = Work::<CorrectnessWorker<'_, X64Arch, DecisionTreeComputation>, u64, _>::load(save_paths.clone())?;
            for worker in runner.workers().iter() {
                for c in worker.inner().encodings.iter() {
                    if !c.correct || all {
                        println!("correct={} for {} / {:?}", c.correct, c.encoding, c.encoding);
                    }
                }
            }
        }
        Verb::Extract { output } => {
            let runner = Work::<CorrectnessWorker<'_, X64Arch, DecisionTreeComputation>, u64, _>::load(save_paths.clone())?;
            let encodings = runner.workers().iter()
                .flat_map(|w| w.inner().encodings.iter())
                .filter(|g| g.correct && g.checks > 100)
                .map(|g| g.encoding.clone())
                .collect::<Vec<_>>();
            serde_json::to_writer(File::create(output)?, &encodings)?;
        }
    }

    Ok(())
}

fn main () { 
    env_logger::init();
    run().unwrap() 
}