use std::{error::Error, fs::File, io::BufReader, path::PathBuf};
use liblisa::{synthesis::{SynthesisRuntimeData, SynthesisWorker, extract_addr_output_groups}, work::{SavePaths, Work}};
use liblisa_core::Encoding;
use liblisa_core::computation::BasicComputation;
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
            let encodings = serde_json::from_reader(File::open(encodings_path)?)?;
            let computation_groups = extract_addr_output_groups(&encodings);

            let mut worker_data = vec![ Vec::new(); num_workers ];
            let mut worker_index = 0;
            for computation in computation_groups.into_iter() {
                worker_data[worker_index].push(computation);
                worker_index = (worker_index + 1) % worker_data.len();
            }

            println!("Saving results...");
            let encodings_path = save_paths.base_data_path().to_owned();
            let group_ids = worker_data.iter().enumerate().map(|(x, _)| x).collect::<Vec<_>>();
            Work::create(save_paths, &group_ids, num_workers, |from, _| {
                SynthesisWorker::<'_, _, BasicComputation> {
                    computation_groups: worker_data[*from].clone(),
                    index: 0,
                    _phantom: Default::default(),
                }
            })?;

            serde_json::to_writer(File::create(encodings_path)?, &encodings)?;
        },
        Verb::Run => {
            println!("Loading base data (encodings)");
            let encodings: Vec<Encoding<X64Arch, BasicComputation>> = serde_json::from_reader(BufReader::new(File::open(save_paths.base_data_path())?))?;

            println!("Running workers...");
            let mut runner = Work::<SynthesisWorker<'_, X64Arch, _>, u64, _>::load(save_paths)?;
            runner.run(&SynthesisRuntimeData::new(&encodings))?;
        },
        Verb::Status => {
            let runner = Work::<SynthesisWorker<'_, X64Arch, BasicComputation>, u64, _>::load(save_paths.clone())?;
            let num_found = runner.workers().iter()
                .flat_map(|w| w.inner().computation_groups.iter())
                .filter(|g| g.table.has_good_tree())
                .count();

            let workers = runner.workers();
            let seconds_running: u64 = runner.seconds_running();

            println!("Found {} computations in {}m", num_found, seconds_running / 60);
            for worker in workers.iter() {
                print!("Worker #{:2} ", worker.id());

                if worker.done() {
                    print!("done: ");
                } else {
                    print!("@ {} / {}: ", worker.inner().index, worker.inner().computation_groups.len());
                }

                let num_found = worker.inner().computation_groups.iter()
                    .filter(|g| g.table.has_good_tree())
                    .count();
                let num_incomplete = worker.inner().computation_groups.iter()
                    .filter(|g| !g.table.has_good_tree() && g.table.has_tree())
                    .count();
                println!("found {} computations + {} incomplete", num_found, num_incomplete);
            }

            println!("Loading base data (encodings)");
            let encodings: Vec<Encoding<X64Arch, BasicComputation>> = serde_json::from_reader(BufReader::new(File::open(save_paths.base_data_path())?))?;

            let mut num_partial = 0;
            let mut num_full = 0;
            for (encoding_index, encoding) in encodings.iter().enumerate() {
                let mut partial = false;
                let mut full = true;

                for (output_index, _) in encoding.outputs().enumerate().filter(|(_, o)| o.memory_access && !o.has_computation) {
                    if runner.workers().iter().flat_map(|w| w.inner().computation_groups.iter())
                        .filter(|g| g.table.has_good_tree())
                        .flat_map(|g| g.iter())
                        .any(|c| c.encoding_index == encoding_index && c.output_index == output_index) {
                        partial = true;
                    } else {
                        full = false;
                    }
                }

                if full {
                    num_full += 1;
                } else if partial {
                    num_partial += 1;
                }
            }

            println!("{} complete, {} partially complete ({} encodings)", num_full, num_partial, encodings.len());
        }
    }

    Ok(())
}

fn main () { 
    env_logger::init();
    run().unwrap() 
}