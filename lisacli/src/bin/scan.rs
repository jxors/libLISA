use std::{collections::{HashMap, HashSet}, error::Error, fs::File, io::BufReader, path::PathBuf, sync::{Arc, atomic::{AtomicUsize, AtomicBool, Ordering}, mpsc::{RecvTimeoutError, Sender, channel}}, time::{Duration, Instant}};
use liblisa_core::{arch::{Arch, Instr, Instruction, InstructionInfo}, counter::InstructionCounter};
use liblisa_enc::Validity;
use liblisa_x64::{X64Arch, x64_kmod_ptrace_oracle};
use rand::Rng;
use std::process::exit;
use structopt::StructOpt;

fn smallize(instr: Instr<'_>) -> u128 {
    let mut bytes = [0u8; 16];
    (&mut bytes[..instr.byte_len()]).copy_from_slice(instr.bytes());
    u128::from_le_bytes(bytes)
}

fn run_worker(index: usize, ch: Sender<(usize, Instruction)>, running: Arc<AtomicBool>) -> Result<(), Box<dyn Error>> {
    let mut o = x64_kmod_ptrace_oracle();
    let mut buf = [0u8; 16];
    let mut rng = rand::thread_rng();
    let mut cache = HashMap::new();
    let mut found = HashSet::new();
    for _ in 0..=1_000_000_000 {
        rng.fill(&mut buf);

        // Force first nibble to prevent overlaping random instructions between the threads
        buf[0] = (buf[0] & 0xf) | ((index as u8) << 4);
        
        let mut min = 1;
        let mut max = buf.len();
        for _ in 0..4 {
            let guessed_len = (min + max) / 2;
            let instr: Instr = buf[0..guessed_len].as_ref().into();
            
            match cache.entry(smallize(instr))
                .or_insert_with(|| Validity::infer(&mut o, instr)) {
                Validity::TooShort => min = guessed_len + 1,
                Validity::TooLong => max = guessed_len - 1,
                Validity::InvalidInstruction | Validity::Excluded => break,
                Validity::Ok => {
                    let mut c = InstructionCounter::range(instr, None);
                    let mut last_instr = instr.as_instruction();
                    while c.tunnel_next(0) {
                        match cache.entry(smallize(c.current()))
                            .or_insert_with(|| Validity::infer(&mut o, c.current())) {
                            Validity::Ok => {
                                last_instr = c.current().as_instruction();
                            },
                            _ => break,
                        }
                    }

                    if !found.contains(&last_instr) {
                        found.insert(last_instr.clone());
                        ch.send((index, last_instr))?;
                    }
                    break
                }
            }
        }

        if !running.load(Ordering::SeqCst) {
            break;
        }
    }

    Ok(())
}

#[derive(StructOpt)]
struct Args {
    #[structopt(long = "continue")]
    continue_path: Option<PathBuf>,

    output: PathBuf,
}

pub fn main() -> Result<(), Box<dyn Error>> {
    let args = Args::from_args();
    let threads = 16;

    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    ctrlc::set_handler(move || {
        if !r.load(Ordering::SeqCst) {
            eprintln!("Aborting without saving!");

            // TODO: Gracefully exit with another atomicbool
            exit(0);
        } else {
            eprintln!("Received Control+C! Saving & quitting on next instruction!");
            r.store(false, Ordering::SeqCst);
        }
    }).expect("Error setting Ctrl-C handler");

    let mut found = args.continue_path.map(|path| {
        serde_json::from_reader(BufReader::new(File::open(path).unwrap())).unwrap()
    }).unwrap_or(Vec::new());

    let start = Instant::now();
    let (sender, receiver) = channel();
    let threads_running = Box::leak(Box::new(AtomicUsize::new(0))) as &AtomicUsize;
    let threads = (0..threads).map(|index| {
        let sender = sender.clone();
        let running = running.clone();

        std::thread::Builder::new()
            .name(format!("Worker #{}", index))
            .spawn(move || {
                let n = threads_running.fetch_add(1, Ordering::SeqCst);
                println!("[{:02}] Workers started: {}", index, n);
                run_worker(index, sender, running.clone()).unwrap();
                let n = threads_running.fetch_sub(1, Ordering::SeqCst);
                println!("[{:02}] Workers remaining: {}", index, n.checked_sub(1).unwrap_or(0));
            })
            .expect("Unable to start worker thread")
    }).collect::<Vec<_>>();

    found.retain(|instr: &Instruction| {
        X64Arch::is_instruction_included(instr.bytes())
    });

    let mut last_save = Instant::now();
    let mut new = 0usize;
    loop {
        let loop_start = Instant::now();
        loop {
            match receiver.recv_timeout(Duration::from_secs(1)) {
                Ok((_index, instr)) => {
                    if !found.contains(&instr) {
                        found.push(instr);
                        println!("[{:02}] Found: {:02X?} (total is now {})", _index, instr.bytes(), found.len());
                        new += 1;
                    }
                },
                Err(RecvTimeoutError::Timeout) => break,
                Err(RecvTimeoutError::Disconnected) => break,
            }

            if Instant::now() - loop_start > Duration::from_secs(30) {
                break
            }
        }

        let seconds_running = (Instant::now() - start).as_secs();
        println!("Found {:.2}k instructions in {}h {}m {}s (~{:.1}k/hour)", new as f64 / 1000., seconds_running / 3600, (seconds_running / 60) % 60, seconds_running % 60, (new as f64 / 1000.) / (seconds_running as f64 / (3600.0)));

        if Instant::now() - last_save > Duration::from_secs(60 * 15) {
            last_save = Instant::now();
            found.sort();
            found.dedup();
            println!("Saving progress @ {} instructions", found.len());
            serde_json::to_writer(File::create(&args.output)?, &found)?;
        }

        if threads_running.load(Ordering::SeqCst) <= 0 {
            break;
        }
    }

    println!("Waiting for all threads to finish...");
    let _ = threads.into_iter().map(|t| t.join()).collect::<Vec<_>>();

    found.sort();
    found.dedup();

    for instr in found.iter() {
        println!("Instruction: {:02X?}", instr.bytes());
    }

    println!("Final number of instructions found: {}", found.len());

    serde_json::to_writer(File::create(&args.output)?, &found)?;

    Ok(())
}