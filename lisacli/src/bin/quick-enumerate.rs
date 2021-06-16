use std::{collections::HashSet, marker::PhantomData};
use itertools::Itertools;
use liblisa::{enumeration::{EnumWorker, RuntimeWorkerData}, work::StateUpdater};
use liblisa_core::{arch::{Instruction, InstructionInfo}, counter::InstructionCounter};
use structopt::StructOpt;
use std::sync::atomic::AtomicBool;
use std::sync::mpsc::channel;
use liblisa::work::Worker;

#[global_allocator]
static GLOBAL: jemallocator::Jemalloc = jemallocator::Jemalloc;

fn hex_to_int(c: char) -> u8 {
    if c >= '0' && c <= '9' {
        c as u8 - '0' as u8
    } else if c >= 'A' && c <= 'F' {
        c as u8 - 'A' as u8 + 10
    } else {
        unimplemented!()
    }
}

fn hex_str_to_bytes(s: &str) -> Vec<u8> {
    let mut result = Vec::new();
    for mut byte in s.chars().map(|c| c.to_uppercase()).flatten().filter(|&c| c >= '0' && c <= '9' || c >= 'A' && c <= 'F').chunks(2).into_iter() {
        result.push(hex_to_int(byte.next().unwrap()) << 4 | hex_to_int(byte.next().unwrap()));
    }

    result
}

fn from_hex_str(s: &str) -> Instruction {
    Instruction::new(&hex_str_to_bytes(s))
}


#[derive(StructOpt)]
struct Args {
    #[structopt(parse(from_str = from_hex_str))]
    instr: Instruction,

    #[structopt(long = "to", parse(from_str = from_hex_str))]
    to: Option<Instruction>,
}

pub fn main() {
    env_logger::init();
    let args = Args::from_args();
    let counter = InstructionCounter::range(args.instr.as_instr(), args.to);
    let mut worker = EnumWorker {
        counter,
        unique_sequences: 0,
        next: None,
        instrs_seen: HashSet::new(),
        instrs_failed: Vec::new(),
        fast_tunnel: false,
        _phantom: PhantomData,
    };

    let (sender, _r) = channel();
    let (artifact_sender, _r) = channel();
    let (log_sender, _r) = channel();
    let updater = StateUpdater::new(0, sender, artifact_sender, log_sender);
    let rd = RuntimeWorkerData::new();

    let running = AtomicBool::new(true);
    worker.run(0, &running, &rd, updater).unwrap();
}