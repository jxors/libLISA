use itertools::Itertools;
use liblisa::learn_instr;
use liblisa_core::arch::{Instruction, InstructionInfo};
use structopt::StructOpt;

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
}

pub fn main() {
    env_logger::init();
    let args = Args::from_args();
    let instr = args.instr.as_instr();
    let encodings = learn_instr(instr).unwrap();

    println!("Result: {:?}", encodings);
}