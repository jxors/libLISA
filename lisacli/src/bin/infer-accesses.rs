use itertools::Itertools;
use liblisa_enc::accesses::MemoryAccessAnalysis;
use liblisa_x64::x64_simple_ptrace_oracle;
use liblisa_core::arch::{Instruction, InstructionInfo};
use structopt::StructOpt;

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
    let mut o = x64_simple_ptrace_oracle();
    let instr = args.instr;
    
    let accesses = MemoryAccessAnalysis::infer(&mut o, instr.as_instr());
    println!("Accesses ({}): {:#?}", accesses.as_ref().map(|m| m.len()).unwrap_or(0), accesses);
}