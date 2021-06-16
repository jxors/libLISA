use std::collections::HashMap;

use itertools::Itertools;
use liblisa_x64::{X64Flag, X64State, x64_simple_ptrace_oracle};
use liblisa_core::{Dest, GetDest, arch::{Instruction, InstructionInfo, MemoryState, Permissions, Register, State, SystemState}, oracle::Oracle};
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

fn hex_to_u64(s: &str) -> u64 {
    u64::from_str_radix(s, 16).unwrap()
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

fn parse_override(s: &str) -> (String, u64) {
    let mut split = s.split('=');
    let name = split.next().unwrap();
    let value = u64::from_str_radix(split.next().unwrap(), 16).unwrap();

    (name.to_owned(), value)
}

fn parse_memory(s: &str) -> (u64, Vec<u8>) {
    let mut split = s.split('=');
    let addr = split.next().unwrap();
    let value = hex_str_to_bytes(split.next().unwrap());

    (hex_to_u64(addr), value)
}


#[derive(StructOpt)]
struct Args {
    #[structopt(parse(from_str = from_hex_str))]
    instr: Instruction,

    #[structopt(short = "r", parse(from_str = parse_override))]
    overrides: Vec<(String, u64)>,

    #[structopt(short = "m", parse(from_str = parse_memory))]
    memory: Vec<(u64, Vec<u8>)>,

    #[structopt(long = "rip", parse(from_str = hex_to_u64))]
    rip: Option<u64>,

    #[structopt(long = "careful")]
    careful: bool,

    #[structopt(long = "repeat", default_value = "1")]
    repeat: usize,
}

pub fn main() {
    env_logger::init();
    let args = Args::from_args();
    let mut o = x64_simple_ptrace_oracle();
    let pc = args.rip.unwrap_or(o.valid_executable_addresses().start);
    let instr = args.instr;
    let overrides = args.overrides.into_iter().collect::<HashMap<_, _>>();
    let mut mem = vec![
        (pc, Permissions::Execute, instr.bytes().to_owned())
    ];

    for (addr, data) in args.memory.into_iter() {
        mem.push((addr, Permissions::ReadWrite, data));
    }

    let state = SystemState::new(X64State::create(|reg| if reg.is_pc() {
        pc
    } else {
        overrides.get(&format!("{}", reg)).cloned().unwrap_or(0)
    }, |_| false), MemoryState::new(mem.into_iter()));

    println!("Input {:X?}", state);

    for _ in 0..args.repeat {
        let output = if args.careful {
            o.observe_carefully(&state).unwrap()
        } else {
            o.observe(&state).unwrap()
        };
        println!("Output {:X?}", output);
        let d = Dest::Flag(X64Flag::Zf);
        println!("{} = {}", d, output.get_dest(&d, |r| format!("{:?}", r)));
    }
}