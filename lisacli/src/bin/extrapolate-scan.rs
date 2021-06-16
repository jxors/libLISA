use std::{error::Error, fs::File, io::BufReader, path::PathBuf};
use liblisa_core::arch::{Arch, Instruction, InstructionInfo};
use liblisa_enc::Validity;
use liblisa_x64::{X64Arch, x64_kmod_ptrace_oracle};
use rayon::prelude::*;
use structopt::StructOpt;

#[derive(StructOpt)]
struct Args {
    input: PathBuf,
    output: PathBuf,
}

fn add_prefix(instrs: &[Instruction], prefix: &[u8], output: &mut Vec<Instruction>) {
    for instr in instrs.iter() {
        let mut new_data = [0u8; 16];
        new_data[..prefix.len()].copy_from_slice(prefix);
        new_data[prefix.len()..prefix.len() + instr.byte_len()].copy_from_slice(instr.bytes());

        output.push(Instruction::new(&new_data[..prefix.len() + instr.byte_len()]));
    }
}

pub fn main() -> Result<(), Box<dyn Error>> {
    let args = Args::from_args();
    let mut instrs: Vec<Instruction> = serde_json::from_reader(BufReader::new(File::open(args.input).unwrap())).unwrap();
    let base_instrs = instrs.clone();

    instrs.sort();
    instrs.dedup();

    println!("Loaded {} instructions", instrs.len());
    
    let mut output = instrs.clone();

    instrs.retain(|instr: &Instruction| {
        X64Arch::is_instruction_included(instr.bytes()) && match instr.bytes()[0] {
            n if n & 0xf0 == 0x40 => false,
            0xF0 | 0xF2 | 0xF3 | 0x66 => false,
            _ => true,
        }
    });

    add_prefix(&instrs, &[ 0x66 ], &mut output);
    for rex in 0x40..0x50 {
        add_prefix(&instrs, &[ rex ], &mut output);
        add_prefix(&instrs, &[ 0x66, rex ], &mut output);
        add_prefix(&instrs, &[ 0xf0, rex ], &mut output);
        add_prefix(&instrs, &[ 0xf2, rex ], &mut output);
        add_prefix(&instrs, &[ 0xf3, rex ], &mut output);
        add_prefix(&instrs, &[ 0xf0, 0x66, rex ], &mut output);
        add_prefix(&instrs, &[ 0xf2, 0x66, rex ], &mut output);
        add_prefix(&instrs, &[ 0xf3, 0x66, rex ], &mut output);
    }

    output.extend(base_instrs.into_iter());

    println!("After extrapolation: {}", output.len());

    output.sort();
    output.dedup();

    println!("After deduplication: {}", output.len());

    let outputs = output.chunks(500_000).map(|x| x.to_vec()).collect::<Vec<_>>();
    let outputs = outputs.into_par_iter().enumerate().map(|(index, mut output)| {
        let mut o = x64_kmod_ptrace_oracle();
        let mut n = 0;
        let mut removed = 0;
        let len = output.len();
        output.retain(|instr| {
            n += 1;
            if n % 10_000 == 0 {
                println!("[{:02}] {:.1}k / {:.1}k: {:.1} removed", index as f64 / 1000., n, len as f64 / 1000., removed as f64 / 1000.);
            }

            if Validity::infer(&mut o, instr.as_instr()) == Validity::Ok {
                true
            } else {
                removed += 1;
                false
            }
        });

        output
    }).collect::<Vec<_>>();

    let output = outputs.into_iter().flat_map(|o| o.into_iter()).collect::<Vec<_>>();

    println!("Final number of instructions found: {}", output.len());

    serde_json::to_writer(File::create(args.output)?, &output).unwrap();

    Ok(())
}