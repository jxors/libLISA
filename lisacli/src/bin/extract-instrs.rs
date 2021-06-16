use std::{error::Error, fs::File, path::PathBuf};
use structopt::StructOpt;
use liblisa_core::arch::Instruction;

#[derive(StructOpt)]
struct Args {
    binary_path: PathBuf,

    #[structopt(long = "out")]
    outfile: PathBuf,
}

fn instr_len(itext: &[u8]) -> Option<usize> {
    let (mmode, stack_addr_width) = (xed_sys::XED_MACHINE_MODE_LONG_64, xed_sys::XED_ADDRESS_WIDTH_64b);
    unsafe {
        let mut xedd = ::std::mem::MaybeUninit::<xed_sys::xed_decoded_inst_t>::uninit();
        xed_sys::xed_decoded_inst_zero(xedd.as_mut_ptr());
        xed_sys::xed_decoded_inst_set_mode(xedd.as_mut_ptr(), mmode, stack_addr_width);

        let xed_error: xed_sys::xed_error_enum_t = xed_sys::xed_decode(xedd.as_mut_ptr(), itext.as_ptr(), itext.len() as u32);
        if xed_error == xed_sys::XED_ERROR_NONE {
            Some(xed_sys::xed_decoded_inst_get_length(&xedd.assume_init()) as usize)
        } else {
            None
        }
    }
}

fn run() -> Result<(), Box<dyn Error>> {
    unsafe {
        xed_sys::xed_tables_init();
    }

    let args = Args::from_args();
    let file = elf::File::open_path(args.binary_path)
        .expect("Unable to open ELF binary");
    let mut instructions = Vec::new();
    let section = file.get_section(".text").unwrap();
    let shdr = &section.shdr;
    if shdr.flags.0 & elf::types::SHF_ALLOC.0 != 0 {
        println!("Section {} @ {:X}..{:X}, size = {}, actual size = {}", shdr.name, shdr.addr, shdr.addr + shdr.size, shdr.size, section.data.len());

        let mut asm = &section.data[..];
        while asm.len() > 0 {
            let bytes = &asm[0..asm.len().min(16)];
            let len = instr_len(bytes);
            if let Some(len) = len {
                let instr_bytes = &bytes[..len];
                instructions.push(Instruction::new(instr_bytes));
                
                println!("Instruction: {:02X?}", instr_bytes);

                asm = &asm[len..];
            } else {
                println!("Unknown instruction: {:02X?}", bytes);
                break
            }
        }
    }

    println!("Saving {} instructions to {}", instructions.len(), args.outfile.display());
    serde_json::to_writer(File::create(args.outfile)?, &instructions)?;

    Ok(())
}

fn main () { 
    env_logger::init();
    run().unwrap() 
}