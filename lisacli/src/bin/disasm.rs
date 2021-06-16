use std::{error::Error, path::PathBuf};
use liblisa::{enumeration::EnumWorker, work::Work};
use lisacli::SavePath;
use structopt::StructOpt;
use liblisa_x64::arch::X64Arch;
use liblisa_core::arch::{Instr, Instruction, InstructionInfo};

#[global_allocator]
static GLOBAL: jemallocator::Jemalloc = jemallocator::Jemalloc;

#[derive(StructOpt)]
struct Args {
    #[structopt(long = "dir")]
    dir: PathBuf,

    #[structopt(long = "binary-path")]
    binary_path: PathBuf,
}

#[derive(Copy, Clone, Default, Debug)]
struct Stats {
    found: usize,
    missed: usize,
    total: usize,
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
    let save_paths = SavePath::from(args.dir);
    
    let runner = Work::<EnumWorker<X64Arch>, Instruction, _>::load(save_paths)?;
    let workers = runner.workers();
    let encodings = runner.artifacts().iter().collect::<Vec<_>>();

    let mapping = encodings.iter().flat_map(|e| e.filters().into_iter().map(move |f| (f, e))).collect::<Vec<_>>();
    let file = elf::File::open_path(args.binary_path)
        .expect("Unable to open ELF binary");

    let mut num_ok = 0usize;
    let mut num_missed = 0usize;
    let mut num_unseen = 0usize;

    let section = file.get_section(".text").unwrap();
    let shdr = &section.shdr;
    if shdr.flags.0 & elf::types::SHF_ALLOC.0 != 0 {
        println!("Section {} @ {:X}..{:X}, size = {}, actual size = {}", shdr.name, shdr.addr, shdr.addr + shdr.size, shdr.size, section.data.len());

        let mut asm = &section.data[..];
        while asm.len() > 0 {
            if let Some((filter, encoding)) = mapping.iter()
                .filter(|(f, _)| f.len() <= asm.len() && f.matches(&Instr::from(&asm[0..f.len()])))
                .next() {
                let instr = Instr::from(&asm[0..filter.len()]);
                let parts = encoding.extract_parts(instr);
                let instantiated = encoding.instantiate(&parts).unwrap();

                println!("{}", instantiated);
                asm = &asm[filter.len()..];

                num_ok += 1;
            } else {
                let bytes = &asm[0..asm.len().min(16)];
                let instr = Instr::from(bytes);
                let worker = workers.iter()
                    .position(|w| instr >= w.from().as_instr() && w.to().as_ref().map(|to| instr <= to.as_instr()).unwrap_or(true))
                    .unwrap();

                if workers[worker].inner().counter.current() > instr.as_instr() {
                    num_missed += 1;
                } else {
                    num_unseen += 1;
                }

                let len = instr_len(bytes);
                if let Some(len) = len {
                    println!("Unknown instruction: {:02X?}", &bytes[..len]);
                    asm = &asm[len..];
                } else {
                    println!("Unknown instruction: {:02X?}", bytes);
                    break
                }
            }
        }
    }

    println!("Ok    : {} / {} = {:.2}%", num_ok, num_ok + num_missed + num_unseen, num_ok as f64 * 100. / (num_ok + num_missed + num_unseen) as f64);
    println!("Unseen: {} / {} = {:.2}%", num_unseen, num_ok + num_missed + num_unseen, num_unseen as f64 * 100. / (num_ok + num_missed + num_unseen) as f64);
    println!("Missed: {} / {} = {:.2}%", num_missed, num_ok + num_missed + num_unseen, num_missed as f64 * 100. / (num_ok + num_missed + num_unseen) as f64);
    println!("Ok (partial): {} / {} = {:.2}%", num_ok, num_ok + num_missed, num_ok as f64 * 100. / (num_ok + num_missed) as f64);

    Ok(())
}

fn main () { 
    env_logger::init();
    run().unwrap() 
}