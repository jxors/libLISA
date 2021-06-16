use std::{error::Error, path::PathBuf};
use capstone::{Capstone, arch::{self, BuildsCapstone, BuildsCapstoneSyntax}};
use liblisa::{enumeration::{EnumWorker, cleanup}, work::Work};
use liblisa_x64::arch::X64Arch;
use liblisa_core::arch::{Instruction, InstructionInfo};
use lisacli::SavePath;
use structopt::StructOpt;

#[derive(StructOpt)]
struct Args {
    #[structopt(long = "dir")]
    dir: PathBuf,
}

fn main() -> Result<(), Box<dyn Error>> {
    env_logger::init();
    let args = Args::from_args();
    let save_paths = SavePath::from(args.dir);

    let (mmode, stack_addr_width) = (xed_sys::XED_MACHINE_MODE_LONG_64, xed_sys::XED_ADDRESS_WIDTH_64b);
    unsafe {
        xed_sys::xed_tables_init();
    }

    let runner = Work::<EnumWorker<X64Arch>, Instruction, _>::load(save_paths)?;
    let mut encodings = runner.artifacts().iter().cloned().collect::<Vec<_>>();
    encodings.retain(|e| e.filters().len() > 0);
    encodings.sort_by_cached_key(|e| e.filters()[0].smallest_matching_instruction().bytes().to_vec());

    let encodings = cleanup(encodings);

    let cs = Capstone::new()
        .x86()
        .mode(arch::x86::ArchMode::Mode64)
        .syntax(arch::x86::ArchSyntax::Att)
        .detail(false)
        .build()
        .unwrap();
    
    for (encoding_index, encoding) in encodings.iter().enumerate() {
        println!();
        println!("---");
        println!();
        println!("Encoding {:02X?} ({} / {})", encoding.instr().bytes(), encoding_index, encodings.len());
        println!("{}", encoding);

        for instance in encoding.iter(&encoding.parts.iter().map(|p| if p.size() <= 4 {
            None 
        } else {
            Some(p.value)   
        }).collect::<Vec<_>>()) {
            unsafe {
                let itext = instance.instr().bytes();
                let mut xedd = ::std::mem::MaybeUninit::<xed_sys::xed_decoded_inst_t>::uninit();
                xed_sys::xed_decoded_inst_zero(xedd.as_mut_ptr());
                xed_sys::xed_decoded_inst_set_mode(xedd.as_mut_ptr(), mmode, stack_addr_width);
    
                let xed_error: xed_sys::xed_error_enum_t = xed_sys::xed_decode(xedd.as_mut_ptr(), itext.as_ptr(), itext.len() as u32);
                let desc = std::ffi::CStr::from_ptr(xed_sys::xed_error_enum_t2str(xed_error)).to_string_lossy();
                if xed_error != xed_sys::XED_ERROR_NONE {
                    println!("error={} for {:02X?}", desc, instance.instr().bytes());
                }
            };

            let isns = cs.disasm_all(instance.instr().bytes(), 0x0).unwrap();
            if isns.iter().next().is_none() {
                println!("Capstone failed for {:02X?}", instance.instr().bytes());
            }
        }
    }

    Ok(())
}