use std::{error::Error, fs::File, path::PathBuf, io::BufReader};
use liblisa_core::arch::{Instruction, InstructionInfo};
use structopt::StructOpt;

#[derive(StructOpt)]
struct Args {
    in_path: PathBuf,

    out_path: PathBuf,
}

pub fn main() -> Result<(), Box<dyn Error>> {
    let args = Args::from_args();

    let (mmode, stack_addr_width) = (xed_sys::XED_MACHINE_MODE_LONG_64, xed_sys::XED_ADDRESS_WIDTH_64b);
    unsafe { xed_sys::xed_tables_init() }

    let mut found: Vec<Instruction> = serde_json::from_reader(BufReader::new(File::open(args.in_path).unwrap())).unwrap();
    found.retain(|instr: &Instruction| {
        unsafe {
            let itext = instr.bytes();
            let mut xedd = ::std::mem::MaybeUninit::<xed_sys::xed_decoded_inst_t>::uninit();
            xed_sys::xed_decoded_inst_zero(xedd.as_mut_ptr());
            xed_sys::xed_decoded_inst_set_mode(xedd.as_mut_ptr(), mmode, stack_addr_width);

            let xed_error: xed_sys::xed_error_enum_t = xed_sys::xed_decode(xedd.as_mut_ptr(), itext.as_ptr(), itext.len() as u32);
            if xed_error == xed_sys::XED_ERROR_NONE {
                let instr = xedd.assume_init();
                let xi = xed_sys::xed_decoded_inst_inst(&instr);
                let mut out_of_scope = false;
                for n in 0..xed_sys::xed_decoded_inst_noperands(&instr) {
                    let op = xed_sys::xed_inst_operand(xi, n);
                    let op_name = xed_sys::xed_operand_name(op);
                    if xed_sys::xed_operand_is_register(op_name) != 0 {
                        match xed_sys::xed_decoded_inst_get_reg(&instr, op_name) {
                            xed_sys::XED_REG_CS | xed_sys::XED_REG_DS | xed_sys::XED_REG_ES 
                            | xed_sys::XED_REG_FS | xed_sys::XED_REG_GS | xed_sys::XED_REG_SS => {
                                out_of_scope = true;
                            }
                            _ => {},
                        }
                    }
                }

                if out_of_scope {
                    println!("Out of scope: {:02X?}", itext);
                    false
                } else if xed_sys::xed_decoded_inst_get_attribute(xedd.as_mut_ptr(), xed_sys::XED_ATTRIBUTE_RING0) == 1 {
                    println!("Ring 0: {:02X?}", itext);
                    false
                } else {
                    true
                }
            } else {
                true
            }
        }
    });

    serde_json::to_writer(File::create(args.out_path)?, &found)?;

    Ok(())
}