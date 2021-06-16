use std::{error::Error, fs::File, io::BufReader, path::PathBuf};
use liblisa::correctness::CorrectnessWorker;
use liblisa::enumeration::EnumWorker;
use liblisa::synthesis::SynthesisWorker;
use liblisa::work::Work;
use liblisa::{FilterMap, synthesis::DecisionTreeComputation};
use liblisa_core::Encoding;
use liblisa_core::computation::BasicComputation;
use lisacli::SavePath;
use structopt::StructOpt;
use liblisa_x64::arch::X64Arch;
use liblisa_core::arch::{Instruction, InstructionInfo};
use std::io::Write;

#[global_allocator]
static GLOBAL: jemallocator::Jemalloc = jemallocator::Jemalloc;

#[derive(StructOpt)]
struct Args {
    #[structopt(long = "enumeration-dir")]
    enumeration_dir: PathBuf,

    #[structopt(long = "addr-synthesis-dir")]
    addr_synthesis_dir: PathBuf,

    #[structopt(long = "dataflow-synthesis-dir")]
    dataflow_synthesis_dir: PathBuf,

    #[structopt(long = "correctness-dir")]
    correctness_dir: PathBuf,

    #[structopt(long = "enumerated-export")]
    enumerated_export_file: PathBuf,

    #[structopt(long = "instrs")]
    instructions: Vec<PathBuf>,

    #[structopt(long = "correctness-out")]
    correctness_out: PathBuf,

    #[structopt(long = "completeness-out")]
    completeness_out: PathBuf,

    #[structopt(long = "coverage-out")]
    coverage_out: PathBuf,

    #[structopt(long = "stats-out")]
    stats_out: PathBuf,
}

#[derive(Copy, Clone, Default, Debug)]
struct Stats {
    correct: usize,
    not_synthesized: usize,
    incorrect: usize,

    seen_correct: usize,
    seen_not_synthesized: usize,
    seen_incorrect: usize,
    seen_ring0: usize,
    seen_out_of_scope: usize,

    missed: usize,
    ring0: usize,
    out_of_scope: usize,
    total: usize,
    total_in_scope: usize,
    seen: usize,

    enum_covered: usize,

    found: usize,
    unseen_found: usize,
}

impl Stats {
    pub fn completeness(&self) -> f64 {
        self.found as f64 * 100. / self.seen as f64
    }

    pub fn correctness(&self) -> f64 {
        self.seen_correct as f64 * 100. / (self.seen_correct + self.seen_incorrect) as f64
    }

    pub fn relative_coverage(&self) -> f64 {
        self.seen_correct as f64 * 100. / self.enum_covered as f64
    }

    pub fn absolute_coverage(&self) -> f64 {
        self.correct as f64 * 100. / self.total as f64
    }
}

fn run() -> Result<(), Box<dyn Error>> {
    let args = Args::from_args();
    let enumeration_save_paths = SavePath::from(args.enumeration_dir);
    let enumeration_runner = Work::<EnumWorker<X64Arch>, Instruction, _>::load(enumeration_save_paths)?;
    let enumeration_workers = enumeration_runner.workers();

    let enumerated_encodings: Vec<Encoding<X64Arch, BasicComputation>> = serde_json::from_reader(BufReader::new(File::open(args.enumerated_export_file)?))?;

    let addr_synthesis_save_paths = SavePath::from(args.addr_synthesis_dir);
    let addr_synthesis_runner = Work::<SynthesisWorker<X64Arch, BasicComputation>, usize, _>::load(addr_synthesis_save_paths)?;
    let addr_synthesis_workers = addr_synthesis_runner.workers();

    let dataflow_synthesis_save_paths = SavePath::from(args.dataflow_synthesis_dir);
    let dataflow_synthesis_runner = Work::<SynthesisWorker<X64Arch, BasicComputation>, usize, _>::load(dataflow_synthesis_save_paths)?;
    let dataflow_synthesis_workers = dataflow_synthesis_runner.workers();

    let correctness_save_paths = SavePath::from(args.correctness_dir);
    let correctness_runner = Work::<CorrectnessWorker<X64Arch, DecisionTreeComputation>, usize, _>::load(correctness_save_paths)?;
    let correctness_workers = correctness_runner.workers();

    println!("Loading encodings...");
    let encodings = enumeration_runner.artifacts().iter().collect::<Vec<_>>();
    let mut filters = FilterMap::new();
    for filter in encodings.iter()
        .flat_map(|e| e.filters().into_iter()) {
        filters.add(filter, ());
    }

    println!("Loading correctness...");
    let correctness = correctness_workers.iter().flat_map(|w| w.inner().encodings.iter().cloned()).collect::<Vec<_>>();
    let mut correctness_map = FilterMap::new();
    for c in correctness.iter() {
        for filter in c.encoding.filters() {
            correctness_map.add(filter, c);
        }
    }

    let (mmode, stack_addr_width) = (xed_sys::XED_MACHINE_MODE_LONG_64, xed_sys::XED_ADDRESS_WIDTH_64b);
    unsafe { xed_sys::xed_tables_init() }

    let mut all_stats = Vec::new();
    for instrs_file in args.instructions {
        print!("Loading {}", instrs_file.display());
        let mut scan_instrs: Vec<Instruction> = serde_json::from_reader(BufReader::new(File::open(&instrs_file)?))?;
        scan_instrs.sort();
        scan_instrs.dedup();

        let stats = {
            let mut stats = Stats::default();
            for chunk in scan_instrs.chunks(10_000) {
                print!(".");
                std::io::stdout().lock().flush().unwrap();
                for instr in chunk.iter() {
                    let instr = X64Arch::normalize_instr(instr.as_instr());
                    let (is_ring0, out_of_scope_reg) = unsafe {
                        let itext = instr.bytes();
                        let mut xedd = ::std::mem::MaybeUninit::<xed_sys::xed_decoded_inst_t>::uninit();
                            xed_sys::xed_decoded_inst_zero(xedd.as_mut_ptr());
                            xed_sys::xed_decoded_inst_set_mode(xedd.as_mut_ptr(), mmode, stack_addr_width);

                        let xed_error: xed_sys::xed_error_enum_t = xed_sys::xed_decode(xedd.as_mut_ptr(), itext.as_ptr(), itext.len() as u32);
                        let desc = std::ffi::CStr::from_ptr(xed_sys::xed_error_enum_t2str(xed_error)).to_string_lossy();
                        if xed_error == xed_sys::XED_ERROR_NONE {
                            let instr = xedd.assume_init();
                            let xi = xed_sys::xed_decoded_inst_inst(&instr);
                            let mut out_of_scope = false;
                            for n in 0..xed_sys::xed_decoded_inst_noperands(&instr) {
                                let op = xed_sys::xed_inst_operand(xi, n);
                                let op_name = xed_sys::xed_operand_name(op);
                                if xed_sys::xed_operand_is_register(op_name) != 0 {
                                    match xed_sys::xed_decoded_inst_get_reg(&instr, op_name) {
                                        xed_sys::XED_REG_INVALID | xed_sys::XED_REG_BNDCFGU | xed_sys::XED_REG_BNDSTATUS | xed_sys::XED_REG_BND0 | xed_sys::XED_REG_BND1 | xed_sys::XED_REG_BND2 | xed_sys::XED_REG_BND3 | xed_sys::XED_REG_CR0 | xed_sys::XED_REG_CR1 | xed_sys::XED_REG_CR2 | xed_sys::XED_REG_CR3 | xed_sys::XED_REG_CR4 | xed_sys::XED_REG_CR5 | xed_sys::XED_REG_CR6 | xed_sys::XED_REG_CR7 | xed_sys::XED_REG_CR8 | xed_sys::XED_REG_CR9 | xed_sys::XED_REG_CR10 | xed_sys::XED_REG_CR11 | xed_sys::XED_REG_CR12 | xed_sys::XED_REG_CR13 | xed_sys::XED_REG_CR14 | xed_sys::XED_REG_CR15 | xed_sys::XED_REG_DR0 | xed_sys::XED_REG_DR1 | xed_sys::XED_REG_DR2 | xed_sys::XED_REG_DR3 | xed_sys::XED_REG_DR4 | xed_sys::XED_REG_DR5 | xed_sys::XED_REG_DR6 | xed_sys::XED_REG_DR7 | xed_sys::XED_REG_ERROR | xed_sys::XED_REG_RIP | xed_sys::XED_REG_EIP | xed_sys::XED_REG_IP | xed_sys::XED_REG_K0 | xed_sys::XED_REG_K1 | xed_sys::XED_REG_K2 | xed_sys::XED_REG_K3 | xed_sys::XED_REG_K4 | xed_sys::XED_REG_K5 | xed_sys::XED_REG_K6 | xed_sys::XED_REG_K7 | xed_sys::XED_REG_MMX0 | xed_sys::XED_REG_MMX1 | xed_sys::XED_REG_MMX2 | xed_sys::XED_REG_MMX3 | xed_sys::XED_REG_MMX4 | xed_sys::XED_REG_MMX5 | xed_sys::XED_REG_MMX6 | xed_sys::XED_REG_MMX7 | xed_sys::XED_REG_SSP | xed_sys::XED_REG_IA32_U_CET | xed_sys::XED_REG_MXCSR | xed_sys::XED_REG_GDTR | xed_sys::XED_REG_LDTR | xed_sys::XED_REG_IDTR | xed_sys::XED_REG_TR | xed_sys::XED_REG_TSC | xed_sys::XED_REG_TSCAUX | xed_sys::XED_REG_MSRS | xed_sys::XED_REG_FSBASE | xed_sys::XED_REG_GSBASE | xed_sys::XED_REG_X87CONTROL | xed_sys::XED_REG_X87STATUS | xed_sys::XED_REG_X87TAG | xed_sys::XED_REG_X87PUSH | xed_sys::XED_REG_X87POP | xed_sys::XED_REG_X87POP2 | xed_sys::XED_REG_X87OPCODE | xed_sys::XED_REG_X87LASTCS | xed_sys::XED_REG_X87LASTIP | xed_sys::XED_REG_X87LASTDS | xed_sys::XED_REG_X87LASTDP | xed_sys::XED_REG_ES | xed_sys::XED_REG_CS | xed_sys::XED_REG_SS | xed_sys::XED_REG_DS | xed_sys::XED_REG_FS | xed_sys::XED_REG_GS | xed_sys::XED_REG_TMP0 | xed_sys::XED_REG_TMP1 | xed_sys::XED_REG_TMP2 | xed_sys::XED_REG_TMP3 | xed_sys::XED_REG_TMP4 | xed_sys::XED_REG_TMP5 | xed_sys::XED_REG_TMP6 | xed_sys::XED_REG_TMP7 | xed_sys::XED_REG_TMP8 | xed_sys::XED_REG_TMP9 | xed_sys::XED_REG_TMP10 | xed_sys::XED_REG_TMP11 | xed_sys::XED_REG_TMP12 | xed_sys::XED_REG_TMP13 | xed_sys::XED_REG_TMP14 | xed_sys::XED_REG_TMP15 | xed_sys::XED_REG_ST0 | xed_sys::XED_REG_ST1 | xed_sys::XED_REG_ST2 | xed_sys::XED_REG_ST3 | xed_sys::XED_REG_ST4 | xed_sys::XED_REG_ST5 | xed_sys::XED_REG_ST6 | xed_sys::XED_REG_ST7 | xed_sys::XED_REG_XCR0 | xed_sys::XED_REG_XMM0 | xed_sys::XED_REG_XMM1 | xed_sys::XED_REG_XMM2 | xed_sys::XED_REG_XMM3 | xed_sys::XED_REG_XMM4 | xed_sys::XED_REG_XMM5 | xed_sys::XED_REG_XMM6 | xed_sys::XED_REG_XMM7 | xed_sys::XED_REG_XMM8 | xed_sys::XED_REG_XMM9 | xed_sys::XED_REG_XMM10 | xed_sys::XED_REG_XMM11 | xed_sys::XED_REG_XMM12 | xed_sys::XED_REG_XMM13 | xed_sys::XED_REG_XMM14 | xed_sys::XED_REG_XMM15 | xed_sys::XED_REG_XMM16 | xed_sys::XED_REG_XMM17 | xed_sys::XED_REG_XMM18 | xed_sys::XED_REG_XMM19 | xed_sys::XED_REG_XMM20 | xed_sys::XED_REG_XMM21 | xed_sys::XED_REG_XMM22 | xed_sys::XED_REG_XMM23 | xed_sys::XED_REG_XMM24 | xed_sys::XED_REG_XMM25 | xed_sys::XED_REG_XMM26 | xed_sys::XED_REG_XMM27 | xed_sys::XED_REG_XMM28 | xed_sys::XED_REG_XMM29 | xed_sys::XED_REG_XMM30 | xed_sys::XED_REG_XMM31 | xed_sys::XED_REG_YMM0 | xed_sys::XED_REG_YMM1 | xed_sys::XED_REG_YMM2 | xed_sys::XED_REG_YMM3 | xed_sys::XED_REG_YMM4 | xed_sys::XED_REG_YMM5 | xed_sys::XED_REG_YMM6 | xed_sys::XED_REG_YMM7 | xed_sys::XED_REG_YMM8 | xed_sys::XED_REG_YMM9 | xed_sys::XED_REG_YMM10 | xed_sys::XED_REG_YMM11 | xed_sys::XED_REG_YMM12 | xed_sys::XED_REG_YMM13 | xed_sys::XED_REG_YMM14 | xed_sys::XED_REG_YMM15 | xed_sys::XED_REG_YMM16 | xed_sys::XED_REG_YMM17 | xed_sys::XED_REG_YMM18 | xed_sys::XED_REG_YMM19 | xed_sys::XED_REG_YMM20 | xed_sys::XED_REG_YMM21 | xed_sys::XED_REG_YMM22 | xed_sys::XED_REG_YMM23 | xed_sys::XED_REG_YMM24 | xed_sys::XED_REG_YMM25 | xed_sys::XED_REG_YMM26 | xed_sys::XED_REG_YMM27 | xed_sys::XED_REG_YMM28 | xed_sys::XED_REG_YMM29 | xed_sys::XED_REG_YMM30 | xed_sys::XED_REG_YMM31 | xed_sys::XED_REG_ZMM0 | xed_sys::XED_REG_ZMM1 | xed_sys::XED_REG_ZMM2 | xed_sys::XED_REG_ZMM3 | xed_sys::XED_REG_ZMM4 | xed_sys::XED_REG_ZMM5 | xed_sys::XED_REG_ZMM6 | xed_sys::XED_REG_ZMM7 | xed_sys::XED_REG_ZMM8 | xed_sys::XED_REG_ZMM9 | xed_sys::XED_REG_ZMM10 | xed_sys::XED_REG_ZMM11 | xed_sys::XED_REG_ZMM12 | xed_sys::XED_REG_ZMM13 | xed_sys::XED_REG_ZMM14 | xed_sys::XED_REG_ZMM15 | xed_sys::XED_REG_ZMM16 | xed_sys::XED_REG_ZMM17 | xed_sys::XED_REG_ZMM18 | xed_sys::XED_REG_ZMM19 | xed_sys::XED_REG_ZMM20 | xed_sys::XED_REG_ZMM21 | xed_sys::XED_REG_ZMM22 | xed_sys::XED_REG_ZMM23 | xed_sys::XED_REG_ZMM24 | xed_sys::XED_REG_ZMM25 | xed_sys::XED_REG_ZMM26 | xed_sys::XED_REG_ZMM27 | xed_sys::XED_REG_ZMM28 | xed_sys::XED_REG_ZMM29 | xed_sys::XED_REG_ZMM30 | xed_sys::XED_REG_ZMM31                            
                                        => {
                                            // We consider use of all these registers out of scope
                                            out_of_scope = true;
                                        }
                                        xed_sys::XED_REG_FLAGS | xed_sys::XED_REG_EFLAGS | xed_sys::XED_REG_RFLAGS | xed_sys::XED_REG_AX | xed_sys::XED_REG_CX | xed_sys::XED_REG_DX | xed_sys::XED_REG_BX | xed_sys::XED_REG_SP | xed_sys::XED_REG_BP | xed_sys::XED_REG_SI | xed_sys::XED_REG_DI | xed_sys::XED_REG_R8W | xed_sys::XED_REG_R9W | xed_sys::XED_REG_R10W | xed_sys::XED_REG_R11W | xed_sys::XED_REG_R12W | xed_sys::XED_REG_R13W | xed_sys::XED_REG_R14W | xed_sys::XED_REG_R15W | xed_sys::XED_REG_EAX | xed_sys::XED_REG_ECX | xed_sys::XED_REG_EDX | xed_sys::XED_REG_EBX | xed_sys::XED_REG_ESP | xed_sys::XED_REG_EBP | xed_sys::XED_REG_ESI | xed_sys::XED_REG_EDI | xed_sys::XED_REG_R8D | xed_sys::XED_REG_R9D | xed_sys::XED_REG_R10D | xed_sys::XED_REG_R11D | xed_sys::XED_REG_R12D | xed_sys::XED_REG_R13D | xed_sys::XED_REG_R14D | xed_sys::XED_REG_R15D | xed_sys::XED_REG_RAX | xed_sys::XED_REG_RCX | xed_sys::XED_REG_RDX | xed_sys::XED_REG_RBX | xed_sys::XED_REG_RSP | xed_sys::XED_REG_RBP | xed_sys::XED_REG_RSI | xed_sys::XED_REG_RDI | xed_sys::XED_REG_R8 | xed_sys::XED_REG_R9 | xed_sys::XED_REG_R10 | xed_sys::XED_REG_R11 | xed_sys::XED_REG_R12 | xed_sys::XED_REG_R13 | xed_sys::XED_REG_R14 | xed_sys::XED_REG_R15 | xed_sys::XED_REG_AL | xed_sys::XED_REG_CL | xed_sys::XED_REG_DL | xed_sys::XED_REG_BL | xed_sys::XED_REG_SPL | xed_sys::XED_REG_BPL | xed_sys::XED_REG_SIL | xed_sys::XED_REG_DIL | xed_sys::XED_REG_R8B | xed_sys::XED_REG_R9B | xed_sys::XED_REG_R10B | xed_sys::XED_REG_R11B | xed_sys::XED_REG_R12B | xed_sys::XED_REG_R13B | xed_sys::XED_REG_R14B | xed_sys::XED_REG_R15B | xed_sys::XED_REG_AH | xed_sys::XED_REG_CH | xed_sys::XED_REG_DH | xed_sys::XED_REG_BH | xed_sys::XED_REG_STACKPUSH | xed_sys::XED_REG_STACKPOP  => {
                                            // These are all general-purpose registers
                                        }
                                        reg => panic!("Unknown register ID {:?}", reg),
                                    }
                                }
                            }

                            let is_ring0 = xed_sys::xed_decoded_inst_get_attribute(xedd.as_mut_ptr(), xed_sys::XED_ATTRIBUTE_RING0) == 1;
                            (is_ring0, out_of_scope)
                        } else {
                            println!("error={} for {:02X?}", desc, instr.bytes());
                            (false, false)
                        }
                    };


                    let worker = enumeration_workers.iter()
                        .position(|w| &instr >= w.from() && w.to().as_ref().map(|to| &instr <= to).unwrap_or(true))
                        .unwrap();
                    let seen = enumeration_workers[worker].inner().counter.current() > instr.as_instr();
                    let found = filters.filters(instr.as_instr()).is_some();
                    let correct = correctness_map.filters(instr.as_instr()).map(|c| c.correct);

                    if seen {
                        stats.seen += 1;
                        if found {
                            stats.found += 1;
                        } else {
                            stats.missed += 1;
                        }

                        if is_ring0 {
                            stats.seen_ring0 += 1;
                        } else if out_of_scope_reg {
                            stats.seen_out_of_scope += 1;
                        } else {
                            match correct {
                                Some(true) => stats.seen_correct += 1,
                                Some(false) => stats.seen_incorrect += 1,
                                None => stats.seen_not_synthesized += 1,
                            }
                        }
                    } else {
                        if found {
                            stats.unseen_found += 1;
                        }
                    }

                    if found {
                        stats.enum_covered += 1;
                    }

                    if is_ring0 {
                        stats.ring0 += 1;
                    } else if out_of_scope_reg {
                        stats.out_of_scope += 1;
                    } else {
                        stats.total_in_scope += 1;
                        match correct {
                            Some(true) => stats.correct += 1,
                            Some(false) => stats.incorrect += 1,
                            None => stats.not_synthesized += 1,
                        }
                    }
                    
                    stats.total += 1;
                }
            }

            println!();

            stats
        };

        all_stats.push((instrs_file.file_stem().unwrap().to_string_lossy().to_string(), stats));

        println!("done.");

        println!("Completeness: {:3.2}%; Correctness: {:3.2}%; Coverage (abs.): {:3.2}%; Coverage (rel.): {:3.2}%; {:?}", stats.completeness(), stats.correctness(), stats.absolute_coverage(), stats.relative_coverage(), stats);

        // Source & Seen & Out of scope & Correct & Not synthesized & Incorrect & Missing & Correctness & Coverage
        // writeln!(correctness_out, "    {} & {} & {} & {} & {} & {} & {} & {:3.2}\\% & {:3.2}\\%\\\\", instrs_file.file_stem().unwrap().to_string_lossy(), stats.seen, stats.ring0 + stats.out_of_scope, correct, not_synthesized, incorrect, stats.missed, correctness, coverage)?;
    }

    {
        let mut f = File::create(args.completeness_out)?;
        writeln!(f, "\\begin{{tabular}}{{|c|c c c c|c|}}")?;
        writeln!(f, "\\hline")?;
        writeln!(f, "Source & Total & Seen & Found & Missed & Completeness \\\\ [0.5ex] ")?;
        writeln!(f, "\\hline\\hline")?;

        for (name, stats) in all_stats.iter() {
            writeln!(f, 
                "    {} & {} & {} & {} & {} & {:3.2}\\%\\\\", 
                name,
                stats.total, 
                stats.seen, 
                stats.found, 
                stats.missed,
                stats.completeness(),
            )?;
        }

        writeln!(f, "\\hline")?;
        writeln!(f, "\\end{{tabular}}")?;
    }

    {
        let mut f = File::create(args.correctness_out)?;
        writeln!(f, "\\begin{{tabular}}{{|c|c c c c|c|}}")?;
        writeln!(f, "\\hline")?;
        writeln!(f, "Source & Correct & Incorrect & Not synthesized & Out of scope & Correctness \\\\ [0.5ex] ")?;
        writeln!(f, "\\hline\\hline")?;

        for (name, stats) in all_stats.iter() {
            writeln!(f, 
                "    {} & {} & {} & {} & {} & {:3.2}\\%\\\\", 
                name,
                stats.seen_correct, 
                stats.seen_incorrect, 
                stats.seen_not_synthesized, 
                stats.seen_out_of_scope + stats.seen_ring0, 
                stats.correctness(),
            )?;
        }

        writeln!(f, "\\hline")?;
        writeln!(f, "\\end{{tabular}}")?;
    }

    {
        let mut f = File::create(args.coverage_out)?;
        writeln!(f, "\\begin{{tabular}}{{|c|c c c|c c|}}")?;
        writeln!(f, "\\hline")?;
        writeln!(f, "Source & Correct & Total & Coverage \\\\ [0.5ex] ")?;
        writeln!(f, "\\hline\\hline")?;

        for (name, stats) in all_stats.iter() {
            writeln!(f, 
                "    {} & {} & {} & {:3.2}\\%\\\\", 
                name,
                stats.correct,
                stats.total,
                stats.absolute_coverage(),
            )?;
        }

        writeln!(f, "\\hline")?;
        writeln!(f, "\\end{{tabular}}")?;
    }

    {
        let mut f = File::create(args.stats_out)?;
        writeln!(f, "\\newcommand\\sEnumerationRuntime{{{}}}", enumeration_runner.seconds_running() / 3600)?;
        writeln!(f, "\\newcommand\\sNumEncodings{{{}}}", enumerated_encodings.len())?;
        writeln!(f, "\\newcommand\\sSynthesisRuntime{{{}}}", (addr_synthesis_runner.seconds_running() + dataflow_synthesis_runner.seconds_running()) / 3600)?;

        let num_computations: usize = addr_synthesis_workers.iter()
            .map(|w| w.inner().computation_groups.iter().map(|g| g.len()).sum::<usize>())
            .sum::<usize>() + dataflow_synthesis_workers.iter()
            .map(|w| w.inner().computation_groups.iter().map(|g| g.len()).sum::<usize>())
            .sum::<usize>();
        writeln!(f, "\\newcommand\\sNumComputations{{{}}}", num_computations)?;


        let num_computations_learned: usize = addr_synthesis_workers.iter()
            .map(|w| w.inner().computation_groups.iter().filter(|g| g.table.has_good_tree()).map(|g| g.len()).sum::<usize>())
            .sum::<usize>() + dataflow_synthesis_workers.iter()
            .map(|w| w.inner().computation_groups.iter().filter(|g| g.table.has_good_tree()).map(|g| g.len()).sum::<usize>())
            .sum::<usize>();
        writeln!(f, "\\newcommand\\sNumComputationsLearned{{{}}}", num_computations_learned)?;

        let num_correct_encodings: usize = correctness_workers.iter()
            .map(|w| w.inner().encodings.iter().filter(|e| e.correct).count())
            .sum();
        writeln!(f, "\\newcommand\\sEncodingsCorrect{{{}}}", num_correct_encodings)?;

        let num_full_semantics: usize = correctness_workers.iter()
            .map(|w| w.inner().encodings.len())
            .sum();
        writeln!(f, "\\newcommand\\sNumFullSemanticsForEncodings{{{}}}", num_full_semantics)?;

        let (_, stats) = all_stats.iter().filter(|(name, _)| name == "scan").next().unwrap();
        writeln!(f, "\\newcommand\\sEnumerationCovered{{{:3.2}\\%}}", (stats.found + stats.missed + stats.unseen_found) as f64 * 100. / stats.total as f64)?;
        writeln!(f, "\\newcommand\\sCompleteness{{{:3.2}\\%}}", stats.completeness())?;
        writeln!(f, "\\newcommand\\sUnseenFound{{{}}}", stats.unseen_found)?;
        writeln!(f, "\\newcommand\\sScanInstructions{{{} million}}", stats.total / 1_000_000)?;
        writeln!(f, "\\newcommand\\sAbsoluteCoverage{{{:3.2}\\%}}", stats.absolute_coverage())?;
        writeln!(f, "\\newcommand\\sRelativeCoverage{{{:3.2}\\%}}", stats.relative_coverage())?;
        writeln!(f, "\\newcommand\\sCorrectness{{{:3.2}\\%}}", stats.correctness())?;
        writeln!(f, "\\newcommand\\sMaxAchievableAbsoluteCoverage{{{:3.2}\\%}}", (stats.correct + stats.incorrect + stats.not_synthesized) as f64 * 100. / stats.total as f64)?;
    }

    Ok(())
}

fn main () { 
    env_logger::init();
    run().unwrap() 
}