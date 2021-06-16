use std::fmt::Display;
use log::trace;
use rand::Rng;
use liblisa_core::{arch::{Arch, Instr, InstructionInfo, Register, State, MemoryState, Permissions, SystemState}, oracle::{Oracle, OracleError}};
use liblisa_core::random_state;

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum Validity {
    TooShort,
    TooLong,
    InvalidInstruction,
    Excluded,
    Ok,
}

impl Validity {
    pub fn infer<A: Arch, O: Oracle<A>>(o: &mut O, instr: Instr<'_>) -> Validity {
        if !A::is_instruction_included(instr.bytes()) {
            return Validity::Excluded;
        }

        let mut rng = rand::thread_rng();
        let pages = o.valid_executable_addresses();
        let page_size = o.page_size();

        if instr.byte_len() > 1 {
            let len = instr.byte_len() - 1;
            let page = rng.gen_range(0, (pages.end - pages.start) / page_size) * page_size + pages.start;
            let page = page..page + page_size;
            let pc = page.end - len as u64;
            let cpu_state = random_state::<A>(pc).cpu;
            let memory = vec! [ 
                (pc, Permissions::Execute, instr.bytes()[0..len].to_owned() ),
            ];
            let state = SystemState::new(cpu_state, MemoryState::new(memory.into_iter()));
            trace!("Observing to determine if the instruction is too long: {:X?}", state);
            match o.observe(&state) {
                // We expect this error; The instruction is too short, so we get a segfault at the memory address
                Err(OracleError::MemoryAccess(addr)) if addr == page.end => {
                    for _ in 0..100 {
                        let page = rng.gen_range(0, (pages.end - pages.start) / page_size) * page_size + pages.start;
                        let page = page..page + page_size;
                        let pc = page.end - len as u64;
                        let cpu_state = state.cpu.with_reg(&A::Reg::pc(), pc);
                        let memory = vec! [ 
                            (pc, Permissions::Execute, instr.bytes()[0..len].to_owned() ),
    
                            // Map the next page as non-executable read-write to catch cases where we're trying to access memory right after the instruction
                            (page.end, Permissions::ReadWrite, vec![ 0 ] ),
                        ];
                        let state = SystemState::new(cpu_state, MemoryState::new(memory.into_iter()));
                        match o.observe(&state) {
                            Err(OracleError::MemoryAccess(second_addr)) if second_addr != page.end && second_addr != addr => return Validity::TooLong,
                            Ok(_) => return Validity::TooLong,

                            Err(OracleError::ApiError(e)) => panic!("Unable to verify instruction: {:?}", e),
                            _ => {},
                        }
                    }
                },

                // If we see any other error, or see no error at all, this means the instruction was fully interpreted (which shouldn't be possible because we sliced it down to len bytes)
                Err(OracleError::ApiError(e)) => {
                    o.debug_dump();
                    panic!("Unable to verify instruction: {:?}", e)
                },
                Ok(_)
                    | Err(OracleError::GeneralFault) | Err(OracleError::InvalidInstruction) 
                    | Err(OracleError::MemoryAccess(_)) | Err(OracleError::ComputationError) => {
                    // Not a minimal instruction because instruction size changed
                    return Validity::TooLong;
                },
            }
        }

        let page = pages.start..pages.start + page_size;
        let pc = page.end - instr.byte_len() as u64;
        let cpu_state = random_state::<A>(pc).cpu;
        let memory = vec! [ (pc, Permissions::Execute, instr.bytes().to_owned() )];
        let state = SystemState::new(cpu_state, MemoryState::new(memory.into_iter()));
        trace!("Observing to determine if the instruction is too short: {:X?}", state);
        let result = o.observe(&state);
        trace!("Result = {:X?}", result);
        match result {
            Err(OracleError::MemoryAccess(addr)) if addr == page.end => {
                for _ in 0..10 {
                    let page = rng.gen_range(0, (pages.end - pages.start) / page_size) * page_size + pages.start;
                    let page = page..page + page_size;
                    let pc = page.end - instr.byte_len() as u64;
                    let cpu_state = state.cpu.with_reg(&A::Reg::pc(), pc);
                    let memory = vec! [ 
                        (pc, Permissions::Execute, instr.bytes().to_owned() ),

                        // Map the next page as non-executable read-write to catch cases where we're trying to access memory right after the instruction
                        (page.end, Permissions::ReadWrite, vec![ 0 ] ),
                    ];
                    let state = SystemState::new(cpu_state, MemoryState::new(memory.into_iter()));
                    trace!("Observing to make sure we found an instruction access and not another memory access: {:X?}", state);
                    match o.observe(&state) {
                        Err(OracleError::MemoryAccess(second_addr)) if second_addr != page.end /* TODO: This bit doesn't seem relevant: && second_addr != addr */ => return Validity::Ok,
                        Ok(_) => return Validity::Ok,

                        Err(OracleError::ApiError(e)) => panic!("Unable to verify instruction: {:?}", e),
                        _ => {},
                    }
                }

                Validity::TooShort
            },
            Err(OracleError::ApiError(e)) => panic!("Unable to verify instruction: {:?}", e),
            Err(OracleError::InvalidInstruction) => Validity::InvalidInstruction,

            // Anything other than these errors means the instruction was decoded succesfully!
            _ => Validity::Ok,
        }
    }
}

impl Display for Validity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Validity::TooShort => f.write_str("TooShort"),
            Validity::TooLong => f.write_str("TooLong"),
            Validity::InvalidInstruction => f.write_str("InvalidInstruction"),
            Validity::Excluded => f.write_str("Excluded"),
            Validity::Ok => f.write_str("Ok"),
        }
    }
}