use std::{error::Error, ops::Range, path::{Path, PathBuf}, sync::Arc};
use liblisa_x64_kmod::{ObservationBuilder, ObservationProcess, ObservationResult, ObservationError, StageMap, StageUnmap};
use log::error;
use nix::{libc::{PROT_EXEC, user_regs_struct}};
use liblisa_core::arch::{Permissions, State, Register};
use crate::arch::X64State;
use crate::memory::SharedMemory;
use liblisa_core::oracle::OracleError;
use thiserror::Error;

use super::{Mapper, Unmapper, X64OracleBackend};

#[allow(unused, non_snake_case, non_camel_case_types, non_upper_case_globals)]
mod sys {
    include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
}

pub struct KmodPtraceBackend {
    process: ObservationProcess,
    current_code_page: Option<Range<u64>>,
    binary_path: PathBuf,

    /// Lowest mappable page address up to the (exclusive) end of the mapping range. I.e. if valid addresses are 0x0000 - 0x7fff, this would be 0x0000..0x8000.
    code_pages: Range<u64>,
    page_size: u64,
}

#[derive(Clone, Debug, Error)]
pub enum PtraceError {
    #[error("Mapping syscalls failed with {}", .0)]
    MappingSyscallsFailed(nix::Error),

    #[error("Unable to unmap {:X?}: {}", .0, .1)]
    UnableToUnmap(Range<u64>, nix::Error),

    #[error("Unable to write to {:X}: {} (data = {:X?})", .0, .2, .1)]
    UnableToWrite(u64, Vec<(u64, Permissions, Vec<u8>)>, nix::Error),

    #[error("Unable to read from {:X}: {}", .0, .1)]
    UnableToRead(u64, nix::Error),
}

impl From<PtraceError> for OracleError {
    fn from(e: PtraceError) -> Self {
        OracleError::ApiError(Arc::new(Box::new(e)))
    }
}

impl Unmapper for ObservationBuilder<StageUnmap> {
    fn unmap(&mut self, addr: u64) {
        ObservationBuilder::unmap(self, addr);
    }
}

impl Mapper for ObservationBuilder<StageMap> {
    fn map(&mut self, addr: u64, fd: i32, prot: u8) {
        ObservationBuilder::map(self, addr, fd, prot);
    }
}

impl X64OracleBackend for KmodPtraceBackend {
    type U = ObservationBuilder<StageUnmap>;
    type M = ObservationBuilder<StageMap>;
    type E = ObservationError;

    fn new<P: AsRef<Path>>(binary_path: P, _: &mut SharedMemory) -> Result<KmodPtraceBackend, Box<dyn Error>> {
        // Need to create the pool before starting the process, so that the file descriptors of the shared memory are equal.
        // Alternative is to send them via domain socket and have the kernel translate them, but that is more complex.
        let process = ObservationProcess::new(binary_path.as_ref().into())?;
        let oracle = KmodPtraceBackend {
            process,
            binary_path: binary_path.as_ref().into(),
            current_code_page: None,
            code_pages: 0..0x7fff_0000_0000,
            page_size: page_size::get() as u64,
        };

        Ok(oracle)
    }

    fn valid_addresses(&self) -> Range<u64> {
        self.code_pages.clone()
    }

    fn page_size(&self) -> u64 {
        self.page_size
    }

    fn get_basic_regs(&mut self) -> Result<user_regs_struct, nix::Error> {
        self.process.get_basic_regs()
    }

    fn clear_fp_exception(&mut self, executable_shm: &mut SharedMemory) {
        let mut regcopy: user_regs_struct = (&X64State::create(|reg| if reg.is_pc() {
            self.current_code_page.as_ref().unwrap().start
        } else {
            0
        }, |_| false)).into();
        executable_shm.write(0, &[ 0xDB, 0xE2 ]);
        let b = self.process.start_observe()
            .start_mapping();
        let result = self.process.observe(&mut regcopy, b)
            .expect("Unable to clear FP exception");

        assert!(matches!(result, ObservationResult::Executed));
        assert_eq!(regcopy.rip, self.current_code_page.as_ref().unwrap().start + 2);
    }

    fn user_write(&mut self, addr: u64, word: u64) -> Result<(), nix::Error> {
        self.process.user_write(addr, word)
    }

    fn user_read(&mut self, addr: u64) -> Result<u64, nix::Error> {
        self.process.user_read(addr)
    }

    fn observe<D>(&mut self, mut data: D, mut f_unmap: impl FnMut(&mut D, &mut Self::U), executable_addr: u64, executable_shm: &mut SharedMemory, mut f_map: impl FnMut(&mut D, &mut Self::M), mut f_prepare: impl FnMut(&mut D), mut f_prepare_exec: impl FnMut(&mut D, &mut SharedMemory), regs: &mut user_regs_struct) -> Result<ObservationResult, Self::E> {
        let mut builder = self.process.start_observe();
        f_unmap(&mut data, &mut builder);

        let executable_fd = executable_shm.fd();
        let page_addr = (executable_addr / self.page_size()) * self.page_size();
        let mut builder = if Some(page_addr) != self.current_code_page.as_ref().map(|x| x.start) {
            if let Some(current) = &self.current_code_page {
                builder.unmap(current.start);
            }

            let mut builder = builder.start_mapping();
            builder.map(page_addr, executable_fd, PROT_EXEC as u8);
            self.current_code_page = Some(page_addr..page_addr + self.page_size());

            builder
        } else {
            builder.start_mapping()
        };

        f_map(&mut data, &mut builder);

        f_prepare(&mut data);
        f_prepare_exec(&mut data, executable_shm);
        self.process.observe(regs, builder)
    }

    fn debug_dump(&mut self) {
        println!("Current code page: {:X?}", self.current_code_page);
        println!("Real mappings: \n{}\n", std::fs::read_to_string(format!("/proc/{}/maps", self.process.raw_pid())).unwrap());
    }

    fn pid(&self) -> Option<i32> {
        Some(self.process.raw_pid())
    }

    fn restart(&mut self, _executable_shm: &mut SharedMemory) -> Result<(), Box<dyn Error>> {
        let mut new = ObservationProcess::new(self.binary_path.clone())?;
        std::mem::swap(&mut self.process, &mut new);
        new.kill();

        self.current_code_page = None;

        Ok(())
    }

    fn kill(self) {
        self.process.kill();
    }
}

#[allow(unused)]
mod tests {
    use liblisa_core::arch::{Instr, InstructionInfo, MemoryState, Permissions, SystemState, Register, State};
    use liblisa_core::oracle::{Oracle, OracleError};
    use crate::{arch::X64State, X64Reg};

    #[test]
    pub fn map_executable_area() {
        let mut o = crate::x64_kmod_ptrace_oracle();
        let instr = Instr::new(&[ 0x48, 0x31, 0xD0 ]); // XOR rax, rdx

        let pc = o.valid_executable_addresses().start;
        let state = SystemState::new(X64State::create(|reg| if reg.is_pc() {
            pc
        } else {
            0
        }, |_| false), MemoryState::new(vec![
            (pc, Permissions::Execute, instr.bytes().to_owned())
        ].into_iter()));
        o.observe(&state).unwrap();

        // Change pc
        let pc = o.valid_executable_addresses().start + o.page_size();
        let state = SystemState::new(X64State::create(|reg| if reg.is_pc() {
            pc
        } else {
            0
        }, |_| false), MemoryState::new(vec![
            (pc, Permissions::Execute, instr.bytes().to_owned())
        ].into_iter()));
        o.observe(&state).unwrap();
    }

    #[test]
    pub fn move_memory() {
        let mut o = crate::x64_kmod_ptrace_oracle();
        let instr = Instr::new(&[ 0x48, 0x8B, 0x04, 0x25, 0x44, 0x33, 0x22, 0x11 ]); // mov rax,QWORD PTR ds:0x11223344
        let instr2 = Instr::new(&[ 0x48, 0x8B, 0x04, 0x25, 0x44, 0x33, 0x22, 0x22 ]); // mov rax,QWORD PTR ds:0x22223344

        let pc = o.valid_executable_addresses().start;
        let state = SystemState::new(X64State::create(|reg| if reg.is_pc() {
            pc
        } else {
            0
        }, |_| false), MemoryState::new(vec![
            (pc, Permissions::Execute, instr.bytes().to_owned()),
            (0x11223344, Permissions::Read, vec![ 1, 1, 1, 1, 1, 1, 1, 1 ]),
        ].into_iter()));
        let result = o.observe(&state).unwrap();
        assert_eq!(result.cpu.reg(&X64Reg::Rax), 0x01010101_01010101, "State: {:X?}", result);

        // Move memory, this should give an error
        let state = SystemState::new(state.cpu, MemoryState::new(vec![
            (pc, Permissions::Execute, instr.bytes().to_owned()),
            (0x22223344, Permissions::Read, vec![ 0, 0, 0, 0, 0, 0, 0, 0 ]),
        ].into_iter()));
        match o.observe(&state) {
            Err(OracleError::MemoryAccess(0x11223344)) => {},
            other => panic!("Memory access should fail: {:X?}", other),
        }

        // Change instruction, this should no longer give an error
        let state = SystemState::new(state.cpu, MemoryState::new(vec![
            (pc, Permissions::Execute, instr2.bytes().to_owned()),
            (0x22223344, Permissions::Read, vec![ 2, 2, 2, 2, 2, 2, 2, 2 ]),
        ].into_iter()));
        assert_eq!(o.observe(&state).unwrap().cpu.reg(&X64Reg::Rax), 0x02020202_02020202);
    }

    #[test]
    pub fn remap_after_restart() {
        let mut o = crate::x64_kmod_ptrace_oracle();
        let instr = Instr::new(&[ 0x48, 0x8B, 0x04, 0x25, 0x44, 0x33, 0x22, 0x11 ]); // mov rax,QWORD PTR ds:0x11223344
        let instr2 = Instr::new(&[ 0x48, 0x8B, 0x04, 0x25, 0x44, 0x33, 0x22, 0x22 ]); // mov rax,QWORD PTR ds:0x22223344

        let pc = o.valid_executable_addresses().start;
        let state = SystemState::new(X64State::create(|reg| if reg.is_pc() {
            pc
        } else {
            0
        }, |_| false), MemoryState::new(vec![
            (pc, Permissions::Execute, instr.bytes().to_owned()),
            (0x11223344, Permissions::Read, vec![ 1, 1, 1, 1, 1, 1, 1, 1 ]),
        ].into_iter()));
        let result = o.observe(&state).unwrap();
        assert_eq!(result.cpu.reg(&X64Reg::Rax), 0x01010101_01010101, "State: {:X?}", result);

        o.restart();

        let result = o.observe(&state).unwrap();
        assert_eq!(result.cpu.reg(&X64Reg::Rax), 0x01010101_01010101, "State: {:X?}", result);
    }


    #[test]
    pub fn write_memory() {
        let mut o = crate::x64_kmod_ptrace_oracle();
        let instr = Instr::new(&[ 0x48, 0x89, 0x04, 0x25, 0x44, 0x33, 0x22, 0x11 ]); // mov QWORD PTR ds:0x11223344,rax
        let instr2 = Instr::new(&[ 0x48, 0x89, 0x04, 0x25, 0x44, 0x33, 0x22, 0x22 ]); // mov QWORD PTR ds:0x22223344,rax

        let pc = o.valid_executable_addresses().start;
        let state = SystemState::new(X64State::create(|reg| if reg.is_pc() {
            pc
        } else if reg == &X64Reg::Rax {
            0x1122334444332211
        } else {
            0
        }, |_| false), MemoryState::new(vec![
            (pc, Permissions::Execute, instr.bytes().to_owned()),
            (0x11223344, Permissions::ReadWrite, vec![ 1, 1, 1, 1, 1, 1, 1, 1 ]),
        ].into_iter()));
        assert_eq!(o.observe(&state).unwrap().memory.data[1], (0x11223344, Permissions::ReadWrite, vec![ 0x11, 0x22, 0x33, 0x44, 0x44, 0x33, 0x22, 0x11 ]));

        // Move memory, this should give an error
        let state = SystemState::new(state.cpu, MemoryState::new(vec![
            (pc, Permissions::Execute, instr.bytes().to_owned()),
            (0x22223344, Permissions::ReadWrite, vec![ 0, 0, 0, 0, 0, 0, 0, 0 ]),
        ].into_iter()));
        match o.observe(&state) {
            Err(OracleError::MemoryAccess(0x11223344)) => {},
            other => panic!("Memory access should fail: {:X?}", other),
        }

        // Make memory unwritable, this should give an error
        let state = SystemState::new(state.cpu, MemoryState::new(vec![
            (pc, Permissions::Execute, instr.bytes().to_owned()),
            (0x11223344, Permissions::Read, vec![ 0, 0, 0, 0, 0, 0, 0, 0 ]),
        ].into_iter()));
        match o.observe(&state) {
            Err(OracleError::MemoryAccess(0x11223344)) => {},
            other => panic!("Memory access should fail: {:X?}", other),
        }

        // Change instruction, this should no longer give an error
        let state = SystemState::new(state.cpu, MemoryState::new(vec![
            (pc, Permissions::Execute, instr2.bytes().to_owned()),
            (0x22223344, Permissions::ReadWrite, vec![ 2, 2, 2, 2, 2, 2, 2, 2 ]),
        ].into_iter()));
        assert_eq!(o.observe(&state).unwrap().memory.data[1], (0x22223344, Permissions::ReadWrite, vec![ 0x11, 0x22, 0x33, 0x44, 0x44, 0x33, 0x22, 0x11 ]));
    }

    #[test]
    pub fn execute_many() {
        let mut o = crate::x64_kmod_ptrace_oracle();
        let pc = o.valid_executable_addresses().start;
        let instr = Instr::new(&[ 0x48, 0x31, 0xD0 ]); // XOR rax, rdx
        let state = SystemState::new(X64State::create(|reg| if reg.is_pc() {
            pc
        } else {
            0
        }, |_| false), MemoryState::new(vec![
            (pc, Permissions::Execute, instr.bytes().to_owned())
        ].into_iter()));

        for _ in 0..5_000 {
            o.observe(&state).unwrap();
        }
    }

    #[test]
    pub fn thorough_scan() {
        let mut o = crate::x64_kmod_ptrace_oracle();
        let pc = o.valid_executable_addresses().start + 500;
        let instr = Instr::new(&[ 0x02, 0x05, 0x00, 0x00, 0x00, 0x00 ]); // add    al,BYTE PTR [rip+0x0]
        let state = SystemState::new(X64State::create(|reg| if reg.is_pc() {
            pc
        } else {
            0
        }, |_| false), MemoryState::new(vec![
            (pc, Permissions::Execute, instr.bytes().to_owned())
        ].into_iter()));

        let result = o.observe_carefully(&state);
        if let Err(OracleError::MemoryAccess(addr)) = result {
            assert_eq!(addr, pc + 6);
        } else {
            panic!("Observe returned: {:?}", result);
        }

        let instr = Instr::new(&[ 0x02, 0x05, 0x01, 0x00, 0x00, 0x00 ]); // add    al,BYTE PTR [rip+0x1]
        let state = SystemState::new(X64State::create(|reg| if reg.is_pc() {
            pc
        } else {
            0
        }, |_| false), MemoryState::new(vec![
            (pc, Permissions::Execute, instr.bytes().to_owned())
        ].into_iter()));

        let result = o.observe_carefully(&state);
        if let Err(OracleError::MemoryAccess(addr)) = result {
            assert_eq!(addr, pc + 7);
        } else {
            panic!("Observe returned: {:?}", result);
        }

        let instr = Instr::new(&[ 0x48, 0x03, 0x05, 0x00, 0x00, 0x00, 0x00 ]); // add    rax,QWORD PTR [rip+0x0]
        let state = SystemState::new(X64State::create(|reg| if reg.is_pc() {
            pc
        } else {
            0
        }, |_| false), MemoryState::new(vec![
            (pc, Permissions::Execute, instr.bytes().to_owned())
        ].into_iter()));

        let result = o.observe_carefully(&state);
        if let Err(OracleError::MemoryAccess(addr)) = result {
            assert_eq!(addr, pc + 7);
        } else {
            panic!("Observe returned: {:?}", result);
        }
    }
}