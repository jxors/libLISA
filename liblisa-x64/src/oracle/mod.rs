use std::{error::Error, ops::Range, path::Path};

use liblisa_x64_kmod::ObservationResult;
use log::trace;
use nix::{libc::{self, PROT_READ, PROT_WRITE, user_regs_struct}, sys::signal::Signal};
use liblisa_core::{arch::{MemoryState, Permissions, State, SystemState}, oracle::Oracle};
use liblisa_core::oracle::OracleError;
use crate::{X64Arch, arch::{X64Flag, X64Reg, X64State}, memory::{MemoryPool, SharedMemory}};

pub mod kmod_ptrace;
pub mod simple_ptrace;

impl From<&X64State> for user_regs_struct {
    fn from(state: &X64State) -> Self {
        let b = |v| if v { 1 } else { 0 };
        user_regs_struct {
            r15: state.reg(&X64Reg::R15),
            r14: state.reg(&X64Reg::R14),
            r13: state.reg(&X64Reg::R13),
            r12: state.reg(&X64Reg::R12),
            rbp: state.reg(&X64Reg::Rbp),
            rbx: state.reg(&X64Reg::Rbx),
            r11: state.reg(&X64Reg::R11),
            r10: state.reg(&X64Reg::R10),
            r9: state.reg(&X64Reg::R9),
            r8: state.reg(&X64Reg::R8),
            rax: state.reg(&X64Reg::Rax),
            rcx: state.reg(&X64Reg::Rcx),
            rdx: state.reg(&X64Reg::Rdx),
            rsi: state.reg(&X64Reg::Rsi),
            rdi: state.reg(&X64Reg::Rdi),
            orig_rax: state.reg(&X64Reg::Rax),
            rip: state.reg(&X64Reg::Rip),
            eflags: (
                (b(state.flag(&X64Flag::Cf)) << 0)
                | (b(state.flag(&X64Flag::Pf)) << 2)
                | (b(state.flag(&X64Flag::Af)) << 4)
                | (b(state.flag(&X64Flag::Zf)) << 6)
                | (b(state.flag(&X64Flag::Sf)) << 7)
                | (b(state.flag(&X64Flag::Of)) << 11)
            ),
            rsp: state.reg(&X64Reg::Rsp),
            // We cannot modify these registers in x86-64
            cs: 0x33,
            ss: 0x2b,
            fs_base: 0,
            gs_base: 0,
            ds: 0,
            es: 0,
            fs: 0,
            gs: 0,
        }
    }
}

impl From<&mut X64State> for user_regs_struct {
    fn from(state: &mut X64State) -> Self {
        let b = |v| if v { 1 } else { 0 };
        user_regs_struct {
            r15: state.reg(&X64Reg::R15),
            r14: state.reg(&X64Reg::R14),
            r13: state.reg(&X64Reg::R13),
            r12: state.reg(&X64Reg::R12),
            rbp: state.reg(&X64Reg::Rbp),
            rbx: state.reg(&X64Reg::Rbx),
            r11: state.reg(&X64Reg::R11),
            r10: state.reg(&X64Reg::R10),
            r9: state.reg(&X64Reg::R9),
            r8: state.reg(&X64Reg::R8),
            rax: state.reg(&X64Reg::Rax),
            rcx: state.reg(&X64Reg::Rcx),
            rdx: state.reg(&X64Reg::Rdx),
            rsi: state.reg(&X64Reg::Rsi),
            rdi: state.reg(&X64Reg::Rdi),
            orig_rax: state.reg(&X64Reg::Rax),
            rip: state.reg(&X64Reg::Rip),
            eflags: (
                (b(state.flag(&X64Flag::Cf)) << 0)
                | (b(state.flag(&X64Flag::Pf)) << 2)
                | (b(state.flag(&X64Flag::Af)) << 4)
                | (b(state.flag(&X64Flag::Zf)) << 6)
                | (b(state.flag(&X64Flag::Sf)) << 7)
                // | (b(state.flag(&X64Flag::Df)) << 10)
                | (b(state.flag(&X64Flag::Of)) << 11)
            ),
            rsp: state.reg(&X64Reg::Rsp),
            // We cannot modify these registers in x86-64
            cs: 0x33,
            ss: 0x2b,
            fs_base: 0,
            gs_base: 0,
            ds: 0,
            es: 0,
            fs: 0,
            gs: 0,
        }
    }
}

impl From<&user_regs_struct> for X64State {
    fn from(state: &user_regs_struct) -> Self {
        let mut result = X64State::default();
        let b = &mut result.basic_regs;

        b[X64Reg::R15 as usize] = state.r15;
        b[X64Reg::R14 as usize] = state.r14;
        b[X64Reg::R13 as usize] = state.r13;
        b[X64Reg::R12 as usize] = state.r12;
        b[X64Reg::Rbp as usize] = state.rbp;
        b[X64Reg::Rbx as usize] = state.rbx;
        b[X64Reg::R11 as usize] = state.r11;
        b[X64Reg::R10 as usize] = state.r10;
        b[X64Reg::R9 as usize] = state.r9;
        b[X64Reg::R8 as usize] = state.r8;
        b[X64Reg::Rax as usize] = state.rax;
        b[X64Reg::Rcx as usize] = state.rcx;
        b[X64Reg::Rdx as usize] = state.rdx;
        b[X64Reg::Rsi as usize] = state.rsi;
        b[X64Reg::Rdi as usize] = state.rdi;
        b[X64Reg::Rip as usize] = state.rip;
        b[X64Reg::Rsp as usize] = state.rsp;

        result.set_flag(X64Flag::Cf, (state.eflags >> 0) & 1 == 1);
        result.set_flag(X64Flag::Pf, (state.eflags >> 2) & 1 == 1);
        result.set_flag(X64Flag::Af, (state.eflags >> 4) & 1 == 1);
        result.set_flag(X64Flag::Zf, (state.eflags >> 6) & 1 == 1);
        result.set_flag(X64Flag::Sf, (state.eflags >> 7) & 1 == 1);
        // result.set_flag(X64Flag::Df, (state.eflags >> 10) & 1 == 1);
        result.set_flag(X64Flag::Of, (state.eflags >> 11) & 1 == 1);

        result
    }
}

pub trait Unmapper {
    fn unmap(&mut self, addr: u64);
}

pub trait Mapper {
    fn map(&mut self, addr: u64, fd: i32, prot: u8);
}

pub trait X64OracleBackend: Sized {
    type U: Unmapper;
    type M: Mapper;
    type E: Error + Send + Sync + 'static;

    fn new<P: AsRef<Path>>(path: P, executable_shm: &mut SharedMemory) -> Result<Self, Box<dyn Error>>;

    fn pid(&self) -> Option<i32>;

    fn valid_addresses(&self) -> Range<u64>;
    fn page_size(&self) -> u64;
    fn get_basic_regs(&mut self) -> Result<user_regs_struct, nix::Error>;
    fn clear_fp_exception(&mut self, executable_shm: &mut SharedMemory);
    fn observe<D>(&mut self, data: D, f_unmap: impl FnMut(&mut D, &mut Self::U), executable_addr: u64, executable_shm: &mut SharedMemory, f_map: impl FnMut(&mut D, &mut Self::M), f_prepare: impl FnMut(&mut D), f_prepare_exec: impl FnMut(&mut D, &mut SharedMemory), regs: &mut user_regs_struct) -> Result<ObservationResult, Self::E>;

    fn user_write(&mut self, addr: u64, word: u64) -> Result<(), nix::Error>;
    fn user_read(&mut self, addr: u64) -> Result<u64, nix::Error>;
    fn restart(&mut self, executable_shm: &mut SharedMemory) -> Result<(), Box<dyn Error>>;
    fn kill(self);

    fn debug_dump(&mut self);
}

pub struct X64Oracle<B: X64OracleBackend> {
    inner: B,
    base_flags: u64,
    current_mapping: Vec<Mapping>,
    pool: MemoryPool,
    executable_shm: SharedMemory,
}

enum Mapping {
    Page {
        page_index: u64,
        perms: Permissions,
        shm: SharedMemory,
    },
    ReUse(usize),
}

impl std::fmt::Debug for Mapping {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Mapping::Page { page_index: addr, perms, shm } => write!(f, "0x{:X}[{:?}] = fd{}", addr, perms, shm.fd()),
            Mapping::ReUse(index) => write!(f, "*{{{}}}", index),
        }
    }
}

fn bit_replace(old_val: u64, lsb: u64, size: u64, new_val: u64) -> u64 {
    let mask = (u64::MAX << (size+lsb)) | ((1 << lsb) - 1);
    (old_val & mask) | (new_val << lsb)
}

impl<B: X64OracleBackend> X64Oracle<B> {
    const FLAG_MASK: u64 = 0b1111_1111__1111_1111__1111_011100101010;

    pub fn new<P: AsRef<Path>>(path: P) -> Result<X64Oracle<B>, Box<dyn Error>> {
        let mut pool = MemoryPool::new(page_size::get())?;
        let mut shm = pool.get();
        let mut inner = B::new(path, &mut shm)?;
        let regs = inner.get_basic_regs()?;
        Ok(X64Oracle {
            inner,
            base_flags: regs.eflags & Self::FLAG_MASK,
            pool,
            executable_shm: shm,
            current_mapping: Vec::new(),
        })
    }

    fn execute_and_interpret<T>(&mut self, memory: &MemoryState, regs: &mut user_regs_struct, result: impl FnOnce(&mut Self, &user_regs_struct) -> Result<T, OracleError>) -> Result<T, OracleError> {
        regs.eflags = regs.eflags | self.base_flags;
        let page_size = self.page_size();

        // First memory access must always be executable, and must be the only executable page
        debug_assert_eq!(memory.get(0).unwrap().1, Permissions::Execute);
        debug_assert_eq!(memory.data.iter().filter(|(_, perms, _)| perms == &Permissions::Execute).count(), 1, "Cannot map more than one executable range: {:X?}", memory);

        // Permissions for memory mappings on the same page must be the same
        debug_assert!(memory.data.iter().all(|(addr1, perms1, _)| memory.data.iter().all(|(addr2, perms2, _)| if addr1 / page_size == addr2 / page_size {
            perms1 == perms2
        } else {
            true
        })), "Memory mappings on the same page must have the same permissions: {:#X?}", memory);

        // Memory mappings may not overlap
        debug_assert!(memory.data.iter().enumerate().all(|(i1, (addr1, _, d1))| memory.data.iter().enumerate().all(|(i2, (addr2, _, d2))| if addr1 / page_size == addr2 / page_size && i1 != i2 {
            addr1 + d1.len() as u64 <= *addr2 || *addr1 >= addr2 + d2.len() as u64
        } else {
            true
        })), "Memory mappings on the same page must not overlap: {:X?}", memory.data);

        let (current_mapping, pool, executable_shm, inner) = (&mut self.current_mapping, &mut self.pool, &mut self.executable_shm, &mut self.inner);
        let observation_result = inner.observe(
            (current_mapping, pool),
            |(current_mapping, pool), s| {
                for (mapping_index, mapping) in current_mapping.iter_mut().enumerate() {
                    let memory_index = mapping_index + 1;
                    match mapping {
                        Mapping::Page { page_index, .. } => {
                            match memory.get(memory_index) {
                                Some((addr, _, _)) => {
                                    if addr / page_size != *page_index {
                                        s.unmap(*page_index * page_size);
                                    }
                                },
                                None => {
                                    s.unmap(*page_index * page_size);
                                }
                            }
                        },
                        Mapping::ReUse(_) => {},
                    }
                }
               
                // Remove all excess mappings
                for mapping_index in (memory.data.len() - 1..current_mapping.len()).rev() {
                    match current_mapping.remove(mapping_index) {
                        Mapping::Page { shm, .. } => pool.release(shm),
                        _ => {},
                    }
                }

                debug_assert!(current_mapping.len() <= memory.data.len() - 1);
            },
            memory.data[0].0, executable_shm,
            |(current_mapping, pool), s| {
                debug_assert!(current_mapping.len() <= memory.data.len() - 1);

                for (memory_index, (addr, new_perms, _)) in memory.iter().enumerate().skip(1) {
                    let mapping_index = memory_index - 1;
                    let new_page_index = addr / page_size;
                    if let Some(index) = current_mapping.iter().take(mapping_index).position(|p| match p {
                        Mapping::Page { page_index, .. } => *page_index == new_page_index,
                        _ => false,
                    }) {
                        match current_mapping.get_mut(mapping_index) {
                            Some(mapping @ Mapping::Page { .. }) => {
                                let mut new = Mapping::ReUse(index);
                                std::mem::swap(&mut new, mapping);

                                if let Mapping::Page { shm, .. } = new {
                                    pool.release(shm);
                                } else {
                                    unreachable!()
                                }
                            }
                            Some(Mapping::ReUse(old_index)) => *old_index = index,
                            None => {
                                current_mapping.push(Mapping::ReUse(index));
                                debug_assert_eq!(current_mapping.len(), memory_index);
                            },
                        }
                    } else {
                        let prot = (match new_perms {
                            Permissions::ReadWrite => PROT_READ | PROT_WRITE,
                            Permissions::Read => PROT_READ,
                            Permissions::Execute => unreachable!("There is only one code page, which has already been mapped"),
                        }) as u8;
                        
                        match current_mapping.get_mut(mapping_index) {
                            Some(Mapping::Page { page_index, perms, shm }) => {
                                if *page_index != new_page_index || perms != new_perms {
                                    s.map(new_page_index * page_size, shm.fd(), prot);
                                    *page_index = new_page_index;
                                    *perms = new_perms.clone();
                                }
                            }
                            Some(Mapping::ReUse(_)) => {
                                let shm = pool.get();
                                s.map(new_page_index * page_size, shm.fd(), prot);
                                current_mapping[mapping_index] = Mapping::Page {
                                    page_index: new_page_index,
                                    perms: new_perms.clone(),
                                    shm,
                                };
                            }
                            None => {
                                let shm = pool.get();
                                s.map(new_page_index * page_size, shm.fd(), prot);
                                current_mapping.push(Mapping::Page {
                                    page_index: new_page_index,
                                    perms: new_perms.clone(),
                                    shm,
                                });

                                debug_assert_eq!(current_mapping.len(), memory_index);
                            }
                        }
                    }
                }
            },
            |(current_mapping, _)| {
                trace!("Chosen mapping = {:X?}", current_mapping);
                debug_assert_eq!(current_mapping.len(), memory.data.len() - 1);
                for (mapping_index, (addr, _, data)) in memory.iter().skip(1).enumerate() {
                    #[cfg(debug_assertions)]
                    {
                        let page_index = addr / page_size;
                        if (addr + data.len() as u64 - 1) / page_size != page_index {
                            panic!("Invalid memory specification: {:X?}; Memory at {:X} crosses page bounds", memory, addr);
                        }
                    }

                    let shm = match &mut current_mapping[mapping_index] {
                        Mapping::Page { shm, .. } => shm,
                        Mapping::ReUse(index) => {
                            let index = *index;
                            if let Mapping::Page { shm, .. } = &mut current_mapping[index] {
                                shm
                            } else {
                                unreachable!("Mapping::ReUse should never point to another Mapping::ReUse")
                            }
                        },
                    };
                    
                    shm.write(*addr, data);
                }
            },
            |(_, _), executable_shm| {
                let (addr, _, data) = memory.get(0).unwrap();
                #[cfg(debug_assertions)]
                if (addr + data.len() as u64 - 1) / page_size != addr / page_size {
                    panic!("Invalid memory specification: {:X?}; Memory at {:X} crosses page bounds", memory, addr);
                }

                executable_shm.write(*addr, data);
            },
            regs,
        ).map_err(OracleError::api)?;

        #[cfg(debug_assertions)]
        if let Some(pid) = self.inner.pid() {
            let mappings = std::io::BufRead::lines(
                std::io::BufReader::new(std::fs::File::open(format!("/proc/{}/maps", pid)).unwrap())
            ).map(|l| l.unwrap()).collect::<Vec<_>>();
            debug_assert_eq!(mappings.len(), self.current_mapping.iter().filter(|p| matches!(p, Mapping::Page { .. })).count() + 2, "Memory mappings are incorrect; Actual mappings: {:#?}; Expected: {:?}", mappings, self.current_mapping);
        }

        match observation_result {
            ObservationResult::Executed => {
                // Process is paused after executing an instruction
                // We cannot determine the instruction length from the IP, as a jump changes this.
                // Therefore, we just assume the length was correct here.
                result(self, regs as &_)
            },
            ObservationResult::Fault { signal, si_code, si_addr, si_errno, .. } => {
                // Fun fact: you might get either a SIGBUS or a SIGSEGV depending on whether you're using the RSP register or some other register, even if you are using the same opcode to access the same memory location.
                match signal {
                    Signal::SIGSEGV => {
                        const SI_KERNEL: i32 = 0x80;

                        match si_code {
                            // https://unix.stackexchange.com/questions/71240/sigaction7-semantics-of-siginfo-ts-si-code-member
                            SI_KERNEL if si_errno == 0 => return Err(OracleError::GeneralFault),
                            _ => {},
                        }

                        return Err(OracleError::MemoryAccess(si_addr));
                    },
                    Signal::SIGILL => {
                        return Err(OracleError::InvalidInstruction);
                    },
                    Signal::SIGBUS => {
                        return Err(OracleError::GeneralFault);
                    }
                    Signal::SIGFPE => {
                        // TODO: WORKAROUND: Floating point exceptions are sticky, so we need to clear them
                        self.inner.clear_fp_exception(&mut self.executable_shm);

                        return Err(OracleError::ComputationError);
                    }
                    
                    other => unimplemented!("Signal: {:?}", other),
                }
            },
            ObservationResult::Killed(sig) => {
                panic!("Process was killed by {}!", sig);
            },
            ObservationResult::ProcessExited(return_code) => {
                panic!("Process exited with return code {}", return_code);
            },
        }
    }


    fn check_memory_accesses_small(&mut self, addr: u64, perms: &Permissions, initial_state: &SystemState<X64Arch>, dr7: &mut u64, dr: u64, found: &mut Vec<u64>) -> Result<(), OracleError> {
        for check_addr in (addr..addr + 8).step_by(4) {
            for regnum in 0..4 {
                *dr7 = bit_replace(*dr7, 18 + 4 * regnum, 2, 0b00); // size, 00 = 1, 01 = 2, 10 = 8, 11 = 4
                *dr7 = bit_replace(*dr7, 16 + 4 * regnum, 2, 0b11); // when, 00 = execution, 01 = write, 11 = read/write
                *dr7 = *dr7 | (3 << (2*regnum));
            }

            // TODO: We should use the ptrace PT_GETDBREG calls for this
            self.inner.user_write(dr + 8 * 7, *dr7).map_err(OracleError::api)?;
            for regnum in 0..4 {
                self.inner.user_write(dr + 8 * regnum, check_addr + regnum).map_err(OracleError::api)?;
            }

            let before = &initial_state.cpu;
            let mut regs = before.into();
            let dr6 = self.execute_and_interpret(&initial_state.memory, &mut regs, |me, _regs| {
                Ok(me.inner.user_read(dr + 8 * 6).map_err(OracleError::api)?)
            });

            match dr6 {
                Ok(dr6) => {
                    if (dr6 & 0b0001) != 0 {
                        let triggered_addr = check_addr + 0;
                        if *perms == Permissions::Execute || initial_state.memory.iter().all(|(addr, _, data)| triggered_addr < *addr || triggered_addr >= addr + data.len() as u64)  {
                            found.push(triggered_addr);
                        }
                    }
                    
                    if (dr6 & 0b0010) != 0 {
                        let triggered_addr = check_addr + 1;
                        if *perms == Permissions::Execute || initial_state.memory.iter().all(|(addr, _, data)| triggered_addr < *addr || triggered_addr >= addr + data.len() as u64)  {
                            found.push(triggered_addr);
                        }
                    }
                    
                    if (dr6 & 0b0100) != 0 {
                        let triggered_addr = check_addr + 2;
                        if *perms == Permissions::Execute || initial_state.memory.iter().all(|(addr, _, data)| triggered_addr < *addr || triggered_addr >= addr + data.len() as u64)  {
                            found.push(triggered_addr);
                        }
                    }
                    
                    if (dr6 & 0b1000) != 0 {
                        let triggered_addr = check_addr + 3;
                        if *perms == Permissions::Execute || initial_state.memory.iter().all(|(addr, _, data)| triggered_addr < *addr || triggered_addr >= addr + data.len() as u64)  {
                            found.push(triggered_addr);
                        }
                    }
                }
                Err(_) => {
                    // Do nothing
                }
            }
        }

        Ok(())
    }

    fn check_memory_accesses(&mut self, initial_state: &SystemState<X64Arch>, found: &mut Vec<u64>) -> Result<(), OracleError> {
        let dr = memoffset::offset_of!(libc::user, u_debugreg) as u64;
        let page_size = self.inner.page_size();
        let mut dr7 = self.inner.user_read(dr + 8 * 7).map_err(OracleError::api)?;

        let mut pages_seen = Vec::new();
        for (mapped_addr, perms, _) in initial_state.memory.iter() {
            let page_address = (mapped_addr / page_size) * page_size;
            if pages_seen.contains(&page_address) {
                continue;
            }

            pages_seen.push(page_address);
            for check_addr in (page_address..page_address + page_size).step_by(32) {
                for regnum in 0..4 {
                    self.inner.user_write(dr + 8 * regnum, check_addr + regnum * 8).map_err(OracleError::api)?;

                    dr7 = bit_replace(dr7, 18 + 4*regnum, 2, 0b10); // size, 00 = 1, 01 = 2, 10 = 8, 11 = 4
                    dr7 = bit_replace(dr7, 16 + 4*regnum, 2, 0b11); // when, 00 = execution, 01 = write, 11 = read/write
                    dr7 = dr7 | (3 << (2*regnum));
                }
                self.inner.user_write(dr + 8 * 7, dr7).map_err(OracleError::api)?;

                let before = &initial_state.cpu;
                let mut regs = before.into();
                let dr6 = self.execute_and_interpret(&initial_state.memory, &mut regs, |me, _regs| {
                    Ok(me.inner.user_read(dr + 8 * 6).map_err(OracleError::api)?)
                });

                match dr6 {
                    // ! The bits correspond to the nth enabled DR register
                    Ok(dr6) => if dr6 & 0b1111 != 0 {
                        if (dr6 & 0b0001) != 0 {
                            self.check_memory_accesses_small(check_addr, perms, initial_state, &mut dr7, dr, found)?;
                        }
                        
                        if (dr6 & 0b0010) != 0 {
                            self.check_memory_accesses_small(check_addr + 8, perms, initial_state, &mut dr7, dr, found)?;
                        }
                        
                        if (dr6 & 0b0100) != 0 {
                            self.check_memory_accesses_small(check_addr + 16, perms, initial_state, &mut dr7, dr, found)?;
                        }
                        
                        if (dr6 & 0b1000) != 0 {
                            self.check_memory_accesses_small(check_addr + 24, perms, initial_state, &mut dr7, dr, found)?;
                        }
                    }
                    Err(_) => {
                        // Do nothing
                    }
                }
            }
        }

        // Disable all breakpoints again
        let dr7 = self.inner.user_read(dr + 8 * 7).map_err(OracleError::api)?;
        self.inner.user_write(dr + 8 * 7, dr7 & !0xff).map_err(OracleError::api)?;

        Ok(())
    }
}

impl<B: X64OracleBackend> Oracle<X64Arch> for X64Oracle<B> {
    fn valid_executable_addresses(&mut self) -> std::ops::Range<u64> {
        self.inner.valid_addresses()
    }

    fn can_map(&mut self, addr: u64) -> bool {
        self.inner.valid_addresses().contains(&addr)
    }

    fn page_size(&mut self) -> u64 {
        self.inner.page_size()
    }

    fn observe(&mut self, state: &liblisa_core::arch::SystemState<X64Arch>) -> Result<liblisa_core::arch::SystemState<X64Arch>, OracleError> {
        let before = &state.cpu;
        let mut regs = before.into();

        trace!("Executing {:X?}", before);
        
        let result = self.execute_and_interpret(&state.memory, &mut regs, |me, regs| {
            let mem = state.memory.data.iter().enumerate()
                .map(|(index, (addr, perms, data))| (*addr, *perms, if perms == &Permissions::ReadWrite {
                    // This won't crash because the permissions on the first memory access are Executable
                    let shm = match &me.current_mapping[index - 1] {
                        Mapping::Page { shm, .. } => shm,
                        Mapping::ReUse(index) => {
                            if let Mapping::Page { shm, .. } = &me.current_mapping[*index] {
                                shm
                            } else {
                                unreachable!("Mapping::ReUse should never point to another Mapping::ReUse")
                            }
                        }
                    };

                    shm.read(*addr, data.len()).to_owned()
                } else {
                    data.clone()
                }));
            
            trace!("Result = {:X?} {:X?}", regs, mem);
            Ok(SystemState::new(regs.into(), MemoryState::new(mem)))
        });

        result
    }

    fn restart(&mut self) {
        // Release all mapped memory
        for mapping in self.current_mapping.drain(..) {
            match mapping {
                Mapping::Page { shm, .. } => self.pool.release(shm),
                Mapping::ReUse(_) => {}
            }
        }

        self.inner.restart(&mut self.executable_shm).unwrap()
    }

    fn scan_unspecified_memory_accesses(&mut self, before: &liblisa_core::arch::SystemState<X64Arch>) -> Result<Vec<u64>, OracleError> {
        let mut accesses = Vec::new();
        self.check_memory_accesses(before, &mut accesses)?;

        Ok(accesses)
    }

    fn debug_dump(&mut self) {
        println!("Current mapping: {:X?}", self.current_mapping.iter().collect::<Vec<_>>());
        self.inner.debug_dump();
    }

    fn kill(self) {
        self.inner.kill()
    }
}