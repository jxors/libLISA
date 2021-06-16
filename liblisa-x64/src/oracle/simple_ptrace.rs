use std::{error::Error, mem, ops::Range, os::unix::process::CommandExt, path::{Path, PathBuf}, process::{Child, Command}, sync::Arc};
use log::{error, info, trace};
use nix::{errno::Errno, libc::{self, MAP_FIXED, PROT_EXEC, PROT_READ, siginfo_t, user_regs_struct}, libc::{MAP_SHARED, pid_t}, sys::ptrace::{self, Options, Request, traceme}, sys::signal::Signal, sys::uio::IoVec, sys::wait::WaitStatus, sys::{ptrace::AddressType, wait::waitpid}, unistd::Pid};
use liblisa_core::arch::{Instr, Permissions, State, Register};
use liblisa_core::oracle::OracleError;

use crate::memory::SharedMemory;
use crate::arch::X64State;
use thiserror::Error;

use super::{Mapper, Unmapper, X64OracleBackend};

#[allow(unused, non_snake_case, non_camel_case_types, non_upper_case_globals)]
mod sys {
    include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
}

struct PtracedProcess {
    pid: Pid,
    child: Child,
}

fn spawn_process(cmd: &mut Command) -> Result<(Pid, Child), Box<dyn Error>> {
    for _ in 0..100 {
        let mut child = cmd.spawn()?;
        let raw_pid = child.id() as i32;
        info!("raw_pid = {}", raw_pid);
        let pid = Pid::from_raw(raw_pid);

        waitpid(pid, None)?;
        if let Err(e) = ptrace::setoptions(pid, Options::PTRACE_O_EXITKILL) {
            if let nix::Error::Sys(Errno::ESRCH) = e {
                error!("Failed to attach to the process! Retrying...");
                child.kill().ok();
                child.wait().ok();
            } else {
                Err(e)?;
            }
        } else {
            return Ok((pid, child));
        }
    }

    panic!("Process failed to spawn");
}

impl PtracedProcess {
    pub fn new(binary_path: PathBuf) -> Result<PtracedProcess, Box<dyn Error>> {
        let mut cmd = Command::new(binary_path);
        let (pid, child) = spawn_process(unsafe {
            cmd.pre_exec(|| {
                traceme().expect("Unable to trace process");
                return Ok(())
            })
        })?;

        // TODO: Disable as many syscalls as possible with seccomp https://security.stackexchange.com/questions/210400/difference-between-linux-capabities-and-seccomp to limit the possibility of accidentially invoking a syscall

        Ok(PtracedProcess {
            pid,
            child,
        })
    }

    fn raw_pid(&self) -> pid_t {
        self.pid.as_raw()
    }

    fn get_basic_regs(&mut self) -> Result<user_regs_struct, nix::Error> {
        let mut output = [0u8; mem::size_of::<user_regs_struct>()];
        Ok(unsafe {
            let addr = sys::NT_PRSTATUS;
            let mut data = IoVec::from_mut_slice(&mut output);
            let data_ptr = &mut data as *mut _;

            // The ptrace function has been deprecated without implementing an actual alternative to PTRACE_GETREGSET
            // So we can ignore the deprecation for now until a safe alternative is provided.
            #[allow(deprecated)]
            let result = libc::ptrace(Request::PTRACE_GETREGSET as u32, self.pid, addr, data_ptr);

            if result != 0 {
                Err(nix::Error::from_errno(Errno::from_i32(-result as i32)))?
            }

            output.align_to::<user_regs_struct>().1[0]
        })
    }

    fn set_basic_regs(&mut self, regs: &user_regs_struct) {
        let p: *const user_regs_struct = regs;     // the same operator is used as with references
        let p: *const u8 = p as *const u8;  // convert between pointer types
        let input: &[u8] = unsafe { 
            std::slice::from_raw_parts(p, mem::size_of::<user_regs_struct>())
        };
        unsafe {
            let addr = sys::NT_PRSTATUS;
            let data = IoVec::from_slice(input);
            let data_ptr = &data as *const _;

            // The ptrace function has been deprecated without implementing an actual alternative to PTRACE_GETREGSET
            // So we can ignore the deprecation for now until a safe alternative is provided.
            #[allow(deprecated)]
            let result = libc::ptrace(Request::PTRACE_SETREGSET as u32, self.pid, addr, data_ptr);
            assert_eq!(result, 0, "ptrace setregset call failed: {:X?}, running={:?}", regs, self.child.try_wait());
        }
    }

    fn mem_write(&mut self, addr: u64, data: &[u8]) -> Result<(), nix::Error> {
        for pos in ((addr & !7)..=((addr + data.len() as u64 - 1) | 7)).step_by(8) {
            // TODO: Don't read if we are overwriting everything
            let w = ptrace::read(self.pid, pos as AddressType)?;
            let mut mem_data = w.to_le_bytes();
            for x in 0..8 {
                if let Some(val) = data.get(((pos + x).overflowing_sub(addr).0) as usize) {
                    mem_data[x as usize] = *val;
                }
            }

            let w = u64::from_le_bytes(mem_data);
            unsafe { ptrace::write(self.pid, pos as AddressType, w as u64 as *mut _)? }
        }

        Ok(())
    }

    fn user_write(&mut self, addr: u64, word: u64) -> Result<(), nix::Error> {
        // The ptrace function has been deprecated without implementing an actual alternative to PTRACE_POKEUSER
        // So we can ignore the deprecation for now until a safe alternative is provided.
        #[allow(deprecated)]
        let result = unsafe { libc::ptrace(Request::PTRACE_POKEUSER as u32, self.pid, addr, word) };
        
        if result != 0 {
            Err(nix::Error::from_errno(Errno::from_i32(-result as i32)))
        } else {
            Ok(())
        }
    }

    fn user_read(&mut self, addr: u64) -> Result<u64, nix::Error> {
        // The ptrace function has been deprecated without implementing an actual alternative to PTRACE_POKEUSER
        // So we can ignore the deprecation for now until a safe alternative is provided.
        #[allow(deprecated)]
        let result = unsafe { libc::ptrace(Request::PTRACE_PEEKUSER as u32, self.pid, addr, 0) };
        
        if result < 0 {
            Err(nix::Error::from_errno(Errno::from_i32(-result as i32)))
        } else {
            Ok(result as u64)
        }
    }

    fn step(&mut self, sig: Option<Signal>) -> Result<(), nix::Error> {
        Ok(ptrace::step(self.pid, sig)?)
    }

    fn cont(&mut self, sig: Option<Signal>) -> Result<(), nix::Error> {
        Ok(ptrace::cont(self.pid, sig)?)
    }

    #[allow(unused)]
    fn step_syscall(&mut self, sig: Option<Signal>) -> Result<(), nix::Error> {
        Ok(ptrace::syscall(self.pid, sig)?)
    }

    fn wait_single(&mut self) -> Result<WaitStatus, nix::Error> {
        Ok(waitpid(self.pid, None)?)
    }

    fn signal_info(&mut self) -> Result<siginfo_t, nix::Error> {
        Ok(ptrace::getsiginfo(self.pid)?)
    }

    fn wait_step(&mut self) -> Result<WaitStatus, nix::Error> {
        loop {
            match self.wait_single()? {
                // We don't care about these signals, 
                WaitStatus::Stopped(_, Signal::SIGWINCH) | WaitStatus::Stopped(_, Signal::SIGINT) => {
                    self.step(None)?;
                },
                wait_result => return Ok(wait_result),
            }
        }
    }

    fn wait_break(&mut self) -> Result<WaitStatus, nix::Error> {
        loop {
            match self.wait_single()? {
                // We don't care about these signals, 
                WaitStatus::Stopped(_, Signal::SIGWINCH) | WaitStatus::Stopped(_, Signal::SIGINT) => {
                    self.cont(None)?;
                },
                wait_result => return Ok(wait_result),
            }
        }
    }

    fn perform_syscalls<'a>(&'a mut self, rip: u64, target: Option<&mut SharedMemory>) -> Result<Syscallable<'a>, OracleError> {
        const SYSCALL: Instr<'static> = Instr::new(&[ 0x0F, 0x05 ]);
        if let Some(target) = target {
            target.write(rip, SYSCALL.bytes());
        } else {
            self.mem_write(rip, SYSCALL.bytes()).map_err(OracleError::api)?;
        }
        let regs = self.get_basic_regs().map_err(OracleError::api)?;

        Ok(Syscallable {
            process: self,
            rip,
            regs,
        })
    }

    fn perform_syscalls_jit<'process, 'shm>(&'process mut self, rip: u64, target: &'shm mut SharedMemory, page_size: u64) -> Result<SyscallJitter<'process, 'shm>, OracleError> {
        Ok(SyscallJitter {
            process: self,
            pos: rip,
            shm: target,
            rip,
            state: Default::default(),
            page_size,
            regs: user_regs_struct {
                r15: 0,
                r14: 0,
                r13: 0,
                r12: 0,
                rbp: 0,
                rbx: 0,
                r11: 0,
                r10: 0,
                r9: 0,
                r8: 0,
                rax: 0,
                rcx: 0,
                rdx: 0,
                rsi: 0,
                rdi: 0,
                orig_rax: 0,
                rip: 0,
                // We cannot modify these registers in x86-64
                cs: 0x33,
                ss: 0x2b,
                eflags: 0,
                rsp: 0,
                fs_base: 0,
                gs_base: 0,
                ds: 0,
                es: 0,
                fs: 0,
                gs: 0,
            },
        })
    }

    fn kill(mut self) {
        self.child.kill().ok();
        self.child.wait().ok();
    }
}

struct Syscallable<'a> {
    process: &'a mut PtracedProcess,
    rip: u64,
    regs: user_regs_struct,
}

impl<'a> Syscallable<'a> {
    fn syscall(&mut self, num: u32, arg1: u64, arg2: u64, arg3: u64, arg4: u64, arg5: u64, arg6: u64) -> Result<u64, nix::Error> {
        let regs = &mut self.regs;
        regs.rax = num as u64;
        regs.rdi = arg1;
        regs.rsi = arg2;
        regs.rdx = arg3;
        regs.r10 = arg4;
        regs.r8 = arg5;
        regs.r9 = arg6;
        regs.rip = self.rip;
        self.process.set_basic_regs(regs);
        self.process.step(None)?;

        match self.process.wait_step()? {
            WaitStatus::Stopped(_, Signal::SIGTRAP) => {
                let new_regs = self.process.get_basic_regs().unwrap();
                Ok(new_regs.rax)
            }
            WaitStatus::Stopped(_, signal) => {
                let info = self.process.signal_info()?;
                let addr = unsafe { info.si_addr() } as u64;
                panic!("Received unexpected signal {:X?}: {:X?}", signal, addr);
            }
            other => unimplemented!("WaitStatus = {:?}", other),
        }
    }

    fn mem_map(&mut self, addr: u64, length: u64, prot: i32, flags: i32, fd: i32) -> Result<u64, nix::Error> {
        let ret = self.syscall(sys::SYS_mmap, addr, length, prot as u64, flags as u64, fd as u64, 0)?;
        if (ret as i64) >= 0 {
            Ok(ret)
        } else {
            error!("Mapping {:X} (len={:X}) gave error = {}", addr, length, ret as i64);
            Err(nix::Error::Sys(Errno::from_i32(-(ret as i32))))
        }
    }

    fn mem_unmap(&mut self, addr: u64, length: u64) -> Result<(), PtraceError> {
        let ret = self.syscall(sys::SYS_munmap, addr, length, 0, 0, 0, 0)
            .map_err(|e| PtraceError::UnableToUnmap(addr..addr + length, e))?;
        if ret == 0 {
            Ok(())
        } else {
            error!("Unmapping {:X} (len={:X}) gave error = {}", addr, length, ret as i64);
            Err(PtraceError::UnableToUnmap(addr..addr + length, nix::Error::from_errno(Errno::from_i32(-(ret as i32)))))
        }
    }
}

#[must_use]
struct SyscallJitter<'process, 'shm> {
    pos: u64,
    shm: &'shm mut SharedMemory,
    process: &'process mut PtracedProcess,
    rip: u64,
    state: [RegVal; 8],
    regs: user_regs_struct,
    page_size: u64,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum RegVal {
    Free,
    Clobbered,
    Num(u64),
}

impl Default for RegVal {
    fn default() -> Self {
        RegVal::Free
    }
}

trait Mov {
    const PREFIX64: &'static [u8];
    const PREFIX32: &'static [u8];
    const CLEAR: &'static [u8];
    const INDEX: usize;

    fn set_reg(r: &mut user_regs_struct, value: u64);
}

struct RAX;
impl Mov for RAX {
    const PREFIX64: &'static [u8] = &[ 0x48, 0xb8 ];
    const PREFIX32: &'static [u8] = &[ 0xb8 ];
    const CLEAR: &'static [u8] = &[ 0x31, 0xc0 ];
    const INDEX: usize = 0;

    fn set_reg(r: &mut user_regs_struct, value: u64) { r.rax = value; r.orig_rax = value }
}

struct RDI;
impl Mov for RDI {
    const PREFIX64: &'static [u8] = &[ 0x48, 0xbf ];
    const PREFIX32: &'static [u8] = &[ 0xbf ];
    const CLEAR: &'static [u8] = &[ 0x31, 0xff ];
    const INDEX: usize = 1;

    fn set_reg(r: &mut user_regs_struct, value: u64) { r.rdi = value }
}

struct RSI;
impl Mov for RSI {
    const PREFIX64: &'static [u8] = &[ 0x48, 0xbe ];
    const PREFIX32: &'static [u8] = &[ 0xbe ];
    const CLEAR: &'static [u8] = &[ 0x48, 0x31, 0xf6 ];
    const INDEX: usize = 2;

    fn set_reg(r: &mut user_regs_struct, value: u64) { r.rsi = value }
}

struct RDX;
impl Mov for RDX {
    const PREFIX64: &'static [u8] = &[ 0x48, 0xba ];
    const PREFIX32: &'static [u8] = &[ 0xba ];
    const CLEAR: &'static [u8] = &[ 0x48, 0x31, 0xd2 ];
    const INDEX: usize = 3;

    fn set_reg(r: &mut user_regs_struct, value: u64) { r.rdx = value }
}

struct R10;
impl Mov for R10 {
    const PREFIX64: &'static [u8] = &[ 0x49, 0xba ];
    const PREFIX32: &'static [u8] = &[ 0x49, 0xc7, 0xc2 ];
    const CLEAR: &'static [u8] = &[ 0x4d, 0x31, 0xd2 ];
    const INDEX: usize = 4;

    fn set_reg(r: &mut user_regs_struct, value: u64) { r.r10 = value }
}

struct R9;
impl Mov for R9 {
    const PREFIX64: &'static [u8] = &[ 0x49, 0xb9 ];
    const PREFIX32: &'static [u8] = &[ 0x49, 0xc7, 0xc1 ];
    const CLEAR: &'static [u8] = &[ 0x4d, 0x31, 0xc9 ];
    const INDEX: usize = 5;

    fn set_reg(r: &mut user_regs_struct, value: u64) { r.r9 = value }
}

struct R8;
impl Mov for R8 {
    const PREFIX64: &'static [u8] = &[ 0x49, 0xb8 ];
    const PREFIX32: &'static [u8] = &[ 0x49, 0xc7, 0xc0 ];
    const CLEAR: &'static [u8] = &[ 0x4d, 0x31, 0xc0 ];
    const INDEX: usize = 6;

    fn set_reg(r: &mut user_regs_struct, value: u64) { r.r8 = value }
}

impl<'shm, 'process: 'shm> SyscallJitter<'process, 'shm> {
    fn push(&mut self, data: &[u8]) {
        self.shm.write(self.pos, data);
        self.pos += data.len() as u64;
    }

    fn set_reg<R: Mov>(&mut self, _: R, value: u64) {
        match self.state[R::INDEX] {
            RegVal::Free => {
                R::set_reg(&mut self.regs, value);
                self.state[R::INDEX] = RegVal::Num(value);
            }
            val if val != RegVal::Num(value) => {
                // TODO: If self.state[R::INDEX] has a value < 255, we can use mov al, [byte] to set the lower 8 bits while keeping the upper the same (0).
                if value == 0 {
                    self.push(R::CLEAR);
                } else if value > u32::MAX as u64 {
                    self.push(R::PREFIX64);
                    self.push(&value.to_le_bytes());
                } else {
                    self.push(R::PREFIX32);
                    self.push(&(value as u32).to_le_bytes());
                }
    
                self.state[R::INDEX] = RegVal::Num(value);
            }
            _ => {}
        }
    }

    pub fn gen_syscall(&mut self, num: u32, arg1: u64, arg2: u64, arg3: u64, arg4: u64, arg5: u64, arg6: u64) {
        self.set_reg(RAX, num as u64);
        self.set_reg(RDI, arg1);
        self.set_reg(RSI, arg2);
        self.set_reg(RDX, arg3);
        self.set_reg(R10, arg4);
        self.set_reg(R8, arg5);
        self.set_reg(R9, arg6);
        if self.pos & 0xfff == 0 {
            self.push(&[ 0x90 ]);
        }
        self.push(&[ 0x0F, 0x05 ]);

        self.state[RAX::INDEX] = RegVal::Clobbered; // RAX is clobbered by the return value
    }

    pub fn gen_error_check(&mut self) {
        self.push(&[ 
            0x48, 0x83, 0xF8, 0x00, // cmp rax, 0
            0x7d, 0x01, // jge +1
            0xcc, // int 3
        ]);
    }

    pub fn gen_break(&mut self) {
        self.push(&[ 
            0xCC, // int 3
        ]);
    }

    pub fn mem_map(&mut self, addr: u64, length: u64, prot: i32, flags: i32, fd: i32) {
        trace!("Mapping {:X}..{:X} @ {:X}: fd={:X}", addr, addr + length, self.pos, fd);
        self.gen_syscall(sys::SYS_mmap, addr, length, prot as u64, flags as u64, fd as u64, 0);
        self.gen_error_check();
    }

    pub fn mem_unmap(&mut self, addr: u64, length: u64) {
        trace!("Unmapping {:X}..{:X} @ {:X}", addr, addr + length, self.pos);
        self.gen_syscall(sys::SYS_munmap, addr, length, 0, 0, 0, 0);
        self.gen_error_check();
    }

    pub fn change_page(&mut self, delta: i64) {
        debug_assert!(delta & 0xfff == 0, "Delta must be a whole number of pages");
        let new_addr = self.pos.overflowing_add(delta as u64).0 + 2;
        debug_assert_eq!(new_addr & 0xfff, (self.pos + 2) & 0xfff, "Page change must continue at last instruction that was executed");
        self.regs.rbp = new_addr;
        self.push(&[ 0xFF, 0xE5 ]);

        trace!("Changing position from {:X} to {:X}", self.pos, new_addr);

        self.pos = new_addr;
    }

    pub fn execute(mut self) -> Result<SyscallCompletion<'process>, nix::Error> {
        if self.pos == self.rip {
            Ok(SyscallCompletion {
                process: self.process,
                pos: None,
            })
        } else {
            self.gen_break();
            self.regs.rip = self.rip;
            self.process.set_basic_regs(&self.regs);
            trace!("Basic regs for syscall: {:X?} going from {:X} to {:X}", self.regs, self.regs.rip, self.pos);
            self.process.cont(None)?;

            Ok(SyscallCompletion {
                process: self.process,
                pos: Some(self.pos),
            })
        }
    }
}

#[must_use]
struct SyscallCompletion<'a> {
    process: &'a mut PtracedProcess,
    pos: Option<u64>,
}

impl<'a> SyscallCompletion<'a> {
    pub fn complete(self, shm: &SharedMemory) -> Result<(), nix::Error> {
        if let Some(pos) = self.pos {
            match self.process.wait_break()? {
                WaitStatus::Stopped(_, Signal::SIGTRAP) => {
                    let new_regs = self.process.get_basic_regs().unwrap();
                    // TODO: We could just check the return code here, saving the need for a full get_basic_regs
                    if new_regs.rip == pos {
                        Ok(())
                    } else {
                        // TODO: We could possibly restart the process here to guarantee it running correctly

                        println!("Real mappings: \n{}\n", std::fs::read_to_string(format!("/proc/{}/maps", self.process.raw_pid())).unwrap());
                        println!("Registers: {:X?}", new_regs);
                        // TODO: Hardcoded page size
                        println!("Memory: {:02X?}", shm.read(0, 4096));

                        panic!("Remapping failed at {:X}", new_regs.rip);
                    }
                }
                WaitStatus::Stopped(_, signal) => {
                    let info = self.process.signal_info()?;
                    let addr = unsafe { info.si_addr() } as u64;
                    
                    println!("Real mappings: \n{}\n", std::fs::read_to_string(format!("/proc/{}/maps", self.process.raw_pid())).unwrap());
                    let new_regs = self.process.get_basic_regs().unwrap();
                    println!("Registers: {:X?}", new_regs);
                    // TODO: Hardcoded page size
                    println!("Memory: {:02X?}", shm.read(0, 4096));
                    panic!("Received unexpected signal {:X?}: {:X?}", signal, addr);
                }
                other => unimplemented!("WaitStatus = {:?}", other),
            }
        } else {
            Ok(())
        }
    }
}

pub struct PtraceBackend {
    process: PtracedProcess,
    current_code_page: Range<u64>,
    binary_path: PathBuf,

    /// Lowest mappable page address up to the (exclusive) end of the mapping range. I.e. if valid addresses are 0x0000 - 0x7fff, this would be 0x0000..0x8000.
    code_pages: Range<u64>,
    page_size: u64,
}

const MMAP_SHARE_FLAGS: i32 = MAP_SHARED | MAP_FIXED;
impl PtraceBackend {
    const MMAP_SHARE_FLAGS: i32 = MAP_SHARED | MAP_FIXED;

    fn execute_instr(&mut self, regs: &mut user_regs_struct) -> Result<WaitStatus, nix::Error> {
        self.process.set_basic_regs(regs);
        self.process.step(None)?;
        self.process.wait_step()
    }

    fn rip(&self) -> u64 {
        self.current_code_page.end - 0x100
    }
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

impl<'a> Mapper for SyscallJitter<'a, 'a> {
    fn map(&mut self, addr: u64, fd: i32, prot: u8) {
        self.mem_map(addr, self.page_size, prot as i32, MMAP_SHARE_FLAGS, fd)
    }
}

impl<'a> Unmapper for SyscallJitter<'a, 'a> {
    fn unmap(&mut self, addr: u64) {
        self.mem_unmap(addr, self.page_size)
    }
}

impl Unmapper for Vec<u64> {
    fn unmap(&mut self, addr: u64) {
        self.push(addr);
    }
}

impl Mapper for Vec<(u64, i32, u8)> {
    fn map(&mut self, addr: u64, fd: i32, prot: u8) {
        self.push((addr, fd, prot));
    }
}

impl PtraceBackend {
    fn setup_process(&mut self, executable_shm: &mut SharedMemory) -> Result<(), Box<dyn Error>> {
        let page_size = self.page_size();
        let mut s = self.process.perform_syscalls(0x401F00, None)?;
        let page_addr = 0x402000;
        let addr = s.mem_map(page_addr, page_size, PROT_READ | PROT_EXEC, Self::MMAP_SHARE_FLAGS, executable_shm.fd())?; 
        if addr != page_addr {
            panic!("Unable to map {:X}..{:X}: we got relocated to {:X}", page_addr, page_addr + page_size, addr);
        }
        let mut s = self.process.perform_syscalls(self.rip(), Some(executable_shm))?;
        s.mem_unmap(0, self.current_code_page.start - 1)?;
        s.mem_unmap(self.current_code_page.end, 0x7fff_ff00_0000 - self.current_code_page.end)?;

        // We determine the lowest address that we can map. The lower this is, the faster instructions can be tested and the easier it is to test instructions with fixed offsets.
        let mut lower_mapping_bound = std::fs::read_to_string("/proc/sys/vm/mmap_min_addr")
            .unwrap_or("65536".to_owned())
            .trim()
            .parse::<u64>()
            .expect("/proc/sys/vm/mmap_min_addr contains an invalid integer");
        assert!(lower_mapping_bound % page_size == 0, "lower_mapping_bound must be a multiple of page_size");
        while lower_mapping_bound != 0 {
            match s.mem_map(lower_mapping_bound - page_size, page_size, PROT_READ, Self::MMAP_SHARE_FLAGS, executable_shm.fd()) {
                Ok(addr) => {
                    trace!("Mapping at {:X} is OK! Decreasing by {:X}", addr, page_size);
                    s.mem_unmap(lower_mapping_bound - page_size, page_size)?;

                    lower_mapping_bound -= page_size;
                }
                Err(e) => {
                    trace!("Failed mapping at {:X}: {}", lower_mapping_bound, e);
                    break;
                }
            }
        }

        if lower_mapping_bound > 0 {
            error!("Lower mapping bound found: {:X} (Use sysctl -w vm.mmap_min_addr=\"0\" to set it to 0 for your current session)", lower_mapping_bound);
        }

        let mut upper_mapping_bound = 0x7fff_fff0_0000;
        loop {
            match s.mem_map(upper_mapping_bound, page_size, PROT_READ, Self::MMAP_SHARE_FLAGS, executable_shm.fd()) {
                Ok(addr) => {
                    trace!("Mapping at {:X} is OK! Decreasing by {:X}", addr, page_size);
                    s.mem_unmap(upper_mapping_bound, page_size)?;

                    upper_mapping_bound += page_size;
                }
                Err(e) => {
                    trace!("Failed mapping at {:X}: {}", upper_mapping_bound, e);
                    break;
                }
            }
        }

        info!("Actual upper mapping bound: {}", upper_mapping_bound);
        self.code_pages = lower_mapping_bound..upper_mapping_bound;

        Ok(())
    }
}

impl X64OracleBackend for PtraceBackend {
    type U = Vec<u64>;
    type M = Vec<(u64, i32, u8)>;
    type E = OracleError;

    fn new<P: AsRef<Path>>(binary_path: P, executable_shm: &mut SharedMemory) -> Result<PtraceBackend, Box<dyn Error>> {
        // Need to create the pool before starting the process, so that the file descriptors of the shared memory are equal.
        // Alternative is to send them via domain socket and have the kernel translate them, but that is more complex.
        let process = PtracedProcess::new(binary_path.as_ref().into())?;
        let mut oracle = PtraceBackend {
            process,
            binary_path: binary_path.as_ref().into(),
            current_code_page: 0x402000..0x403000,
            code_pages: 0..0x7fff_0000_0000,
            page_size: page_size::get() as u64,
        };

        oracle.setup_process(executable_shm)?;

        Ok(oracle)
    }

    fn valid_addresses(&self) -> Range<u64> {
        self.code_pages.clone()
    }

    fn page_size(&self) -> u64 {
        self.page_size
    }

    fn debug_dump(&mut self) {
        println!("Current code page: {:X?}", self.current_code_page);
        println!("Real mappings: \n{}\n", std::fs::read_to_string(format!("/proc/{}/maps", self.process.raw_pid())).unwrap());
    }

    fn get_basic_regs(&mut self) -> Result<user_regs_struct, nix::Error> {
        self.process.get_basic_regs()
    }

    fn clear_fp_exception(&mut self, executable_shm: &mut SharedMemory) {
        let mut regcopy: user_regs_struct = (&X64State::create(|reg| if reg.is_pc() {
            self.current_code_page.start
        } else {
            0
        }, |_| false)).into();
        executable_shm.write(0, &[ 0xDB, 0xE2 ]);
        let b = self.execute_instr(&mut regcopy)
            .expect("Unable to clear FP exception");
        assert!(matches!(b, WaitStatus::Stopped(_, Signal::SIGTRAP)));

        let result_regs = self.process.get_basic_regs().unwrap();
        assert_eq!(result_regs.rip, self.current_code_page.start + 2);
    }

    fn observe<D>(&mut self, mut data: D, mut f_unmap: impl FnMut(&mut D, &mut Self::U), executable_addr: u64, executable_shm: &mut SharedMemory, mut f_map: impl FnMut(&mut D, &mut Self::M), mut f_prepare: impl FnMut(&mut D), mut f_prepare_exec: impl FnMut(&mut D, &mut SharedMemory), regs: &mut user_regs_struct) -> Result<liblisa_x64_kmod::ObservationResult, Self::E> {
        let page_size = self.page_size();

        // ! BEGIN OF ZONE THAT CANNOT RETURN
        let executable_fd = executable_shm.fd();
        let mut s = self.process.perform_syscalls_jit(self.current_code_page.start, executable_shm, page_size)?;
        let mut v = Vec::new();
        f_unmap(&mut data, &mut v);
        for addr in v {
            s.mem_unmap(addr, page_size);
        }

        // Remap the executable page if necessary
        let page_addr = (executable_addr / page_size) * page_size;
        if page_addr != self.current_code_page.start {
            s.mem_map(page_addr, page_size, PROT_EXEC, MMAP_SHARE_FLAGS, executable_fd);
            s.change_page(page_addr as i64 - self.current_code_page.start as i64);
            s.mem_unmap(self.current_code_page.start, self.current_code_page.end - self.current_code_page.start);
            self.current_code_page = page_addr..page_addr + page_size;
        }
        
        let mut v = Vec::new();
        f_map(&mut data, &mut v);
        for (addr, fd, prot) in v {
            s.mem_map(addr, page_size, prot as i32, MMAP_SHARE_FLAGS, fd);
        }

        // TODO: If this fails, we need to throw out all pages and remap them next time
        let completion = s.execute().map_err(|e| PtraceError::MappingSyscallsFailed(e))?;

        // We gain a bit of performance by already writing to memory while the memory is being mapped into the target process
        // We can write all memory except the executable memory while the completion is still running
        // The memory mapping only touches the executable page, which we don't modify here, so everything will run fine
        f_prepare(&mut data);

        completion.complete(&executable_shm).map_err(|e| PtraceError::MappingSyscallsFailed(e))?;
        
        f_prepare_exec(&mut data, executable_shm);

        let wait_result = self.execute_instr(regs).map_err(OracleError::api)?;
        Ok(match wait_result {
            WaitStatus::Stopped(_, Signal::SIGTRAP) => {
                // Process is paused after executing an instruction
                // We cannot determine the instruction length from the IP, as a jump changes this.
                // Therefore, we just assume the length was correct here.
                *regs = self.process.get_basic_regs().map_err(OracleError::api)?;
                liblisa_x64_kmod::ObservationResult::Executed
            },
            WaitStatus::Stopped(_, signal) => {
                let info = self.process.signal_info().map_err(OracleError::api)?;

                trace!("Received signal {:?} with info {:?}", signal, info);

                liblisa_x64_kmod::ObservationResult::Fault { 
                    signal,
                    si_code: info.si_code,
                    si_addr: unsafe { info.si_addr() as u64 },
                    si_errno: info.si_errno,
                }
            },
            WaitStatus::Signaled(_, sig, _) => {
                panic!("Process was killed by {}!", sig);
            },
            WaitStatus::Exited(_, return_code) => {
                panic!("Process exited with return code {}", return_code);
            },
            other => {
                panic!("Got {:?}", other);
            },
        })
    }

    fn user_write(&mut self, addr: u64, word: u64) -> Result<(), nix::Error> {
        self.process.user_write(addr, word)
    }

    fn user_read(&mut self, addr: u64) -> Result<u64, nix::Error> {
        self.process.user_read(addr)
    }

    fn pid(&self) -> Option<i32> {
        Some(self.process.raw_pid())
    }

    fn restart(&mut self, executable_shm: &mut SharedMemory) -> Result<(), Box<dyn Error>> {
        let mut new = PtracedProcess::new(self.binary_path.clone())?;
        std::mem::swap(&mut self.process, &mut new);
        new.kill();

        self.current_code_page = 0x402000..0x403000;
        self.setup_process(executable_shm)?;

        Ok(())
    }

    fn kill(self) {
        self.process.kill();
    }
}

#[cfg(test)]
#[allow(unused)]
mod tests {
    use test_env_log::test;
    use liblisa_core::arch::{Instr, InstructionInfo, MemoryState, Permissions, SystemState, Register, State};
    use liblisa_core::oracle::{Oracle, OracleError};
    use crate::arch::{X64State, X64Reg};

    #[test]
    pub fn map_executable_area() {
        let mut o = crate::x64_simple_ptrace_oracle();
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
    pub fn remap_after_restart() {
        let mut o = crate::x64_simple_ptrace_oracle();
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
    pub fn move_memory() {
        let mut o = crate::x64_simple_ptrace_oracle();
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
    pub fn write_memory() {
        let mut o = crate::x64_simple_ptrace_oracle();
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
        o.debug_dump();
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
        o.debug_dump();
    }

    #[test]
    pub fn execute_many() {
        let mut o = crate::x64_simple_ptrace_oracle();
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
        let mut o = crate::x64_simple_ptrace_oracle();
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