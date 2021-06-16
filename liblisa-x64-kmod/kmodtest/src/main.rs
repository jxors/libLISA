use libc::{PROT_EXEC, PROT_READ, user_regs_struct};
use liblisa_x64_kmod::*;
use memfd::Memfd;
use memmap::MmapMut;
use nix::sys::signal::Signal;
use std::{error::Error, os::unix::prelude::AsRawFd, time::Instant};

pub struct SharedMemory {
    fd: Memfd,
    mem: MmapMut,
    len: usize,
}

impl SharedMemory {
    pub fn new(name: &str, len: usize) -> Result<SharedMemory, Box<dyn Error>> {
        let opts = memfd::MemfdOptions::default().allow_sealing(true);
        let mfd = opts.create(name)?;
    
        mfd.as_file().set_len(len as u64)?;
    
        // Add seals to prevent further resizing.
        let mut seals = memfd::SealsHashSet::new();
        seals.insert(memfd::FileSeal::SealShrink);
        seals.insert(memfd::FileSeal::SealGrow);
        mfd.add_seals(&seals)?;
    
        // Prevent further sealing changes.
        mfd.add_seal(memfd::FileSeal::SealSeal)?;

        Ok(SharedMemory {
            mem: unsafe { MmapMut::map_mut(mfd.as_file()) }?,
            fd: mfd,
            len,
        })
    }

    pub fn fd(&self) -> i32 {
        self.fd.as_file().as_raw_fd()
    }

    pub fn write(&mut self, addr: u64, data: &[u8]) {
        let addr = addr as usize & (self.len - 1);
        self.mem[addr..addr + data.len()].copy_from_slice(data);
    }

    pub fn read(&self, addr: u64, len: usize) -> &[u8] {
        let addr = addr as usize & (self.len - 1);
        &self.mem[addr..addr + len]
    }
}

const DEFAULT_REGS: user_regs_struct = user_regs_struct {
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
};
const EXEC_PROTS: u8 = (PROT_READ | PROT_EXEC) as u8;

fn main() {
    test_normal_execution();
    test_memory_accesses();
    bench();
}

fn bench() {
    println!("Doing a small unscientific benchmark...");

    let mut shm1 = SharedMemory::new("shm1", 4096).unwrap();
    let mut p = ObservationProcess::new("/bin/ls".into()).unwrap();
    shm1.write(0x101, &[ 0x49, 0xC7, 0xC7, 0x44, 0x33, 0x22, 0x11 ]);

    let mut best_time = u128::MAX;
    for _ in 0..300_000 {
        let start = Instant::now();
        let mut regs = user_regs_struct {
            rip: 0xA101,
            ..DEFAULT_REGS
        };
        let mut b = p.start_observe();
        b.unmap(0xA000);
        let mut b = b.start_mapping();
        b.map(0xA000, shm1.fd(), EXEC_PROTS);
        let result = p.observe(&mut regs, b).unwrap();
        
        assert!(result.is_executed());
        assert_eq!(regs.rip, 0xA108);
        assert_eq!(regs.r15, 0x11223344);
        best_time = best_time.min((Instant::now() - start).as_nanos());
    }
    
    println!("Best time = {:.2}us", best_time as f64 / 1000.);
}

fn test_normal_execution() {
    let mut shm = SharedMemory::new("shm1", 4096).unwrap();
    let mut p = ObservationProcess::new("/bin/ls".into()).unwrap();
    {
        println!("Observing NOP");
        let start = Instant::now();
        let mut regs = user_regs_struct {
            rip: 0x5000,
            ..DEFAULT_REGS
        };
        shm.write(0, &[ 0x90 ]);
        let b = p.start_observe();
        let mut b = b.start_mapping();
        b.map(0x5000, shm.fd(), EXEC_PROTS);
        let result = p.observe(&mut regs, b).unwrap();
        
        println!("Result = {:?} in {:.2}us", result, (Instant::now() - start).as_nanos() as f64 / 1000.);
        println!("Output registers = {:#X?}", regs);
        println!("New mappings: \n{}", std::fs::read_to_string(format!("/proc/{}/maps", p.raw_pid())).unwrap());
        assert!(result.is_executed());
        assert_eq!(regs.rip, 0x5001);
    }

    {
        let start = Instant::now();
        let mut regs = user_regs_struct {
            rip: 0xA101,
            ..DEFAULT_REGS
        };
        shm.write(0x101, &[ 0x49, 0xC7, 0xC7, 0x44, 0x33, 0x22, 0x11 ]);
        let mut b = p.start_observe();
        b.unmap(0x5000);
        let mut b = b.start_mapping();
        b.map(0xA000, shm.fd(), EXEC_PROTS);
        let result = p.observe(&mut regs, b).unwrap();
        
        println!("Result = {:?} in {:.2}us", result, (Instant::now() - start).as_nanos() as f64 / 1000.);
        println!("Output registers = {:#X?}", regs);
        println!("New mappings: \n{}", std::fs::read_to_string(format!("/proc/{}/maps", p.raw_pid())).unwrap());
        assert!(result.is_executed());
        assert_eq!(regs.rip, 0xA108);
        assert_eq!(regs.r15, 0x11223344);
    }
}


fn test_memory_accesses() {
    let mut shm = SharedMemory::new("shm1", 4096).unwrap();
    let mut p = ObservationProcess::new("/bin/ls".into()).unwrap();
    {
        println!("Observing memory access for RIP");
        let start = Instant::now();
        let mut regs = user_regs_struct {
            rip: 0x5000,
            ..DEFAULT_REGS
        };
        let b = p.start_observe()
            .start_mapping();
        let result = p.observe(&mut regs, b).unwrap();
        
        println!("Result = {:?} in {:.2}us", result, (Instant::now() - start).as_nanos() as f64 / 1000.);
        println!("Output registers = {:#X?}", regs);
        println!("New mappings: \n{}", std::fs::read_to_string(format!("/proc/{}/maps", p.raw_pid())).unwrap());
        
        if let ObservationResult::Fault { signal, si_code, si_addr, si_errno } = result {
            assert_eq!(si_addr, 0x5000);
            assert_eq!(si_code, 1);
            assert_eq!(si_errno, 0);
            assert_eq!(signal, Signal::SIGSEGV);
        } else {
            panic!("Incorrect result on memory access error: {:X?}", result);
        }
    }

    {
        println!("Observing memory access for RAX");
        let start = Instant::now();
        let mut regs = user_regs_struct {
            rip: 0x5000,
            rax: 0x10_000,
            ..DEFAULT_REGS
        };
        shm.write(0, &[ 0x48, 0x01, 0x18 ]);
        let b = p.start_observe();
        let mut b = b.start_mapping();
        b.map(0x5000, shm.fd(), EXEC_PROTS);
        let result = p.observe(&mut regs, b).unwrap();
        
        println!("Result = {:?} in {:.2}us", result, (Instant::now() - start).as_nanos() as f64 / 1000.);
        println!("Output registers = {:#X?}", regs);
        println!("New mappings: \n{}", std::fs::read_to_string(format!("/proc/{}/maps", p.raw_pid())).unwrap());
        
        if let ObservationResult::Fault { signal, si_code, si_addr, si_errno } = result {
            assert_eq!(si_addr, 0x10_000);
            assert_eq!(si_code, 1);
            assert_eq!(si_errno, 0);
            assert_eq!(signal, Signal::SIGSEGV);
        } else {
            panic!("Incorrect result on memory access error: {:X?}", result);
        }
    }
}