use std::fmt::Display;
use serde::{Serialize, Deserialize};
use liblisa_core::arch::{Arch, Flag, Instr, Instruction, Register, State};

#[derive(Clone, Debug, PartialEq, Eq, Hash, Default, PartialOrd, Ord, Serialize, Deserialize)]
pub struct X64Arch;

impl X64Arch {
    pub fn normalize_instr(instr: Instr) -> Instruction {
        let b = instr.bytes();
        match b {
            // CS & DS segment overrides are used as branch prediction hints; They don't affect the behavior of the code itself.
            [0x3E, ..] | [0x2E, ..] => Self::normalize_instr(Instr::from(&b[1..])),
            _ => Instruction::new(b),
        }
    }
}

fn decode_modrm(b: u8) -> (u8, u8, u8) {
    let v_mod = b >> 6;
    let v_reg = (b >> 3) & 0b111;
    let v_rm = b & 0b111;

    (v_mod, v_reg, v_rm)
}

impl Arch for X64Arch {
    type CpuState = X64State;
    type Reg = X64Reg;
    type Flag = X64Flag;

    fn is_instruction_included(b: &[u8]) -> bool {
        /*
        https://github.com/corkami/docs/blob/master/x86/x86.md
        https://gist.github.com/lancejpollard/1db84c23  3bcd849b237df76b3a6c4d9e
        https://wiki.osdev.org/X86-64_Instruction_Encoding#Legacy_Prefixes
        
        In 64-bit, prefixes work as follows:

        === Legacy Prefixes ===
        [F0 | F2 | F3] - group 1 sometimes mandatory?
            (group 2 is for segment overrides and branching hints, which don't work or we can't observe, respectively)
        [66] - group 3: operand size prefix
        [67] - group 4: address size prefix

        === New Prefixes ===
        [REX | VEX | XOP]

        "REX prefix is not allowed in extended instruction encodings that employ the VEX or XOP prefixes"
        https://www.amd.com/system/files/TechDocs/24594.pdf

        4 * 2 * 2 * 4 = enumerate the entire instruction space 64x

        */

        // Prefixes that are mandatory for some instructions
        let b = match b {
            [ 0xF0, .. ] | [ 0xF2, .. ] | [ 0xF3, .. ] => &b[1..],
            _ => b,
        };

        // Operand size override
        let b = match b {
            [ 0x66, .. ] => &b[1..],
            _ => b,
        };

        // Address size override
        // TODO: Disabled this to reduce the instruction space a bit
        // let b = match b {
        //     [ 0x67, .. ] => &b[1..],
        //     _ => b,
        // };

        // Rex prefix
        let b = if b.len() >= 1 && b[0] & 0xf0 == 0x40 {
            &b[1..]
        } else {
            b   
        };

        // TODO: EVEX prefix; Not supported on the 3900X so very low priority
        // TODO: VEX/XOP cannot be followed up by a 'legacy' opcode?
        let b = match b {
            // Two-byte VEX
            [ 0xC5, .. ] if b.len() >= 2 => &b[2..],
            [ 0xC5, .. ] => return true,

            // Three-byte VEX
            [ 0xC4, .. ] if b.len() >= 3 => &b[3..],
            [ 0xC4, .. ] => return true,

            // Three-byte XOP: no longer supported on Zen architecture, never supported on Intel.
            // 8F /0 is the POP instruction; 8F /n where n > 0 is XOP.
            // Here, we filter all instructions that are XOP-prefixed.
            [ 0x8F, x, .. ] if (x >> 3) & 0x7 != 0 => return false,
            [ 0x8F, .. ] => return true,
            _ => b,
        };

        match b {
            // syscall
            [ 0x0F, 0x05 ] => return false,
            // int 0x?? -- we don't want to trigger interrupts (like syscalls, int 0x80)
            [ 0xCD, .. ] => return false,
            // retf, does "interesting" things with the CS/SS registers and possibly the processor mode?
            // might possibly be destroying the page table?
            [ 0xCA, .. ] | [ 0xCB, .. ] => return false,
            // callf absolute offset, jmpf absolute offset, see retf
            [ 0x9A, .. ] | [ 0xEA, .. ] => return false,
            // callf /3, jmpf /5, see retf
            [ 0xFF, b, .. ] if (b >> 3) & 0x7 == 0x3 || (b >> 3) & 0x7 == 0x5 => return false,


            // Some instructions are blocked via UMIP.
            // These instructions are emulated by the kernel.
            // The kernel does a bad job of emulating.
            // It does not trigger the breakpoint after executing one instruction.
            // It does not trigger page faults at the right addresses.
            // It might change behavior from one kernel version to another.
            // We manually exclude these instructions from our analysis.
            // 0F 00 /0 -- SLDT
            // 0F 00 /1 -- STR
            [ 0x0F, 0x00, modrm, ..] if decode_modrm(*modrm).1 == 0 || decode_modrm(*modrm).1 == 1 => false, 
            // 0F 01 /0 -- SGDT
            // 0F 01 /1 -- SIDT
            // 0F 01 /4 -- SMSW
            [ 0x0F, 0x01, modrm, ..] if decode_modrm(*modrm).1 == 0 || decode_modrm(*modrm).1 == 1 || decode_modrm(*modrm).1 == 4 => false, 

            [ x, .. ] => match x {
                // Legacy prefixes, up to 4 bytes, one per group
                0xF0 | 0xF2 | 0xF3
                // Segment overrides; have no effect in 64-bit mode (*mostly) (2E and 3E can also be branching hints, which we don't care about)
                | 0x2E | 0x36 | 0x3E | 0x26 | 0x64 | 0x65
                // Operand size override
                | 0x66 
                // Address size override
                | 0x67
                // REX
                | 0x40 | 0x41 | 0x42 | 0x43 | 0x44 | 0x45 | 0x46 | 0x47 | 0x48 | 0x49 | 0x4A | 0x4B | 0x4C | 0x4D | 0x4E | 0x4F
                // VEX/XOP
                | 0xC4 | 0xC5 | 0x8F => return false,
                _ => true,
            }
            _ => true,
        }    
    }
}

#[derive(Debug, Clone, Default, Eq)]
pub struct X64State {
    pub(crate) basic_regs: [u64; 19],
    pub(crate) flags: u8,
}

impl PartialEq for X64State {
    fn eq(&self, other: &Self) -> bool {
        if self.flags != other.flags {
            return false;
        }

        for reg in X64Reg::iter() {
            if self.reg(&reg) != other.reg(&reg) {
                return false;
            }
        }

        return true;
    }
}

impl State<X64Arch> for X64State {
    fn reg(&self, reg: &X64Reg) -> u64 {
        if reg == &X64Reg::Riz {
            assert_eq!(self.basic_regs[*reg as usize], 0);
        }

        self.basic_regs[*reg as usize]
    }

    fn create<R: FnMut(&X64Reg) -> u64, F: FnMut(&X64Flag) -> bool>(mut regval: R, mut flagval: F) -> Self {
        let mut s = Self::default();
        X64Reg::iter().for_each(|reg| s.set_reg(&reg, regval(&reg)));
        X64Flag::iter().for_each(|flag| s.set_flag(flag, flagval(&flag)));
        s
    }

    fn flag(&self, flag: &X64Flag) -> bool {
        (self.flags >> (*flag as usize)) & 1 == 1
    }

    fn serialize_flags(&self) -> u64 {
        self.flags as u64
    }

    fn set_reg(&mut self, reg: &X64Reg, value: u64) {
        assert!(reg != &X64Reg::Riz);
        self.basic_regs[*reg as usize] = value;
    }

    fn set_flag(&mut self, flag: &X64Flag, value: bool) {
        let mask = 1 << (*flag as usize);
        if value {
            self.flags |= mask;
        } else {
            self.flags = self.flags & !mask;
        }
    }
}

impl X64State {
    pub fn set_flag(&mut self, flag: X64Flag, value: bool) {
        self.flags = (self.flags & !(1 << (flag as usize))) | if value { 1 } else { 0 } << (flag as usize);
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum X64Reg {
    Rax = 0,
    Rcx,
    Rdx,
    Rsi,
    Rdi,
    Rip,
    Rbp,
    Rbx,
    Rsp,
    R8,
    R9,
    R10,
    R11,
    R12,
    R13,
    R14,
    R15,

    Riz,
}

impl Display for X64Reg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            X64Reg::Rax => write!(f, "RAX"),
            X64Reg::Rcx => write!(f, "RCX"),
            X64Reg::Rdx => write!(f, "RDX"),
            X64Reg::Rsi => write!(f, "RSI"),
            X64Reg::Rdi => write!(f, "RDI"),
            X64Reg::Rip => write!(f, "RIP"),
            X64Reg::Rbp => write!(f, "RBP"),
            X64Reg::Rbx => write!(f, "RBX"),
            X64Reg::Rsp => write!(f, "RSP"),
            X64Reg::R8 => write!(f, "R8"),
            X64Reg::R9 => write!(f, "R9"),
            X64Reg::R10 => write!(f, "R10"),
            X64Reg::R11 => write!(f, "R11"),
            X64Reg::R12 => write!(f, "R12"),
            X64Reg::R13 => write!(f, "R13"),
            X64Reg::R14 => write!(f, "R14"),
            X64Reg::R15 => write!(f, "R15"),
            X64Reg::Riz => write!(f, "RIZ"),
        }
    }
}

impl Register for X64Reg {
    type Iter = X64RegIterator;

    fn iter() -> Self::Iter {
        X64RegIterator {
            current: Some(X64Reg::Rax),
        }
    }

    fn is_pc(&self) -> bool {
        self == &X64Reg::Rip
    }

    fn pc() -> Self {
        X64Reg::Rip
    }

    fn zero() -> Self {
        X64Reg::Riz
    }

    fn is_zero(&self) -> bool {
        self == &X64Reg::Riz
    }

    fn as_num(&self) -> usize {
        *self as usize
    }

    // TODO: Can we derive this automatically?
    // Just return a number that will certainly be greater than the max
    const MAX_NUM: usize = 32;
}

pub struct X64RegIterator {
    current: Option<X64Reg>,
}

impl Iterator for X64RegIterator {
    type Item = X64Reg;

    fn next(&mut self) -> Option<Self::Item> {
        let result = self.current.clone();
        if let Some(val) = result {
            use X64Reg::*;
            self.current = (|| Some(match val {
                Rax => Rcx,
                Rcx => Rdx,
                Rdx => Rsi,
                Rsi => Rdi,
                Rdi => Rip,
                Rip => Rbp,
                Rbp => Rbx,
                Rbx => Rsp,
                Rsp => R8,
                R8 => R9,
                R9 => R10,
                R10 => R11,
                R11 => R12,
                R12 => R13,
                R13 => R14,
                R14 => R15,
                R15 => return None,
                Riz => return None,
            }))();
        }

        result
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum X64Flag {
    Cf = 0,
    Pf,
    Af,
    Zf,
    Sf,
    Of,
}

impl Display for X64Flag {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            X64Flag::Cf => "CF",
            X64Flag::Pf => "PF",
            X64Flag::Af => "AF",
            X64Flag::Zf => "ZF",
            X64Flag::Sf => "SF",
            X64Flag::Of => "OF",
        })
    }
}

impl Flag for X64Flag {
    type Iter = X64FlagIterator;

    fn iter() -> Self::Iter {
        X64FlagIterator {
            current: Some(X64Flag::Cf),
        }
    }
}

pub struct X64FlagIterator {
    current: Option<X64Flag>,
}

impl Iterator for X64FlagIterator {
    type Item = X64Flag;

    fn next(&mut self) -> Option<Self::Item> {
        let result = self.current.clone();
        if let Some(val) = result {
            use X64Flag::*;
            self.current = match val {
                Cf => Some(Pf),
                Pf => Some(Af),
                Af => Some(Zf),
                Zf => Some(Sf),
                Sf => Some(Of),
                Of => None,
            };
        }

        result
    }
}

#[allow(unused)]
mod tests {
    use crate::arch::{Flag, State};
    use super::{X64Flag, X64State};

    #[test]
    pub fn get_set_flags() {
        let mut s = X64State::create(|_| 0, |_| false);

        for f in X64Flag::iter() {
            s.set_flag(f, false);
            assert_eq!(s.flag(&f), false);

            s.set_flag(f, true);
            assert_eq!(s.flag(&f), true);
        }
    }
}