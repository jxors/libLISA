use std::{fmt, vec::IntoIter};

use crate::arch::{Arch, Flag, Register, State};
use serde::{Serialize, Deserialize};

pub use FakeReg::*;
pub use FakeFlag::*;

#[derive(Hash, Debug, PartialEq, Eq, Copy, Clone, Default, PartialOrd, Ord, Serialize, Deserialize)]
pub struct FakeArch;

#[derive(Hash, Debug, PartialEq, Eq, Copy, Clone, PartialOrd, Ord, Serialize, Deserialize)]
pub enum FakeReg {
    R0 = 0,
    R1,
    R2,
    R3,
    R4,
    R5,
    R6,
    R7,
    RZ,
}

#[derive(Hash, Debug, PartialEq, Eq, Copy, Clone, PartialOrd, Ord, Serialize, Deserialize)]
pub enum FakeFlag {
    F0 = 0,
    F1,
    F2,
}

#[derive(Hash, Debug, PartialEq, Eq, Copy, Clone, PartialOrd, Ord, Serialize, Deserialize)]
pub struct FakeState {
    regs: [u64; 4],
    flags: [bool; 3],
}

impl Arch for FakeArch {
    type CpuState = FakeState;
    type Reg = FakeReg;
    type Flag = FakeFlag;

    fn is_instruction_included(_b: &[u8]) -> bool {
        true
    }
}

impl State<FakeArch> for FakeState {
    fn reg(&self, reg: &FakeReg) -> u64 {
        self.regs[*reg as usize]
    }

    fn flag(&self, flag: &FakeFlag) -> bool {
        self.flags[*flag as usize]
    }

    fn serialize_flags(&self) -> u64 {
        todo!()
    }

    fn create<R: FnMut(&FakeReg) -> u64, F: FnMut(&FakeFlag) -> bool>(mut r: R, mut f: F) -> Self {
        FakeState {
            regs: [r(&FakeReg::R0), r(&FakeReg::R1), r(&FakeReg::R2), r(&FakeReg::R3)],
            flags: [f(&FakeFlag::F0), f(&FakeFlag::F1), f(&FakeFlag::F2)]
        }
    }

    fn set_reg(&mut self, reg: &FakeReg, value: u64) {
        self.regs[*reg as usize] = value;
    }

    fn set_flag(&mut self, flag: &FakeFlag, value: bool) {
        self.flags[*flag as usize] = value;
    }
}

impl fmt::Display for FakeReg {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

impl fmt::Display for FakeFlag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

impl Register for FakeReg {
    type Iter = IntoIter<FakeReg>;

    fn iter() -> Self::Iter {
        vec! [
            FakeReg::R0,
            FakeReg::R1,
            FakeReg::R2,
        ].into_iter()
    }

    fn pc() -> Self {
        Self::R0
    }

    fn zero() -> Self {
        Self::RZ
    }

    const MAX_NUM: usize = 3;

    fn as_num(&self) -> usize {
        *self as usize
    }
}

impl Flag for FakeFlag {
    type Iter = IntoIter<FakeFlag>;

    fn iter() -> Self::Iter {
        vec! [
            FakeFlag::F0,
            FakeFlag::F1,
            FakeFlag::F2,
        ].into_iter()
    }
}