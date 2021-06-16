use std::{convert::TryFrom, fmt::{Debug, Display}, ops::Index};
use rand::Rng;
use serde::{Serialize, Deserialize};
use crate::arch::{Arch, Instr, Instruction, InstructionInfo, MemoryState, Register, State, SystemState, Value};

pub mod arch;
pub mod accesses;
pub mod dataflow;
pub mod encoding;
pub mod oracle;
pub mod counter;
pub mod gen;
pub mod computation;

#[cfg(test)]
mod fake;

pub use accesses::{MemoryAccesses, AccessKind};
pub use gen::{StateGen, RemapError, RandomizationError};
pub use dataflow::Dataflows;
pub use encoding::{Encoding, PartMapping};
pub use computation::Computation;

pub fn randomized_value<R: Rng>(rng: &mut R) -> u64 {
    // Always set the top bit, because we decide the number of prefixed zeroes separately
    // This makes the number of prefix zeroes nicely uniform
    const TOPMOST_BIT: u64 = 0x80000000_00000000;
    let v = rng.gen::<u64>();
    let zeros = rng.gen_range(0, 64);
    let v = v << zeros;

    // Make sure the topmost bit is set
    let v = v | TOPMOST_BIT;

    let shift: u64 = rng.gen_range(0, 65);
    let v = if shift >= 64 { 
        0
    } else {
        v >> shift
    };

    if rng.gen() {
        if shift > 18 && rng.gen() {
            // up to "48-bit" memory address that can actually be mapped
            // we're cropping to just 46 bits, because:
            // - bit 48 is equal to bits 49..64, so it has to be 0 to make the address mappable (a 1 in bit 48..64 is an address reserved for kernel use)
            // - bit 47 is 0, because the highest mappable address is 0x7fff_ffff_e000, not 0x7fff_ffff_f000. So it would be impossible to generate something mappable ending in .._ffff_ffff if bit 47 was set (and it would be set, because we're negating the number here).
            (!v) & 0x0000_3fff_ffff_ffff
        } else {
            // 64-bit negative number
            !v
        }
    } else {
        // (up to) 64-bit positive number
        v
    }
}

pub fn randomized_bytes<R: Rng>(rng: &mut R, len: usize) -> Vec<u8> {
    let mut bits = len * 8;
    let mut result = Vec::new();
    let mut zeroes = rng.gen_range(0, bits);

    let orig_zeroes = zeroes;

    if rng.gen() {
        // Generate bytes prefixed with zeroes (big-endian)
        while zeroes >= 8 {
            result.push(0);
            zeroes -= 8;
        }

        if zeroes != 0 {
            let b: u8 = rng.gen();
            result.push(b >> zeroes);
        }

        while result.len() < len {
            result.push(rng.gen());
        }

        assert_eq!(result.len(), len, "Tried generating {} bits (starting with {} zeroes)", len * 8, orig_zeroes);
    } else {
        // Generate bytes postfixed with zeroes (little-endian)
        while bits >= 8 && bits >= zeroes + 8 {
            result.push(rng.gen());
            bits -= 8;
        }

        if bits > 0 {
            let b: u8 = rng.gen();
            // TODO: Is this shift correct?
            result.push(b << (bits - zeroes));

            while result.len() < len {
                result.push(0);
            }
        }

        assert_eq!(result.len(), len, "Tried generating {} bits (ending with {} zeroes)", len * 8, orig_zeroes);
    }

    // 50% chance to flip all bits (effectively making the number negative)
    if rng.gen() {
        for b in result.iter_mut() {
            *b ^= 0xFF;
        }
    }

    result
}

pub fn random_state<A: Arch>(pc: u64) -> SystemState<A> {
    let mut rng = rand::thread_rng();
    let mut rng2 = rand::thread_rng();
    SystemState::new(A::CpuState::create(|reg| {
        if reg.is_pc() {
            pc
        } else {
            randomized_value(&mut rng)
        }
    }, |_| rng2.gen()), MemoryState::default())
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum LocationKind {
    Reg,
    Memory,
    Flags,
    Flag,
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Location<A: Arch> {
    Reg(A::Reg),
    Memory(usize),
    Flags,
    Flag(A::Flag),
}

impl<A: Arch> Location<A> {
    pub fn kind(&self) -> LocationKind {
        match self {
            Location::Reg(_) => LocationKind::Reg,
            Location::Memory(_) => LocationKind::Memory,
            Location::Flags => LocationKind::Flags,
            Location::Flag(_) => LocationKind::Flag,
        }
    }
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SizedLocation<A: Arch> {
    pub location: Location<A>,
    pub size: Size,
}

impl<A: Arch> Debug for Location<A> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Location::Reg(reg) => write!(f, "Reg[{}]", reg)?,
            Location::Memory(index) => write!(f, "Memory[#{}]", index)?,
            Location::Flags => write!(f, "Flags")?,
            Location::Flag(flag) => write!(f, "Flag[{}]", flag)?,
        }

        Ok(())
    }
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Size {
    pub start_byte: usize,
    pub end_byte: usize,
}

impl Default for Size {
    fn default() -> Self {
        Size {
            start_byte: usize::MIN,
            end_byte: usize::MAX,
        }
    }
}

impl Size {
    pub fn new(start_byte: usize, end_byte: usize) -> Self {
        Size {
            start_byte,
            end_byte,
        }
    }

    pub fn qword() -> Self {
        Size {
            start_byte: 0,
            end_byte: 7,
        }
    }

    pub fn union(&self, other: &Self) -> Self {
        Size {
            start_byte: self.start_byte.min(other.start_byte),
            end_byte: self.end_byte.max(other.end_byte),
        }
    }

    pub fn contains(&self, other: &Self) -> bool {
        self.start_byte <= other.start_byte && self.end_byte >= other.end_byte
    }

    pub fn len(&self) -> usize {
        (self.end_byte - self.start_byte) as usize + 1
    }
}

impl Debug for Size {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.end_byte < self.start_byte {
            write!(f, "-")
        } else {
            write!(f, "{}..{}", self.start_byte, self.end_byte)
        }
    }
}

pub struct WithInstr<T> {
    instr: Instruction,
    inner: T,
}

impl<T> WithInstr<T> {
    pub fn new<I: Into<Instruction>>(instr: I, inner: T) -> WithInstr<T> {
        WithInstr {
            instr: instr.into(),
            inner,
        }
    }

    pub fn instr<'a>(&'a self) -> Instr<'a> {
        self.instr.as_instr()
    }

    pub fn inner(&self) -> &T {
        &self.inner
    }
}


#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Dest<A: Arch> {
    Reg(A::Reg, Size),
    Mem(usize, Size),
    Flag(A::Flag),
    Flags,
}

#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Source<A: Arch> {
    Dest(Dest<A>),
    Imm(usize),
    Const { value: u64, num_bits: usize },
}

impl<A: Arch> PartialEq<Location<A>> for Dest<A> {
    fn eq(&self, other: &Location<A>) -> bool {
        match (self, other) {
            (Dest::Reg(a, _), Location::Reg(b)) => a == b,
            (Dest::Mem(a, _), Location::Memory(b)) => a == b,
            (Dest::Flags, Location::Flags) => true,
            (Dest::Flag(a), Location::Flag(b)) => a == b,
            _ => false,
        }
    }
}

impl<A: Arch> PartialEq<Location<A>> for Source<A> {
    fn eq(&self, other: &Location<A>) -> bool {
        match self {
            Source::Dest(d) => d == other,
            Source::Imm(_) | Source::Const { .. } => false,
        }
    }
}

impl<A: Arch> Dest<A> {
    pub fn size(&self) -> Option<Size> {
        match self {
            Dest::Reg(_, size) | Dest::Mem(_, size) => Some(size.clone()),
            Dest::Flag(_) => Some(Size::new(0, 0)),
            Dest::Flags => Some(Size::new(0, 0)),
        }
    }
    
    pub fn with_size(&self, size: Size) -> Self {
        match self {
            Dest::Reg(r, _) => Dest::Reg(r.clone(), size),
            Dest::Mem(a, _) => Dest::Mem(a.clone(), size),
            Dest::Flags => Dest::Flags,
            Dest::Flag(f) => Dest::Flag(f.clone()),
        }
    }

    pub fn contains(&self, other: &Dest<A>) -> bool {
        match (self, other) {
            (Dest::Reg(r1, s1), Dest::Reg(r2, s2)) => r1 == r2 && s1.contains(s2),
            (Dest::Mem(m1, s1), Dest::Mem(m2, s2)) => m1 == m2 && s1.contains(s2),
            (Dest::Flags, Dest::Flags) | (Dest::Flag(_), Dest::Flags) | (Dest::Flags, Dest::Flag(_)) => true,
            (Dest::Flag(a), Dest::Flag(b)) => a == b,
            _ => false,
        }
    }
}

impl<A: Arch> Source<A> {
    pub fn size(&self) -> Option<Size> {
        match self {
            Source::Dest(d) => d.size(),
            Source::Imm(_) | Source::Const { .. } => None,
        }
    }

    pub fn contains(&self, other: &Source<A>) -> bool {
        match (self, other) {
            (Source::Dest(a), Source::Dest(b)) => a.contains(b),
            _ => false,
        }
    }

    pub fn unwrap_dest(self) -> Dest<A> {
        match self {
            Source::Dest(d) => d,
            other => panic!("Tried to unwrap a Dest in {:?}, but it contains no Dest", other),
        }
    }
}

impl<A: Arch> Debug for Dest<A> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Dest::Reg(reg, size) => write!(f, "Reg({})[{:?}]", reg, size),
            Dest::Mem(index, size) => write!(f, "Mem{}[{:?}]", index, size),
            Dest::Flags => write!(f, "Flags"),
            Dest::Flag(flag) => write!(f, "Flag[{:?}]", flag),
        }
    }
}

impl<A: Arch> Debug for Source<A> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Source::Imm(index) => write!(f, "v{}", index),
            Source::Dest(d) => write!(f, "{:?}", d),
            Source::Const { value, .. } => write!(f, "0x{}", value),
        }
    }
}

impl<A: Arch> Display for Dest<A> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Dest::Reg(reg, size) => write!(f, "Reg({})[{:?}]", reg, size),
            Dest::Mem(index, size) => write!(f, "Mem{}[{:?}]", index, size),
            Dest::Flags => write!(f, "Flags"),
            Dest::Flag(flag) => write!(f, "Flag[{:?}]", flag),
        }
    }
}

impl<A: Arch> Display for Source<A> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Source::Imm(index) => write!(f, "v{}", index),
            Source::Dest(d) => write!(f, "{}", d),
            Source::Const { value, .. } => write!(f, "0x{}", value),
        }
    }
}

impl<A: Arch> From<Dest<A>> for Source<A> {
    fn from(d: Dest<A>) -> Source<A> {
        Source::Dest(d)
    }
}

impl<A: Arch> TryFrom<Source<A>> for Dest<A> {
    type Error = ();

    fn try_from(s: Source<A>) -> Result<Dest<A>, ()> {
        match s {
            Source::Dest(d) => Ok(d),
            _ => Err(()),
        }
    }
}

impl<A: Arch> From<Location<A>> for Dest<A> {
    fn from(location: Location<A>) -> Dest<A> {
        match location {
            Location::Reg(reg) => Dest::Reg(
                reg,
                Size::qword(),
            ),
            Location::Memory(index) => Dest::Mem(
                index,
                Size::qword(),
            ),
            Location::Flags => Dest::Flags,
            Location::Flag(f) => Dest::Flag(f),
        }
    }
}


impl<A: Arch> From<Dest<A>> for Location<A> {
    fn from(dest: Dest<A>) -> Location<A> {

        match dest {
            Dest::Reg(reg, _) => Location::Reg(reg),
            Dest::Mem(index, _) => Location::Memory(index),
            Dest::Flags => Location::Flags,
            Dest::Flag(f) => Location::Flag(f),
        }
    }
}

impl<A: Arch> From<&Source<A>> for Option<Location<A>> {
    fn from(v: &Source<A>) -> Self {
        Location::try_from(v).ok()
    }
}

pub trait IntoDestWithSize<A: Arch> {
    fn into_dest_with_size(self, size: Size) -> Dest<A>;
}

pub trait IntoSourceWithSize<A: Arch> {
    fn into_source_with_size(self, size: Size) -> Source<A>;
}

impl<A: Arch> IntoDestWithSize<A> for Location<A> {
    fn into_dest_with_size(self, size: Size) -> Dest<A> {
        match self {
            Location::Reg(reg) => Dest::Reg(
                reg,
                size,
            ),
            Location::Memory(index) => Dest::Mem(
                index,
                size,
            ),
            Location::Flags => Dest::Flags,
            Location::Flag(f) => Dest::Flag(f),
        }
    }
}

impl<A: Arch> IntoSourceWithSize<A> for Location<A> {
    fn into_source_with_size(self, size: Size) -> Source<A> {
        Source::Dest(self.into_dest_with_size(size))
    }
}

impl<A: Arch> From<&Dest<A>> for Location<A> {
    fn from(dest: &Dest<A>) -> Self {
        match dest {
            Dest::Reg(reg, _) => Location::Reg(reg.clone()),
            Dest::Mem(index, _) => Location::Memory(*index),
            Dest::Flags => Location::Flags,
            Dest::Flag(flag) => Location::Flag(flag.clone()),
        }
    }
}

impl<A: Arch> TryFrom<&Source<A>> for Location<A> {
    type Error = ();

    fn try_from(source: &Source<A>) -> Result<Self, Self::Error> {
        match source {
            Source::Dest(d) => Ok(d.into()),
            Source::Imm(_) | Source::Const { .. } => Err(()),
        }
    }
}

#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Inputs<A: Arch> {
    inputs: Vec<Source<A>>,
}

impl<A: Arch> Inputs<A> {
    pub fn unsorted(inputs: Vec<Source<A>>) -> Self {
        Inputs { inputs }
    }
    
    pub fn sorted(mut inputs: Vec<Source<A>>) -> Self {
        inputs.sort();
        Self::unsorted(inputs)
    }

    pub fn get(&self, loc: &Location<A>) -> Option<&Source<A>> {
        self.inputs.iter().filter(|i| i == &loc).next()
    }

    pub fn iter(&self) -> impl Iterator<Item = &Source<A>> {
        self.inputs.iter()
    }

    pub fn iter_mut(&mut self) -> impl Iterator<Item = &mut Source<A>> {
        self.inputs.iter_mut()
    }

    pub fn retain(&mut self, f: impl FnMut(&Source<A>) -> bool) {
        self.inputs.retain(f);
    }

    pub fn len(&self) -> usize {
        self.inputs.len()
    }

    pub fn contains(&self, item: &Source<A>) -> bool {
        self.inputs.contains(item)
    }

    pub fn remove(&mut self, item: &Source<A>) {
        self.inputs.retain(|input| input != item);
    }

    pub fn push(&mut self, item: Source<A>) {
        self.inputs.push(item)
    }
}

impl<A: Arch> Index<usize> for Inputs<A> {
    type Output = Source<A>;

    fn index(&self, index: usize) -> &Source<A> {
        &self.inputs[index]
    }
}

impl<A: Arch> Debug for Inputs<A> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.inputs.fmt(f)
    }
}

// impl<A: Arch> FromIterator<Source<A>> for Inputs<A> {
//     fn from_iter<T: IntoIterator<Item = Source<A>>>(iter: T) -> Self {
//         iter.into_iter().collect::<Vec<Source<A>>>().into()
//     }
// }

impl<A: Arch> Display for Inputs<A> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        for (index, input) in self.inputs.iter().enumerate() {
            if index != 0 {
                write!(f, ", ")?;
            }

            write!(f, "{}", input)?;
        }
        
        Ok(())
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum FlowInputLocation {
    InputForOutput {
        output_index: usize,
        input_index: usize,
    },
    MemoryAddress {
        memory_index: usize,
        input_index: usize,
    },
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum FlowOutputLocation {
    Output(usize),
    MemoryAccess(usize),
}

impl FlowOutputLocation {
    pub fn input(&self, input_index: usize) -> FlowInputLocation {
        match *self {
            FlowOutputLocation::Output(output_index) => FlowInputLocation::InputForOutput {
                output_index,
                input_index,
            },
            FlowOutputLocation::MemoryAccess(memory_index) => FlowInputLocation::MemoryAddress {
                memory_index,
                input_index,
            }
        }
    }
}
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum FlowValueLocation {
    Output(usize),
    InputForOutput {
        output_index: usize,
        input_index: usize,
    },
    MemoryAddress {
        memory_index: usize,
        input_index: usize,
    },
}

impl From<FlowInputLocation> for FlowValueLocation {
    fn from(location: FlowInputLocation) -> Self {
        match location {
            FlowInputLocation::InputForOutput { output_index, input_index } => FlowValueLocation::InputForOutput { output_index, input_index },
            FlowInputLocation::MemoryAddress { memory_index, input_index } => FlowValueLocation::MemoryAddress { memory_index, input_index },
        }
    }
}

pub trait GetDest<A: Arch>: Sized + Clone {
    fn get_dest<T>(&self, dest: &Dest<A>, f: impl FnOnce(&Value<'_>) -> T) -> T;

    fn with_dest(&self, dest: &Dest<A>, v: &Value<'_>) -> Self {
        let mut result = self.clone();
        result.set_dest(dest, v);
        result
    }

    fn set_dest(&mut self, dest: &Dest<A>, v: &Value<'_>);
}

impl<A: Arch> GetDest<A> for SystemState<A> {
    fn get_dest<T>(&self, dest: &Dest<A>, f: impl FnOnce(&Value<'_>) -> T) -> T {
        let loc = Location::from(dest);
        let value = self.location(&loc);
        let size = dest.size();

        let new_bytes;
        let sliced = if let Some(size) = size {
            let w = (size.end_byte - size.start_byte + 1) * 8;
            match value {
                Value::Num(n) => Value::Num((n >> (size.start_byte * 8)) & if w == 64 {
                    0xffffffff_ffffffff
                } else {
                    (1 << w) - 1
                }),
                Value::Bytes(b) => {
                    new_bytes = b.iter().copied().skip(size.start_byte).take(size.end_byte - size.start_byte + 1).collect::<Vec<_>>();
                    Value::Bytes(&new_bytes)
                }
                Value::FlagBitmap(f) => Value::FlagBitmap(f),
            }
        } else {
            value
        };
        
        f(&sliced)
    }

    fn set_dest(&mut self, dest: &Dest<A>, new_value: &Value<'_>) {
        let loc = Location::from(dest);
        let new_bytes;
        let size = dest.size();
        let current_value = self.location(&loc);
        let sliced = if let Some(size) = size {
            match (current_value, new_value) {
                (Value::Num(current), Value::Num(new)) => {
                    let w = (size.end_byte - size.start_byte + 1) * 8;
                    let mask = if w == 64 {
                        0xffffffff_ffffffff
                    } else {
                        (1 << w) - 1
                    } << (size.start_byte * 8);
                    Value::Num((current & !mask) | ((new << (size.start_byte * 8)) & mask))
                },
                (Value::Bytes(current), Value::Bytes(new)) => {
                    new_bytes = current.iter().copied().take(size.start_byte)
                        .chain(new.iter().copied().take(size.end_byte - size.start_byte + 1))
                        .chain(current.iter().copied().skip(size.end_byte + 1))
                        .collect::<Vec<_>>();

                    Value::Bytes(&new_bytes)
                }
                (_, Value::FlagBitmap(f)) => Value::FlagBitmap(*f),
                (_, new) => new.clone(),
            }
        } else {
            new_value.clone()
        };

        self.set_location(&loc, sliced)
    }
}

#[allow(unused)]
#[cfg(test)]
mod tests {
    use super::Size;
    use crate::{Dest, arch::{MemoryState, State, SystemState, Value}, fake::*, GetDest};

    #[test]
    pub fn size_contains() {
        assert!(Size::new(0, 7).contains(&Size::new(0, 5)));
        assert!(Size::new(0, 7).contains(&Size::new(0, 7)));
        assert!(Size::new(0, 7).contains(&Size::new(0, 6)));
        assert!(!Size::new(0, 7).contains(&Size::new(0, 8)));
        assert!(Size::new(0, 7).contains(&Size::new(1, 7)));
        assert!(!Size::new(1, 7).contains(&Size::new(0, 7)));
    }

    #[test]
    pub fn set_dest_flag() {
        let state = FakeState::create(|_| 0, |_| true);
        let mut s = SystemState::<FakeArch>::new(state, MemoryState::default());
        assert!(s.get_dest(&Dest::Flag(FakeFlag::F1), |v| match v {
            Value::Num(n) => *n == 1,
            _ => panic!(),
        }));

        s.set_dest(&Dest::Flag(FakeFlag::F1), &Value::Num(0));

        assert!(s.get_dest(&Dest::Flag(FakeFlag::F0), |v| match v {
            Value::Num(n) => *n == 1,
            _ => panic!(),
        }));

        assert!(s.get_dest(&Dest::Flag(FakeFlag::F1), |v| match v {
            Value::Num(n) => *n == 0,
            _ => panic!(),
        }));
    }

    #[test]
    pub fn set_dest_byte() {
        let state = FakeState::create(|_| 0, |_| true);
        let mut s = SystemState::<FakeArch>::new(state, MemoryState::default());
        assert!(s.get_dest(&Dest::Reg(FakeReg::R1, Size::new(1, 1)), |v| match v {
            Value::Num(n) => *n == 0,
            _ => panic!(),
        }));

        s.set_dest(&Dest::Reg(FakeReg::R1, Size::new(1, 1)), &Value::Num(0x25));

        assert!(s.get_dest(&Dest::Reg(FakeReg::R0, Size::new(1, 1)), |v| match v {
            Value::Num(n) => *n == 0,
            _ => panic!(),
        }));

        assert!(s.get_dest(&Dest::Reg(FakeReg::R1, Size::new(1, 1)), |v| match v {
            Value::Num(n) => *n == 0x25,
            _ => panic!(),
        }));
    }
}