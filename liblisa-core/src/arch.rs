use std::{fmt::{Debug, Display}, hash::Hash, cmp::Ordering, marker::PhantomData};
use std::str::FromStr;
use hex::FromHexError;
use itertools::Itertools;
use crate::Location;
use serde::{Deserialize, Deserializer, Serialize, Serializer, de::{DeserializeOwned, MapAccess, Visitor}};

#[derive(Copy, Clone, Hash)]
pub struct Instruction {
    data: [u8; 15],
    len: u8,
}

impl From<&str> for Instruction {
    fn from(s: &str) -> Self {
        Self::from_str(s).unwrap()
    }
}

impl Serialize for Instruction {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let s = self.into_string();
        serializer.serialize_str(&s)
    }
}

impl FromStr for Instruction {
    type Err = FromHexError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.chars().filter(|c| !c.is_whitespace() && *c != ',').collect::<String>();
        let mut data = [0u8; 15];
        let len = s.len() / 2;
        hex::decode_to_slice(s, &mut data[..len])?;

        Ok(Instruction {
            data,
            len: len as u8,
        })
    }
}

#[derive(Deserialize)]
pub struct OldInstruction {
    data: [u8; 31],
    len: u8,
}

impl<'de> Deserialize<'de> for Instruction {
    fn deserialize<D>(deserializer: D) -> Result<Instruction, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct InstructionVisitor;

        impl<'de> Visitor<'de> for InstructionVisitor {
            type Value = Instruction;
        
            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("an instruction string")
            }
        
            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Ok(Instruction::from(value))
            }

            fn visit_map<M>(self, map: M) -> Result<Instruction, M::Error>
            where
                M: MapAccess<'de>,
            {
                let old: OldInstruction = Deserialize::deserialize(serde::de::value::MapAccessDeserializer::new(map))?;
                Ok(Instruction::new(&old.data[..old.len as usize]))
            }
        }

        deserializer.deserialize_any(InstructionVisitor) 
    }
}

impl Instruction {
    pub fn new(data: &[u8]) -> Instruction {
        assert!(data.len() <= 15);
        let len = data.len() as u8;
        let mut slice = [0u8; 15];
        slice[0..data.len()].copy_from_slice(data);

        Instruction { 
            data: slice, 
            len,
        }
    }

    pub fn into_string(&self) -> String {
        hex::encode_upper(self.bytes())
    }
}

impl PartialEq for Instruction {
    fn eq(&self, other: &Self) -> bool {
        self.as_instr() == other.as_instr()
    }
}

impl Eq for Instruction {}

impl PartialOrd for Instruction {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        PartialOrd::partial_cmp(&self.as_instr(), &other.as_instr())
    }
}

impl Ord for Instruction {
    fn cmp(&self, other: &Self) -> Ordering {
        Ord::cmp(&self.as_instr(), &other.as_instr())
    }
}

#[derive(Copy, Clone)]
pub struct Instr<'a> {
    data: &'a [u8],
}

impl PartialEq for Instr<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.bytes() == other.bytes()
    }
}

impl Eq for Instr<'_> {}

impl Hash for Instr<'_> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.bytes().hash(state)
    }
}

impl<'a> From<&'a [u8]> for Instr<'a> {
    fn from(data: &'a [u8]) -> Self {
        Self::new(data)
    }
}

impl<'a> From<&'a Instruction> for Instr<'a> {
    fn from(instr: &'a Instruction) -> Self {
        Self::new(&instr.data[0..instr.len as usize])
    }
}

impl<'a> From<Instr<'a>> for Instruction {
    fn from(instr: Instr<'a>) -> Self {
        Instruction::new(instr.bytes())
    }
}

impl<'a> From<&Instr<'a>> for Instruction {
    fn from(instr: &Instr<'a>) -> Self {
        Instruction::new(instr.bytes())
    }
}

impl<'a> PartialOrd<Instr<'a>> for Instr<'a> {
    fn partial_cmp(&self, other: &Instr<'a>) -> Option<Ordering> {
        Some(Ord::cmp(self, other))
    }
}

impl<'a> Ord for Instr<'a> {
    fn cmp(&self, other: &Instr<'a>) -> Ordering {
        for (a, b) in self.bytes().iter().zip(other.bytes().iter()) {
            match a.cmp(b) {
                Ordering::Equal => {},
                other => return other,
            }
        }

        if self.bytes().len() < other.bytes().len() {
            Ordering::Less
        } else if self.bytes().len() > other.bytes().len() {
            Ordering::Greater
        } else {
            Ordering::Equal
        }
    }
}

pub trait InstructionInfo {
    fn bytes(&self) -> &[u8];

    fn byte_len(&self) -> usize {
        self.bytes().len()
    }

    fn bit_len(&self) -> usize {
        self.byte_len() * 8
    }

    fn with_flipped_bit(&self, index: usize) -> Instruction {
        let mut instr = Instruction::new(self.bytes());
        instr.data[instr.len as usize - 1 - index / 8] ^= 1 << (index % 8);

        instr
    }

    fn with_bit(&self, index: usize, bit: u8) -> Instruction {
        assert!(bit == 0 || bit == 1);
        let mut instr = Instruction::new(self.bytes());
        let i = instr.len as usize - 1 - index / 8;
        instr.data[i] = (instr.data[i] & !(1 << (index % 8))) | bit << (index % 8);

        instr
    }

    fn bit_at(&self, index: usize) -> u8 {
        (self.bytes()[self.byte_len() as usize - 1 - index / 8] >> (index % 8)) & 1
    }

    fn as_instr<'a>(&'a self) -> Instr<'a> {
        Instr {
            data: &self.bytes(),
        }
    }

    fn as_instruction(&self) -> Instruction {
        Instruction::new(self.bytes())
    }
}

impl<'a> InstructionInfo for Instr<'a> {
    fn bytes(&self) -> &[u8] {
        self.data
    }
}

impl InstructionInfo for Instruction {
    fn bytes(&self) -> &[u8] {
        &self.data[0..self.len as usize]
    }
}

impl<'a> Instr<'a> {
    pub const fn new(data: &'a [u8]) -> Instr<'a> {
        Instr { data }
    }

    pub fn slice(&self, start: usize, end: usize) -> Instr<'a> {
        Instr::new(&self.data[start..end])
    }

    pub fn bytes(&self) -> &'a [u8] {
        self.data
    }
}

impl<'a> Debug for Instr<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for b in self.data.iter() {
            write!(f, " {:08b}", b)?;
        }

        Ok(())
    }
}

impl Debug for Instruction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for b in self.data[0..self.len as usize].iter() {
            write!(f, " {:08b}", b)?;
        }

        Ok(())
    }
}


pub trait Arch : Clone + Debug + PartialEq + Eq + Hash + Default + PartialOrd + Ord
    where Self: Sized {
    type CpuState: State<Self> + Clone + PartialEq + Eq + Send + Sync;
    type Reg: Register + Clone + Debug + Display + PartialEq + Eq + Hash + PartialOrd + Ord + Serialize + DeserializeOwned + Send + Sync;
    type Flag: Flag + Clone + Debug + Display + PartialEq + Eq + Hash + PartialOrd + Ord + Serialize + DeserializeOwned + Send + Sync;

    fn is_instruction_included(b: &[u8]) -> bool;
}
pub trait State<A: Arch> {
    fn reg(&self, reg: &A::Reg) -> u64;

    fn flag(&self, flag: &A::Flag) -> bool;

    fn serialize_flags(&self) -> u64;

    fn create<R: FnMut(&A::Reg) -> u64, F: FnMut(&A::Flag) -> bool>(regval: R, flagval: F) -> Self;

    fn with_reg(&self, reg: &A::Reg, value: u64) -> Self
        where Self: Sized {
        Self::create(|r| if r == reg { 
            value
        } else {
            self.reg(r)
        }, |f| self.flag(f))
    }

    fn with_flag(&self, flag: &A::Flag, value: bool) -> Self
        where Self: Sized {
        Self::create(|r| self.reg(r), |f| if f == flag { 
            value 
        } else { 
            self.flag(f) 
        })
    }

    fn set_reg(&mut self, reg: &A::Reg, value: u64);
    fn set_flag(&mut self, flag: &A::Flag, value: bool);
}

pub trait Register 
    where Self : Sized + PartialOrd + Ord {
    type Iter: Iterator<Item = Self>;
    fn iter() -> Self::Iter;

    fn pc() -> Self;
    fn zero() -> Self;

    fn is_pc(&self) -> bool {
        self == &Self::pc()
    }

    fn is_zero(&self) -> bool {
        self == &Self::zero()
    }

    const MAX_NUM: usize;
    fn as_num(&self) -> usize;
}

pub trait Flag 
    where Self : Sized + PartialOrd + Ord {
    type Iter: Iterator<Item = Self>;
    fn iter() -> Self::Iter;
}

pub struct StateView<'a, A: Arch, S: State<A>> {
    state: &'a S,
    _phantom: PhantomData<A>,
}

impl<'a, A: Arch, S: State<A>> StateView<'a, A, S> {
    pub fn new(state: &'a S) -> StateView<'a, A, S> {
        StateView { 
            state, 
            _phantom: PhantomData::default() 
        }
    }
}

impl<'a, A: Arch, S: State<A>> Display for StateView<'a, A, S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { 
        for reg in A::Reg::iter() {
            write!(f, "\n{} = 0x{:X}", reg, self.state.reg(&reg))?;
        }

        write!(f, "\n{}", A::Flag::iter().map(|f| format!("{}={}", f, if self.state.flag(&f) { 1 } else { 0 })).join(" "))?;

        Ok(())
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct SystemState<A: Arch> {
    pub cpu: A::CpuState,
    pub memory: MemoryState,
}

impl<A: Arch> Debug for SystemState<A> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "{}", StateView::new(&self.cpu))?;
        writeln!(f, "{:X?}", self.memory)?;

        Ok(())
    }
}

impl<A: Arch> SystemState<A> {
    pub fn with_reg(&self, reg: &A::Reg, value: u64) -> Self {
        SystemState { 
            cpu: self.cpu.with_reg(reg, value),
            memory: self.memory.clone(),
        }
    }

    pub fn with_flag(&self, flag: &A::Flag, value: bool) -> Self {
        SystemState { 
            cpu: self.cpu.with_flag(flag, value),
            memory: self.memory.clone(),
        }
    }

    pub fn with_location(&self, loc: &Location<A>, value: Value) -> Self {
        let mut result = self.clone();
        result.set_location(loc, value);
        result
    }

    pub fn set_reg(&mut self, reg: &A::Reg, value: u64) {
        self.cpu.set_reg(reg, value)
    }

    pub fn set_flag(&mut self, flag: &A::Flag, value: bool) {
        self.cpu.set_flag(flag, value)
    }

    pub fn set_location(&mut self, loc: &Location<A>, value: Value) {
        match (loc, value) {
            (Location::Reg(reg), Value::Num(v)) => self.set_reg(reg, v),
            (Location::Memory(index), Value::Bytes(v)) => {
                // Prevent Vec reallocation by re-using the existing Vec, and copying the slice into it.
                let target = &mut self.memory.data[*index].2;
                target.clear();
                target.extend_from_slice(v);
            },
            (Location::Flag(flag), Value::Num(n)) => self.set_flag(flag, n != 0),
            (loc, value) => panic!("Unsupported (location, value) pair: {:?} and {:?}", loc, value),
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
pub enum Value<'a> {
    Num(u64),
    Bytes(&'a [u8]),
    FlagBitmap(u64),
}

impl<'a> Debug for Value<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for b in self.to_le_bytes().iter().rev() {
            write!(f, "{:02X}", b)?;
        }

        Ok(())
    }
}

impl<'a> Value<'a> {
    pub fn to_le_bytes(&self) -> Vec<u8> {
        match self {
            Value::Num(n) => n.to_le_bytes().to_vec(),
            Value::Bytes(v) => v.to_vec(),
            Value::FlagBitmap(n) => n.to_le_bytes().to_vec(),
        }
    }

    pub fn select_byte(&self, index: usize) -> u8 {
        match self {
            Value::Num(n) => (n >> (index * 8)) as u8,
            Value::Bytes(v) => v[index],
            Value::FlagBitmap(_) => todo!("select_byte not implemented for flags"),
        }
    }

    pub fn xor<T>(&self, b: &Value, mut f: impl FnMut(&Value) -> T) -> T {
        match (self, b) {
            (Value::Num(a), Value::Num(b)) => f(&Value::Num(a ^ b)),
            (Value::Bytes(a), Value::Bytes(b)) => f(&Value::Bytes(&a.iter().copied().zip(b.iter().copied()).map(|(a, b)| a ^ b).collect::<Vec<_>>())),
            (Value::FlagBitmap(a), Value::FlagBitmap(b)) => f(&Value::FlagBitmap(a ^ b)),
            _ => panic!("Comparing mixed values"),
        }
    }

    pub fn or<T>(&self, b: &Value, mut f: impl FnMut(&Value) -> T) -> T {
        match (self, b) {
            (Value::Num(a), Value::Num(b)) => f(&Value::Num(a | b)),
            (Value::Bytes(a), Value::Bytes(b)) => f(&Value::Bytes(&a.iter().copied().zip(b.iter().copied()).map(|(a, b)| a | b).collect::<Vec<_>>())),
            (Value::FlagBitmap(a), Value::FlagBitmap(b)) => f(&Value::FlagBitmap(a | b)),
            _ => panic!("Comparing mixed values"),
        }
    }

    pub fn and<T>(&self, b: &Value, mut f: impl FnMut(&Value) -> T) -> T {
        match (self, b) {
            (Value::Num(a), Value::Num(b)) => f(&Value::Num(a & b)),
            (Value::Bytes(a), Value::Bytes(b)) => f(&Value::Bytes(&a.iter().copied().zip(b.iter().copied()).map(|(a, b)| a & b).collect::<Vec<_>>())),
            (Value::FlagBitmap(a), Value::FlagBitmap(b)) => f(&Value::FlagBitmap(a & b)),
            _ => panic!("Comparing mixed values"),
        }
    }

    pub fn expand_to_bytes<T>(&self, mut f: impl FnMut(&Value) -> T) -> T {
        let mut byte_container: Vec<u8>;
        match self {
            Value::Num(n) => f(&Value::Num({
                let mut bytes = n.to_le_bytes();
                for b in bytes.iter_mut() {
                    if *b != 0 {
                        *b = 0xff;
                    }
                }

                u64::from_le_bytes(bytes)
            })),
            Value::Bytes(b) => f(&Value::Bytes({
                byte_container = b.to_vec();
                for b in byte_container.iter_mut() {
                    if *b != 0 {
                        *b = 0xff;
                    }
                }

                &byte_container
            })),
            Value::FlagBitmap(n) => f(&Value::FlagBitmap({
                let mut bytes = n.to_le_bytes();
                for b in bytes.iter_mut() {
                    if *b != 0 {
                        *b = 0xff;
                    }
                }

                u64::from_le_bytes(bytes)
            })),
        }
    }

    pub fn equal_with_mixed_bytes(&self, bytes: &[bool], new_result: &Value, new_input: &Value) -> bool {
        match (self, new_result, new_input) {
            (Value::Num(old), Value::Num(new), Value::Num(new_in)) => {
                for (index, b) in bytes.iter().enumerate() {
                    let f = index * 8;
                    let old = (old >> f) & 0xff;
                    let new = (new >> f) & 0xff;
                    let new_in = (new_in >> f) & 0xff;

                    if old != new {
                        if *b {
                            return false;
                        } else {
                            if new != new_in {
                                return false;
                            }
                        }
                    }
                }

                true
            },
            (Value::Bytes(old), Value::Bytes(new), Value::Bytes(new_in)) => {
                if old.len() != new.len() {
                    return false;
                }

                for i in 0..old.len() {
                    if old[i] != new[i] {
                        if bytes[i] {
                            return false;
                        } else {
                            if new[i] != new_in[i] {
                                return false;
                            }
                        }
                    }
                }

                true
            },
            (Value::FlagBitmap(a), Value::FlagBitmap(b), Value::FlagBitmap(_)) => a == b,
            _ => false,
        }
    }
}

impl<A: Arch> SystemState<A> {
    pub fn new(cpu: A::CpuState, memory: MemoryState) -> SystemState<A> {
        SystemState { cpu, memory }
    }

    pub fn location(&self, loc: &Location<A>) -> Value<'_> {
        match loc {
            Location::Reg(reg) => Value::Num(self.cpu.reg(reg)),
            Location::Memory(n) => Value::Bytes(&self.memory.data.get(*n).unwrap_or_else(|| panic!("Memory #{} out of bounds on {:X?}", n, self)).2),
            Location::Flags => Value::FlagBitmap(self.cpu.serialize_flags()),
            Location::Flag(flag) => Value::Num(if self.cpu.flag(flag) { 1 } else { 0 }),
        }
    }

    pub fn get_location(&self, loc: &Location<A>) -> Option<Value<'_>> {
        match loc {
            Location::Reg(reg) => Some(Value::Num(self.cpu.reg(reg))),
            Location::Memory(n) => self.memory.data.get(*n).as_ref().map(|v| Value::Bytes(&v.2)),
            Location::Flags => Some(Value::FlagBitmap(self.cpu.serialize_flags())),
            Location::Flag(flag) => Some(Value::Num(if self.cpu.flag(flag) { 1 } else { 0 })),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemoryState {
    pub data: Vec<(u64, Permissions, Vec<u8>)>,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Permissions {
    Read,
    ReadWrite,
    Execute,
}

impl MemoryState {
    pub fn new<I: Iterator<Item = (u64, Permissions, Vec<u8>)>>(items: I) -> MemoryState {
        let data = items.collect::<Vec<_>>();
        // TODO: Ranges cannot overlap
        MemoryState {
            data,
        }
    }

    pub fn push(&mut self, offset: u64, permissions: Permissions, data: Vec<u8>) {
        for (addr, item_perms, item_data) in self.data.iter_mut() {
            if *addr == offset {
                *item_perms = permissions;
                *item_data = data;
                return;
            }
        }

        self.data.push((offset, permissions, data));
        // self.data.sort_by_key(|item| (item.0, item.2.len()));
    }

    pub fn iter(&self) -> impl Iterator<Item = &(u64, Permissions, Vec<u8>)> {
        self.data.iter()
    }

    pub fn get(&self, index: usize) -> Option<&(u64, Permissions, Vec<u8>)> {
        self.data.get(index)
    }
}

impl Default for MemoryState {
    fn default() -> Self {
        MemoryState {
            data: Vec::new(),
        }
    }
}

#[cfg(test)]
#[allow(unused)]
mod tests {
    use crate::arch::Instruction;
    use crate::arch::Instr;
    use super::Value;

    pub fn test_instr_ordering() {
        assert!(Instr::new(&[ 0x47, 0xF0 ]) < Instr::new(&[ 0x48, 0x89, 0xBB, 0x00, 0x00, 0x00, 0x00 ]));
        assert!(Instr::new(&[ 0x48 ]) < Instr::new(&[ 0x48, 0x89, 0xBB, 0x00, 0x00, 0x00, 0x00 ]));
    }

    pub fn test_instruction_ordering() {
        assert!(Instruction::new(&[ 0x47, 0xF0 ]) < Instruction::new(&[ 0x48, 0x89, 0xBB, 0x00, 0x00, 0x00, 0x00 ]));
        assert!(Instruction::new(&[ 0x48 ]) < Instruction::new(&[ 0x48, 0x89, 0xBB, 0x00, 0x00, 0x00, 0x00 ]));
    }

    #[test]
    pub fn test_equal_with_mixed_bytes() {
        assert!(
            Value::Num(0x00000000FFFFCD94).equal_with_mixed_bytes(
                &[false, true, false, false, false, false, false, false], 
                &Value::Num(0x00000000FFFFCD42),
                &Value::Num(0x000000000003CD42)
            )
        );
    }

    #[test]
    pub fn test_serialize_instr() {
        println!("{}", serde_json::to_string(&Instruction::new(&[ 0xff, 0x13, 0x22 ])).unwrap());

        assert_eq!(
            serde_json::to_string(&Instruction::new(&[ 0xff, 0x13, 0x22 ])).unwrap(),
            r#""FF1322""#
        );

        assert_eq!(
            serde_json::to_string(&Instruction::new(&[ 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC ])).unwrap(),
            r#""123456789ABC""#
        );
    }

    #[test]
    pub fn test_deserialize_instr_hex() {
        assert_eq!(
            serde_json::from_str::<Instruction>(r#""1F""#).unwrap(),
            Instruction::new(&[ 0x1F ]),
        );

        assert_eq!(
            serde_json::from_str::<Instruction>(r#""FF1322""#).unwrap(),
            Instruction::new(&[ 0xff, 0x13, 0x22 ]),
        );

        assert_eq!(
            serde_json::from_str::<Instruction>(r#""FA1322""#).unwrap(),
            Instruction::new(&[ 0xfA, 0x13, 0x22 ]),
        );
    }

    #[test]
    pub fn test_deserialize_instr_old() {
        assert_eq!(
            serde_json::from_str::<Instruction>(r#"{"data":[72,200,141,113,150,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"len":5}"#).unwrap(),
            Instruction::new(&[ 72,200,141,113,150 ]),
        );
    }
}