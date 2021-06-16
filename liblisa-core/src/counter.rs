use std::{collections::VecDeque, fmt::Debug};
use itertools::Itertools;
use log::info;
use serde::{Serialize, Deserialize};
use crate::arch::{Instr, Instruction, InstructionInfo};

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ByteFilter {
    mask: u8,
    value: u8,
}

impl Debug for ByteFilter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for i in (0..8).rev() {
            if (self.mask >> i) & 1 == 1 {
                write!(f, "{}", (self.value >> i) & 1)?;
            } else {
                write!(f, "_")?;
            }
        }

        Ok(())
    }
}

impl ByteFilter {
    pub fn new(mask: u8, value: u8) -> Self {
        ByteFilter { mask, value }
    }

    pub fn matches(&self, value: u8) -> bool {
        (value & self.mask) == self.value 
    }

    fn max_matching_val(&self) -> u8 {
        let leading_zeros = self.mask.leading_zeros();
        let prefix = (((1u32 << leading_zeros) - 1) as u8).overflowing_shl(8 - leading_zeros).0;
        self.value | prefix | !self.mask
    }

    fn min_matching_val(&self) -> u8 {
        self.value & self.mask
    }

    pub fn min_greater_than(&self, value: u8) -> bool {
        self.min_matching_val() > value
    }

    pub fn max_smaller_than(&self, value: u8) -> bool {
        self.max_matching_val() < value
    }

    pub fn at_max(&self, value: u8) -> bool {
        self.max_matching_val() == value
    }

    pub fn at_min(&self, value: u8) -> bool {
        self.min_matching_val() == value
    }

    pub fn matches_anything(&self) -> bool {
        self.mask == 0
    }

    /// All instructions matched by other are also matched by self
    pub fn covers(&self, other: &ByteFilter) -> bool {
        // Example: _ _ _ _ covers _ _ 0 1
        // Example: _ _ _ 0 covers 0 1 1 0
        self.value & self.mask == other.value & self.mask && other.mask & self.mask == self.mask
    }

    pub fn can_intersect(&self, other: &ByteFilter) -> bool {
        // Example: _ _ 1 _ can intersect with _ _ _ 0 into _ _ 1 0
        // Example: _ _ 0 _ can intersect with _ 1 _ _ into _ 1 0 _
        // Example: _ _ 1 1 CANNOT intersect with _ _ _ 0
        let intersect_mask = self.mask & other.mask;
        intersect_mask & self.value == intersect_mask & other.value
    }

    pub fn can_merge(&self, other: &ByteFilter) -> bool {
        // 1__1 0__1
        // ____ ___0

        if self.value == other.value && self.mask == other.mask {
            // If the filters are equal there's nothing to merge
            return false;
        }

        // Own mask can be more restrictive, as long as other matches with one flipped bit in all cases we match as well.
        // We both match the exact same bits, but one bit is exactly the opposite
        // EXAMPLE: self = _ _ 1 0, other = _ _ 1 1. Merged = _ _ 1 _
        ((self.value ^ other.value) & other.mask).count_ones() == 1 
            && (other.mask & self.mask) == other.mask
    }

    pub fn merge(&mut self, other: &ByteFilter) {
        let filter = !((self.value ^ other.value) & other.mask);
        debug_assert_eq!(filter.count_ones(), 7, "merge() can only be called if can_merge returns true");

        self.mask &= filter;
        self.value &= filter;
    }

    pub fn intersect(&mut self, other: &ByteFilter) {
        debug_assert!(self.can_intersect(other) || other.can_intersect(self), "intersect() can only be called if can_intersect(a, b) or can_intersect(b, a) returns true");

        let new_mask = self.mask | other.mask;
        self.value |= other.value & other.mask & !self.mask;
        self.mask = new_mask;
    }

    pub fn num_wildcard_bits(&self) -> usize {
        self.mask.count_zeros() as usize
    }

    pub fn as_value(&self) -> Option<u8> {
        if self.mask == 0xff {
            Some(self.value)
        } else {
            None
        }
    }
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InstructionFilter {
    pub data: Vec<ByteFilter>,
}

impl Debug for InstructionFilter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for bf in self.data.iter() {
            write!(f, "{:?} ", bf)?;
        }

        Ok(())
    }
}

impl InstructionFilter {
    pub fn new(data: Vec<ByteFilter>) -> InstructionFilter {
        InstructionFilter { data }
    }

    pub fn parse(s: &str) -> InstructionFilter {
        let mut bfs = Vec::new();
        for part in s.split(' ') {
            let cs = part.chars().collect::<Vec<_>>();

            let mut bf = ByteFilter::new(0, 0);
            for i in (0..8).rev() {
                match cs[7 - i] {
                    '0' => bf.mask |= 1 << i,
                    '1' => {
                        bf.mask |= 1 << i;
                        bf.value |= 1 << i;
                    },
                    '_' => {},
                    _ => panic!(),
                }
            }

            bfs.push(bf);
        }

        let result = Self::new(bfs);
        println!("Parsed: {:?} (from {})", result, s);
        result
    }

    pub fn matches(&self, instr: &Instr<'_>) -> bool {
        for (i, bf) in self.data.iter().enumerate() {
            if let Some(idata) = instr.bytes().get(i) {
                if !bf.matches(*idata) {
                    return false;
                }
            } else if !bf.matches_anything() { 
                return false;
            }
        }

        true
    }

    pub fn matches_smaller_instr_partially(&self, instr: &Instr<'_>) -> bool {
        if instr.byte_len() > self.len() {
            false
        } else {
            self.data.iter().zip(instr.bytes()).all(|(bf, idata)| bf.matches(*idata))
        }
    }

    pub fn len(&self) -> usize {
        self.data.len()
    }

    pub fn max_smaller_than(&self, instr: &Instr<'_>) -> bool {
        for (i, bf) in self.data.iter().enumerate() {
            if let Some(idata) = instr.bytes().get(i) {
                if bf.max_smaller_than(*idata) {
                    return true;
                } else if !bf.at_max(*idata) {
                    return false;
                }
            } else { 
                return false;
            }
        }

        false
    }

    pub fn min_greater_than(&self, instr: &Instr<'_>) -> bool {
        for (i, bf) in self.data.iter().enumerate() {
            if let Some(idata) = instr.bytes().get(i) {
                if bf.min_greater_than(*idata) {
                    return true;
                } else if !bf.at_min(*idata) {
                    return false;
                }
            } else { 
                return false;
            }
        }

        false
    }

    pub fn covers(&self, other: &InstructionFilter) -> bool {
        self.data.len() <= other.data.len() && self.data.iter().zip(other.data.iter()).all(|(a, b)| a.covers(b))
    }

    pub fn try_merge(&self, other: &InstructionFilter) -> Option<InstructionFilter> {
        if self.data.len() != other.data.len() {
            return None;
        }

        // Basic merge
        let mut merge_index = None;
        for (index, (a, b)) in self.data.iter().zip(other.data.iter()).enumerate() {
            if a.can_merge(b) && self.data.iter().zip(other.data.iter())
                .skip(index + 1)
                .all(|(a, b)| b.covers(a)) {
                merge_index = Some(index);
            }
            
            if !b.covers(a) {
                break;
            }
        }

        if let Some(merge_index) = merge_index {
            let mut new = self.clone();
            new.data[merge_index].merge(&other.data[merge_index]);
            return Some(new);
        }

        // Merge by specializing `b` with a single byte from `a`
        let mut merge_index = None;
        for (index, (a, b)) in self.data.iter().zip(other.data.iter()).enumerate() {
            if a.can_merge(b) && self.data.iter().zip(other.data.iter())
                .skip(index + 1)
                .all(|(a, b)| a.covers(b)) {
                merge_index = Some(index);
            }
            
            if !a.covers(b) {
                break;
            }
        }

        if let Some(merge_index) = merge_index {
            let mut new = other.clone();
            new.data[merge_index] = self.data[merge_index].clone();
            new.data[merge_index].merge(&other.data[merge_index]);
            return Some(new);
        }


        // Merge by specializing everything
        let mut merge_index = None;
        for (index, (a, b)) in self.data.iter().zip(other.data.iter()).enumerate() {
            if a.can_merge(b) && self.data.iter().zip(other.data.iter())
                .skip(index + 1)
                .all(|(a, b)| a.can_intersect(b) || b.can_intersect(a)) {
                merge_index = Some(index);
            }
            
            if !a.can_intersect(b) && !b.can_intersect(a) {
                break;
            }
        }

        if let Some(merge_index) = merge_index {
            let mut new = other.clone();
            for (index, (item, other)) in new.data[..self.data.len()].iter_mut().zip(self.data.iter()).enumerate() {
                if index != merge_index {
                    item.intersect(other);
                }
            }

            new.data[merge_index] = self.data[merge_index].clone();
            new.data[merge_index].merge(&other.data[merge_index]);
            return Some(new);
        }

        None
    }

    pub fn smallest_matching_instruction(&self) -> Instruction {
        let data = self.data.iter().map(|bf| bf.value & bf.mask).collect::<Vec<_>>();
        Instruction::new(&data)
    }

    pub fn num_wildcard_bits(&self) -> usize {
        self.data.iter().map(|f| f.num_wildcard_bits()).sum()
    }
}

impl From<Instr<'_>> for InstructionFilter {
    fn from(instr: Instr<'_>) -> Self {
        InstructionFilter::new(instr.bytes()
            .iter()
            .copied()
            .map(|b| ByteFilter::new(0xff, b))
            .collect()
        )
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct InstructionCounter {
    data: [u8; 32],
    len: usize,
    filters: Vec<InstructionFilter>,
    end: Option<Instruction>,
    tunnel_pos: usize,
    #[serde(default)]
    num_tunneled: usize,
}

impl Debug for InstructionCounter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "InstructionCounter[{:X?}]: \n", &self.data[0..self.len])?;

        for (index, filter) in self.filters.iter().enumerate() {
            write!(f, "    filter #{:3}: {:?}", index, filter)?;

            let redundancies = self.filters.iter().enumerate().filter(|(i, f)| *i != index && filter.covers(f)).map(|(i, _)| i).collect::<Vec<_>>();

            if redundancies.len() > 0 {
                write!(f, "({} made redundant by this filter)", redundancies.iter().join(", "))?;
            }

            writeln!(f)?;
        }

        Ok(())
    }
}

impl InstructionCounter {
    pub fn new() -> InstructionCounter {
        InstructionCounter {
            data: [0u8; 32],
            len: 1,
            filters: Vec::new(),
            end: None,
            tunnel_pos: 0,
            num_tunneled: 0,
        }
    }

    pub fn clear_filters(&mut self) {
        self.filters.clear();
    }

    pub fn set_current(&mut self, instr: Instr<'_>) {
        self.data[0..instr.byte_len()].copy_from_slice(instr.bytes());
        self.len = instr.byte_len();
        self.tunnel_pos = instr.byte_len();
    }

    pub fn rebuild(self) -> InstructionCounter {
        let mut new = Self::range(self.current(), self.end);
        for filter in self.filters.into_iter() {
            new.filter(filter);
        }

        new
    }

    pub fn rebuild_inplace(&mut self) {
        let r = self.clone().rebuild();
        self.filters = r.filters;
    }

    pub fn num_filters(&self) -> usize {
        self.filters.len()
    }

    pub fn range(start: Instr<'_>, end: Option<Instruction>) -> InstructionCounter {
        let mut result = InstructionCounter {
            data: [0u8; 32],
            len: start.byte_len(),
            filters: Vec::new(),
            end,
            tunnel_pos: start.byte_len() - 1,
            num_tunneled: 0,
        };
        result.data[0..start.byte_len()].copy_from_slice(start.bytes());

        result
    }

    pub fn extend(&mut self, fast_tunnel: bool) -> bool {
        self.data[self.len] = 0;
        self.len += 1;

        if !fast_tunnel {
            self.tunnel_pos = self.len - 1;
            self.num_tunneled = 0;
        }

        self.apply_filters_to_current()
    }

    pub fn reduce(&mut self, fast_tunnel: bool) -> bool {
        self.len -= 1;
        if !fast_tunnel || self.tunnel_pos >= self.len {
            self.tunnel_pos = self.len - 1;
            self.num_tunneled = 0;
        }

        self.apply_filters_to_current()
    }

    fn next_single(&mut self) -> bool {
        loop {
            let i = self.tunnel_pos;
            if let Some(v) = self.data[i].checked_add(1) {
                self.data[i] = v;
                break;
            } else {
                self.data[i] = 0;
                if self.tunnel_pos <= 0 {
                    return false;
                } else {
                    self.tunnel_pos -= 1;
                }
            }
        }

        if let Some(end) = self.end {
            self.current() <= end.as_instr()
        } else {
            true
        }
    }

    fn filter_is_relevant(&self, filter: &InstructionFilter) -> bool {
        // Filter may not be smaller than the current instruction, and must be smaller than the end instruction
        !filter.max_smaller_than(&self.current()) && self.end.as_ref().map(|end| !filter.min_greater_than(&end.as_instr())).unwrap_or(true)
    }

    pub fn filter(&mut self, mut filter: InstructionFilter) {
        #[cfg(test)]
        println!("New filter: {:?}", filter);
        if !self.filter_is_relevant(&filter) {
            info!("Filter {:?} ignored, because it is not relevant for this instruction counter", filter);
        } else if let Some(index) = self.filters.iter().position(|f| f.covers(&filter) || f == &filter) {
            // The filter is not necessary, because we already have another filter that filters the same instructions.
            info!("Filter {:?} ignored, because it is redundant with {:?}", filter, self.filters[index]);
        } else {
            info!("Adding filter: {:?}", filter);
            // ! We don't need to add new filters here, since we most likely will end up doing that in apply_filters_to_current if need be.
            for f in self.filters.iter_mut() {
                if let Some(new) = f.try_merge(&filter) {
                    if new.covers(f) {
                        *f = new;
                    }
                }
            }

            for f in self.filters.iter() {
                if let Some(new) = filter.try_merge(f) {
                    if new.covers(&filter) {
                        filter = new;
                    }
                }
            }

            self.filters.retain(|f| !filter.covers(f));
            self.filters.push(filter);
        }
    }

    pub fn filter_nomerge(&mut self, filter: InstructionFilter) {
        if self.filter_is_relevant(&filter) {
            self.filters.push(filter);
        }
    }

    pub fn apply_filters_to_current(&mut self) -> bool {
        let mut seen = VecDeque::new();
        loop {
            // If all bytes in the instruction match, but the filter is longer, we can extend by a single byte.
            while {
                let current = self.current();
                self.filters.iter().any(|f| current.byte_len() < f.len() && f.matches_smaller_instr_partially(&current))
            } {
                self.extend(false);
            }

            // Inlined self.current() to make the borrow checker happy
            // This allows the compiler to understand that we're only taking a reference &self.data, and not &self entirely
            let current = self.data[0..self.len].into();

            if let Some(matching_filter_index) = self.filters.iter().enumerate().rev().find(|(_, filter)| 
                filter.matches(&current) && filter.data.iter().skip(self.len).all(|bf| bf.mask == 0)
            ).map(|(index, _)| index) {
                let tmp_f;
                let matching_filter = {
                    let mut new_filters = Vec::new();
                    for &index in seen.iter() {
                        if index != matching_filter_index {
                            let filters = &mut self.filters;
                            let (prev, current) = if index < matching_filter_index {
                                let (before, after) = filters.split_at_mut(index + 1);
                                (&mut before[before.len() - 1], &mut after[matching_filter_index - index - 1])
                            } else {
                                let (before, after) = filters.split_at_mut(index);
                                (&mut after[0], &mut before[matching_filter_index])
                            };

                            if let Some(new) = prev.try_merge(&current) {
                                if new.covers(prev) {
                                    *prev = new;
                                } else {
                                    new_filters.push(new);
                                }
                            }

                            if let Some(new) = current.try_merge(&prev) {
                                if new.covers(prev) {
                                    *prev = new;
                                } else {
                                    new_filters.push(new);
                                }
                            }
                        }
                    }

                    new_filters.retain(|new| self.filter_is_relevant(&new));

                    if new_filters.len() > 0 {
                        seen.clear();

                        tmp_f = self.filters[matching_filter_index].clone();

                        for new_filter in new_filters.iter().cloned() {
                            let mut is_relevant = true;
                            self.filters.retain(|f| if !new_filter.covers(f) {
                                if f.covers(&new_filter) {
                                    is_relevant = false;
                                }

                                true
                            } else {
                                false
                            });

                            if is_relevant {
                                self.filters.push(new_filter);
                            }
                        }

                        for new_filter in new_filters.into_iter() {
                            for (index, f) in self.filters.iter().enumerate() {
                                if f.covers(&new_filter) && !seen.contains(&index) {
                                    seen.push_back(index);
                                }
                            }
                        }

                        &tmp_f
                    } else {
                        seen.push_back(matching_filter_index);
                        if seen.len() >= 16 {
                            seen.pop_front();
                        }

                        &self.filters[matching_filter_index]
                    }
                };

                println!("Filtering: {:?}", matching_filter);
                // Limit our length to the length of the filter
                self.len = self.len.min(matching_filter.data.len());

                // We want to try and flip a bit such that the filter no longer matches. If we cannot find such a bit in the last byte
                // of the instruction, we will reduce the length of the instruction by one byte and try again.
                // The goal is to flip the lowest unmasked bit. If this bit is 0, we only need to flip it. 
                // If the bit is 1, we need to carry it to wherever it would end up.
                // We take this approach because naively doing next_single() until no filters match is prohibitively expensive.
                // This code will easily eat through a filtered 64-bit value, while the naive iteration would take ages.
                let mut will_not_match = false;
                'outer: for pos in (0..self.len).rev() {
                    let byte = &mut self.data[pos];
                    let bf = &matching_filter.data[pos];

                    for bit_index in 0..8 {
                        let m = 1 << bit_index;
                        // The bit is unmasked, i.e., if we change it the filter will no longer match.
                        if will_not_match || bf.mask & m != 0 {
                            let need_carry = *byte & m != 0;
                            *byte ^= m;

                            will_not_match = true;
                            if !need_carry {
                                break 'outer;
                            }
                        } else {
                            *byte &= !m;
                        }
                    }

                    self.data[self.len] = 0x00;
                    self.len -= 1;
                }

                self.num_tunneled = 0;
                self.tunnel_pos = self.len - 1;

                // Can we combine all filters in `seen` to form a new, bigger, filter?
                if seen.len() > 1 {
                    let mut relevant_filters = seen.iter()
                        .map(|n| &self.filters[*n])
                        .filter(|f| f.len() == matching_filter.len())
                        .collect::<Vec<_>>();
                    if relevant_filters.len() > 1 {
                        if let Some(change_index) = matching_filter.data.iter().zip(relevant_filters[0].data.iter()).position(|(a, b)| !a.can_intersect(b)) {
                            let mut new_filter = matching_filter.clone();
                            relevant_filters.retain(|f| 
                                matching_filter.data.iter()
                                    .zip(f.data.iter())
                                    .enumerate()
                                    .all(|(index, (a, b))| index == change_index || a.can_intersect(b))
                            );

                            for f in relevant_filters.iter() {
                                for (index, (a, b)) in new_filter.data.iter_mut().zip(f.data.iter()).enumerate() {
                                    if index != change_index {
                                        a.intersect(b);
                                    }
                                }
                            }

                            new_filter.data[change_index].mask = 0xff;

                            if (0..=0xff).all(|n| {
                                new_filter.data[change_index].value = n;

                                relevant_filters.iter().any(|f| f.covers(&new_filter))
                            }) {
                                new_filter.data[change_index] = ByteFilter::new(0, 0);

                                if self.filter_is_relevant(&new_filter) {
                                    self.filters.push(new_filter);
                                }
                            }
                        }
                    }
                }
            } else {
                // None of the filters match, making this a good candidate instruction!
                // We remove some redundant filters
                self.filters.retain(|f| !f.max_smaller_than(&current));
                if let Some(end) = &self.end {
                    if self.current() > end.as_instr() {
                        return false;
                    }
                }

                return true;
            }
        }
    }

    pub fn tunnel_next(&mut self, tunnel_delay: usize) -> bool {
        self.num_tunneled += 1;
        // Require some amount of consecutive tunnels before we actually start tunneling
        if self.num_tunneled < tunnel_delay {
            self.tunnel_pos = self.len - 1;
        }

        if !self.next_single() {
            return false;
        }

        if self.num_tunneled < tunnel_delay {
            self.len = self.tunnel_pos + 1;
        }
        self.apply_filters_to_current()
    }

    pub fn tunnel_next_ignore_filters(&mut self) -> bool {
        if !self.next_single() {
            return false;
        }

        true
    }

    pub fn current(&self) -> Instr<'_> {
        self.data[0..self.len].into()
    }
}

#[cfg(test)]
mod tests {
    use crate::arch::Instruction;
    use super::{ByteFilter, Instr, InstructionCounter, InstructionFilter};

    #[test]
    pub fn bytefilter_match() {
        let bf = ByteFilter::new(0b1111_1100, 0b0010_1000);
        assert!(bf.matches(0b0010_1000));
        assert!(bf.matches(0b0010_1001));
        assert!(bf.matches(0b0010_1010));
        assert!(bf.matches(0b0010_1011));
        assert!(!bf.matches(0b1010_1011));
        assert!(!bf.matches(0b0110_1011));
        assert!(!bf.matches(0b0000_1011));
        assert!(!bf.matches(0b0011_1011));
        assert!(!bf.matches(0b0010_0011));
        assert!(!bf.matches(0b0010_1111));

        let bf = ByteFilter::new(0b0000_0001, 0b0000_0000);
        assert!(bf.matches(0b0000_0000));
        assert!(bf.matches(0b0000_0010));
    }

    #[test]
    pub fn bytefilter_covers() {
        let bf1 = ByteFilter::new(0b0011_1100, 0b0010_1000);
        let bf2 = ByteFilter::new(0b1111_1100, 0b1010_1000);

        assert!(bf1.covers(&bf1));
        assert!(bf2.covers(&bf2));
        assert!(bf1.covers(&bf2));
        assert!(!bf2.covers(&bf1));
    }

    #[test]
    pub fn bytefilter_ord() {
        let bf = ByteFilter::new(0b0011_1100, 0b0010_1000);
        assert!(!bf.max_smaller_than(0));
        assert!(bf.max_smaller_than(0b1111_1101));

        let bf = ByteFilter::new(0b0000_0001, 0b0000_0001);
        assert!(!bf.max_smaller_than(0));
        assert!(!bf.max_smaller_than(1));
        assert!(!bf.max_smaller_than(21));

        let bf = ByteFilter::new(0b0011_0000, 0b0000_0000);
        assert!(!bf.max_smaller_than(0));
        assert!(!bf.max_smaller_than(1));
        assert!(!bf.max_smaller_than(0b00010101));
        assert!(!bf.max_smaller_than(0b0011_0000));
        assert!(!bf.max_smaller_than(0b1100_0000));
        assert!(bf.max_smaller_than(0b1101_0000));

        let bf = ByteFilter::new(0b0000_0001, 0b0000_0000);
        assert!(!bf.max_smaller_than(0));
        assert!(!bf.max_smaller_than(1));
        assert!(!bf.max_smaller_than(21));
    }

    #[test]
    pub fn bytefilter_max() {
        let bf = ByteFilter::new(0b0011_1100, 0b0010_1000);
        assert!(bf.at_max(0b1110_1011));

        let bf = ByteFilter::new(0b0000_0001, 0b0000_0001);
        assert!(bf.at_max(0b1111_1111));

        let bf = ByteFilter::new(0b0011_0000, 0b0000_0000);
        assert!(bf.at_max(0b1100_1111));

        let bf = ByteFilter::new(0b0000_0001, 0b0000_0000);
        assert!(bf.at_max(0b1111_1110));
    }

    #[test]
    pub fn bytefilter_merge() {
        let mut bf1 = ByteFilter::new(0b0010, 0b0000);
        let bf2 = ByteFilter::new(0b0010, 0b0010);
        assert!(bf1.can_merge(&bf2));

        bf1.merge(&bf2);
        assert_eq!(bf1, ByteFilter::new(0, 0));

        let m = ByteFilter::new(0b1010, 0b1010);
        assert!(!bf1.can_merge(&m));

        let bf3 = ByteFilter::new(0b1010, 0b0000);
        assert!(!bf3.can_merge(&m));

        let a1 = ByteFilter::new(0b0011_0010, 0b0001_0010);
        let mut a2 = ByteFilter::new(0b1001_1001, 0b1001_0001);
        let b1 = ByteFilter::new(0b0001_0010, 0b0001_0010);
        let b2 = ByteFilter::new(0b0000_0001, 0b0000_0000);

        assert!(!a1.can_merge(&b1));
        assert!(b1.covers(&a1));

        assert!(a2.can_merge(&b2));
        a2.merge(&b2);
        assert_eq!(a2, ByteFilter::new(0b1001_1000, 0b1001_0000));

    }

    #[test]
    pub fn bytefilter_intersect() {
        let mut bf1 = ByteFilter::new(0b0010, 0b0000);
        let bf2 = ByteFilter::new(0b0100, 0b0100);

        assert!(bf1.can_intersect(&bf2));

        bf1.intersect(&bf2);
        assert_eq!(bf1, ByteFilter::new(0b0110, 0b0100));
    }

    #[test]
    pub fn instruction_filter() {
        let f = InstructionFilter::new(vec! [
            ByteFilter::new(0b1111_1100, 0b0010_1000),
            ByteFilter::new(0b1001_1001, 0b1001_0001)
        ]);

        assert!(f.matches(&Instr::new(&[ 0b0010_1000, 0b1001_0001 ])));
        assert!(f.matches(&Instr::new(&[ 0b0010_1011, 0b1011_0111 ])));
        assert!(f.matches(&Instr::new(&[ 0b0010_1000, 0b1001_0001, 0b1111_0000 ])));
        assert!(!f.matches(&Instr::new(&[])));
        assert!(!f.matches(&Instr::new(&[ 0b0010_1000 ])));

        assert!(!f.matches(&Instr::new(&[ 0b0010_1011, 0b1011_1111 ])));

        let f = InstructionFilter::new(vec! [
            ByteFilter::new(0, 0),
            ByteFilter::new(0b1000_0000, 0b0000_0000)
        ]);
        assert!(!f.matches(&Instr::new(&[ 1, 0b1000_0000 ])));
    }

    #[test]
    pub fn instruction_filter_ord() {
        let f = InstructionFilter::new(vec! [
            ByteFilter::new(0b0011_1100, 0b0010_1000),
            ByteFilter::new(0b1001_1001, 0b1001_0001)
        ]);

        assert!(!f.max_smaller_than(&Instr::new(&[ 0, 0 ])));
        assert!(!f.max_smaller_than(&Instr::new(&[ 0 ])));
        assert!(!f.max_smaller_than(&Instr::new(&[ 0b0010_1000, 0b1001_0001 ])));

        assert!(f.max_smaller_than(&Instr::new(&[ 0b1111_1000 ])));
        assert!(!f.max_smaller_than(&Instr::new(&[ 0b0010_1000, 0b1111_1001 ])));

        let f = InstructionFilter::parse("00000011 10___100 ___00000 ________ ________ ________ ________");
        assert!(!f.max_smaller_than(&Instr::new(&[ 0x03, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00 ])));
        assert!(!f.min_greater_than(&Instr::new(&[ 0x03, 0x86 ])));
    }

    #[test]
    pub fn instruction_filter_redundancy() {
        let f = InstructionFilter::new(vec! [
            ByteFilter::new(0b0011_0010, 0b0001_0010),
            ByteFilter::new(0b1001_1001, 0b1001_0001)
        ]);
        let g = InstructionFilter::new(vec! [
            ByteFilter::new(0b0001_0010, 0b0001_0010),
            ByteFilter::new(0b0001_1001, 0b0001_0001)
        ]);
        
        assert!(!f.covers(&g));
        assert!(g.covers(&f));
    }

    #[test]
    pub fn instruction_filter_merge() {
        let f = InstructionFilter::new(vec! [
            ByteFilter::new(0b0011_0010, 0b0001_0010),
            ByteFilter::new(0b1001_1001, 0b1001_0001)
        ]);
        let g = InstructionFilter::new(vec! [
            ByteFilter::new(0b0001_0010, 0b0001_0010),
            ByteFilter::new(0b0000_0001, 0b0000_0000)
        ]);

        let expected = InstructionFilter::new(vec! [
            ByteFilter::new(0b0011_0010, 0b0001_0010),
            ByteFilter::new(0b1001_1000, 0b1001_0000)
        ]);

        println!("Merging: {:?}", f);
        println!("With   : {:?}", g);
        println!("Expect : {:?}", expected);
        
        assert_eq!(f.try_merge(&g), Some(expected));
    }

    #[test]
    pub fn instruction_filter_merge2() {
        let f1 = InstructionFilter::parse("0100____ 00001111 00000000 01100100 ________ ________");
        let f2 = InstructionFilter::parse("01000___ 00001101 ________ ________ ________ ________");
        
        let result = f1.try_merge(&f2);

        println!("Merged: {:?}", f1);
        println!("With  : {:?}", f2);
        println!("Giving: {:?}", result);

        assert_eq!(Some(InstructionFilter::parse("01000___ 000011_1 00000000 01100100 ________ ________")), result);
    }

    #[test]
    pub fn instruction_filter_merge_specialize() {
        let f = InstructionFilter::new(vec! [
            ByteFilter::new(0b1111_1011, 0b0001_0010),
            ByteFilter::new(0b1001_1001, 0b1001_0001)
        ]);
        let g = InstructionFilter::new(vec! [
            ByteFilter::new(0b1111_1111, 0b0001_0010),
            ByteFilter::new(0b0000_0001, 0b0000_0000)
        ]);

        let expected = InstructionFilter::new(vec! [
            ByteFilter::new(0b1111_1111, 0b0001_0010),
            ByteFilter::new(0b1001_1000, 0b1001_0000)
        ]);

        println!("Merging: {:?}", f);
        println!("With   : {:?}", g);
        println!("Expect : {:?}", expected);
        
        assert_eq!(f.try_merge(&g), Some(expected));
    }

    #[test]
    pub fn count_next() {
        let mut c = InstructionCounter::new();
        assert_eq!(c.current(), [ 0x00 ].as_ref().into());

        c.tunnel_next(200);
        assert_eq!(c.current(), [ 0x01 ].as_ref().into());
        
        c.tunnel_next(200);
        assert_eq!(c.current(), [ 0x02 ].as_ref().into());
    }

    #[test]
    pub fn count_range() {
        let mut c = InstructionCounter::range(Instr::new(&[ 0x14 ]), Some(Instruction::new(&[ 0x18 ])));
        
        assert_eq!(c.current(), [ 0x14 ].as_ref().into());

        assert!(c.tunnel_next(200));
        assert_eq!(c.current(), [ 0x15 ].as_ref().into());

        assert!(c.tunnel_next(200));
        assert_eq!(c.current(), [ 0x16 ].as_ref().into());

        assert!(c.tunnel_next(200));
        assert_eq!(c.current(), [ 0x17 ].as_ref().into());

        assert!(c.tunnel_next(200));
        assert_eq!(c.current(), [ 0x18 ].as_ref().into());

        assert!(!c.tunnel_next(200));
    }

    #[test]
    pub fn count_extend() {
        let mut c = InstructionCounter::new();
        assert_eq!(c.current(), [ 0x00 ].as_ref().into());

        c.extend(false);
        assert_eq!(c.current(), [ 0x00, 0x00 ].as_ref().into());
        
        c.tunnel_next(200);
        assert_eq!(c.current(), [ 0x00, 0x01 ].as_ref().into());
    }

    #[test]
    pub fn count_overflow() {
        let mut c = InstructionCounter::new();
        assert_eq!(c.current(), [ 0x00 ].as_ref().into());

        c.extend(false);
        assert_eq!(c.current(), [ 0x00, 0x00 ].as_ref().into());

        c.extend(false);
        assert_eq!(c.current(), [ 0x00, 0x00, 0x00 ].as_ref().into());

        for n in 0..=0xff { 
            c.filter(InstructionFilter::new(vec![
                ByteFilter::new(0xff, 0x00),
                ByteFilter::new(0xff, 0x00),
                ByteFilter::new(0xff, n),
            ]));

            c.apply_filters_to_current(); 
        }

        assert_eq!(c.current(), [ 0x00, 0x01 ].as_ref().into());

        c.extend(false);
        assert_eq!(c.current(), [ 0x00, 0x01, 0x00 ].as_ref().into());
    }

    #[test]
    pub fn count_finish() {
        let mut c = InstructionCounter::new();
        assert_eq!(c.current(), [ 0x00 ].as_ref().into());

        for _ in 0..255 { 
            assert_eq!(c.tunnel_next(200), true); 
        }

        assert_eq!(c.tunnel_next(200), false);
    }

    #[test]
    pub fn counter_end_complex() {
        let mut c = InstructionCounter::range(Instr::new(&[ 0x45, 0x40 ]), Some(Instruction::new(&[ 0x47, 0x19, 0x1B ])));
        assert_eq!(c.current(), [ 0x45, 0x40 ].as_ref().into());

        for _ in 0..0xC0 { 
            assert_eq!(c.tunnel_next(200), true); 
        }

        assert_eq!(c.current(), [ 0x46 ].as_ref().into());
        c.extend(false);

        for n in 0..=0xff {
            c.filter(InstructionFilter::new(vec![
                ByteFilter::new(0xff, 0x46),
                ByteFilter::new(0xff, n),
            ]));
            assert_eq!(c.apply_filters_to_current(), true); 
        }

        assert_eq!(c.current(), [ 0x47 ].as_ref().into());
        c.extend(false);

        for _ in 0..0x19 { 
            assert_eq!(c.tunnel_next(200), true); 
        }

        println!("Current: {:02X?}", c.current().bytes());
        assert_eq!(c.current(), [ 0x47, 0x19 ].as_ref().into());
        c.extend(false);

        for n in 0..0x1B {
            println!("Remaining {}: {:02X?}", n, c.current().bytes());
            assert_eq!(c.tunnel_next(200), true); 
        }

        assert_eq!(c.tunnel_next(200), false);
    }

    #[test]
    pub fn test_filter1() {
        let mut c = InstructionCounter::new();
        assert_eq!(c.current(), [ 0x00 ].as_ref().into());

        c.filter(InstructionFilter::new(vec! [ 
            ByteFilter::new(0b0000_0001, 0b00000000)
        ]));

        for i in 0..128 { 
            assert_eq!(c.tunnel_next(200), true); 
            assert_eq!(c.current(), [ 1 + i * 2 ].as_ref().into());
        }

        assert_eq!(c.tunnel_next(200), false);
    }

    #[test]
    pub fn test_filter2() {
        let mut c = InstructionCounter::new();
        assert_eq!(c.current(), [ 0x00 ].as_ref().into());

        let f = InstructionFilter::new(vec! [ 
            ByteFilter::new(0b1111_0010, 0b00000010)
        ]);
        println!("Filter: {:?}", f);
        c.filter(f);

        for i in [
            0b0001, 
            0b0100, 0b0101, 
            0b1000, 0b1001, 0b1100, 0b1101,
        ].iter().cloned().chain(16..=255) { 
            assert_eq!(c.tunnel_next(200), true); 
            assert_eq!(c.current(), [ i ].as_ref().into());
        }

        assert_eq!(c.tunnel_next(200), false);
    }

    #[test]
    pub fn test_apply_filter() {
        let mut c = InstructionCounter::new();
        assert_eq!(c.current(), [ 0x00 ].as_ref().into());

        c.filter(InstructionFilter::new(vec! [ 
            ByteFilter::new(0b1111_1100, 0b0000_0000)
        ]));

        assert!(c.apply_filters_to_current());
        assert_eq!(c.current(), [ 0x04 ].as_ref().into());
    }

    #[test]
    pub fn test_filter_partial() {
        let mut c = InstructionCounter::new();
        c.extend(false);
        assert_eq!(c.current(), [ 0x00, 0x00 ].as_ref().into());

        c.filter(InstructionFilter::new(vec! [  
            ByteFilter::new(0, 0),
            ByteFilter::new(0b1000_0000, 0b0000_0000),
        ]));

        for i in 128..=255 {
            assert_eq!(c.tunnel_next(200), true); 
            assert_eq!(c.current(), [ 0x00, i ].as_ref().into());
        }

        assert_eq!(c.tunnel_next(200), true); 
        // assert_eq!(c.current(), [ 0x01 ].as_ref().into());

        // c.extend(false);
        assert_eq!(c.current(), [ 0x01, 0b1000_0000 ].as_ref().into());
    }


    #[test]
    pub fn test_filter_redundancy() {
        let f1 = InstructionFilter::new(vec![
            ByteFilter::new(0xff, 0b10000011),
            ByteFilter::new(0b01110110, 0b00000100),
            ByteFilter::new(0, 0),
            ByteFilter::new(0, 0),
            ByteFilter::new(0, 0),
            ByteFilter::new(0, 0),
            ByteFilter::new(0b10, 0),
        ]);

        let f2 = InstructionFilter::new(vec![
            ByteFilter::new(0xff, 0b10000011),
            ByteFilter::new(0xff, 0b00001100),
            ByteFilter::new(0x01, 0x00),
            ByteFilter::new(0x80, 0x80),
        ]);

        assert!(!f1.covers(&f2));
    }

    #[test_env_log::test]
    pub fn test_filter_nesting() {
        let mut c = InstructionCounter::new();
        c.extend(false);
        c.extend(false);
        c.extend(false);
        assert_eq!(c.current(), [ 0x00, 0x00, 0x00, 0x00 ].as_ref().into());

        for i in 0..8 {
            c.filter(InstructionFilter::new(vec! [  
                ByteFilter::new(0b0010_0001, 0),
                ByteFilter::new(0b1111_1111, 0),
                ByteFilter::new(0b1111_1111, 0),
                ByteFilter::new(1 << i, 1 << i),
            ]));
        }

        assert_eq!(c.tunnel_next(200), true);
        assert_eq!(c.current(), [ 0x00, 0x00, 0x01 ].as_ref().into());

        assert_eq!(c.extend(false), true);
        assert_eq!(c.current(), [ 0x00, 0x00, 0x01, 0x00 ].as_ref().into());

        for i in 0..8 {
            c.filter(InstructionFilter::new(vec! [  
                ByteFilter::new(0b0010_0001, 0),
                ByteFilter::new(0b1111_1111, 0),
                ByteFilter::new(1 << i, 1 << i),
                ByteFilter::new(0, 0),
            ]));
        }

        assert_eq!(c.tunnel_next(200), true);
        assert_eq!(c.current(), [ 0x00, 0x01 ].as_ref().into());

        assert_eq!(c.extend(false), true);
        assert_eq!(c.current(), [ 0x00, 0x01, 0x00 ].as_ref().into());

        assert_eq!(c.extend(false), true);
        assert_eq!(c.current(), [ 0x00, 0x01, 0x00, 0x00 ].as_ref().into());

        assert_eq!(c.tunnel_next(200), true);
        assert_eq!(c.current(), [ 0x00, 0x01, 0x00, 0x01 ].as_ref().into());
    }

    #[test_env_log::test]
    pub fn instr_ord() {
        assert!(Instr::new(&[ 0x0F ]) < Instr::new(&[ 0x0F, 0xFF ]));
        assert!(Instr::new(&[ 0x0F, 0xFF ]) > Instr::new(&[ 0x0F ]));
        assert!(Instr::new(&[ 0x0F, 0xFF ]) >= Instr::new(&[ 0x0F ]));
    }

    #[test_env_log::test]
    pub fn counter_end() {
        let mut c = InstructionCounter::range(Instr::new(&[ 0x0E ]), Some(Instr::new(&[ 0x0F, 0xFF ]).into()));
        assert_eq!(c.current(), [ 0x0E ].as_ref().into());

        assert!(c.tunnel_next(200));
        assert_eq!(c.current(), [ 0x0F ].as_ref().into());
    }

    #[test_env_log::test]
    pub fn test_filter_merge() {
        let mut c = InstructionCounter::range(Instr::new(&[ 0x02, 0x15, 0x82, 0x09, 0x00, 0x00 ]), None);
        assert_eq!(c.current(), [ 0x02, 0x15, 0x82, 0x09, 0x00, 0x00 ].as_ref().into());

        for i in 0..8 {
            c.filter(InstructionFilter::new(vec! [  
                ByteFilter::new(0b1101_0110, 0b0000_0010),
                ByteFilter::new(0b0100_0111, 0b0000_0101),
                ByteFilter::new(0, 0),
                ByteFilter::new(0, 0),
                ByteFilter::new(0, 0),
                ByteFilter::new(1 << i, 1 << i),
            ]));
        }

        for i in 0..8 {
            c.filter(InstructionFilter::new(vec! [  
                ByteFilter::new(0b1101_0110, 0b0000_0010),
                ByteFilter::new(0b0100_0111, 0b0000_0101),
                ByteFilter::new(0, 0),
                ByteFilter::new(0, 0),
                ByteFilter::new(1 << i, 1 << i),
                ByteFilter::new(0, 0),
            ]));
        }

        for i in 4..8 {
            c.filter(InstructionFilter::new(vec! [  
                ByteFilter::new(0b1101_0110, 0b0000_0010),
                ByteFilter::new(0b0100_0111, 0b0000_0101),
                ByteFilter::new(0, 0),
                ByteFilter::new(1 << i, 1 << i),
                ByteFilter::new(0, 0),
                ByteFilter::new(0, 0),
            ]));
        }

        for i in 0..4 {
            c.filter(InstructionFilter::new(vec! [  
                ByteFilter::new(0b1101_0110, 0b0000_0010),
                ByteFilter::new(0b0100_0111, 0b0000_0101),
                ByteFilter::new(0, 0),
                ByteFilter::new(1 << i, 1 << i),
                ByteFilter::new(0xff, 0),
                ByteFilter::new(0xff, 0),
            ]));
        }

        println!("{:?}", c);

        assert_eq!(c.apply_filters_to_current(), true);
        assert_eq!(c.current(), [ 0x02, 0x15, 0x83, 0x00, 0x00, 0x00 ].as_ref().into());
    }


    #[test_env_log::test]
    pub fn test_filter_merge_complex() {
        let f1 = InstructionFilter::parse("01000100 11110110 01010100 __111111 ________");
        let f2 = InstructionFilter::parse("00001111 00010111 01___100 ___0__1_ ________");

        assert!(f1.try_merge(&f2).is_none());


        let f1 = InstructionFilter::parse("01000100 11110110 01010100 __111111 ________");
        let f2 = InstructionFilter::parse("____111_ ____0111 01___100 ___0__1_ ________");

        assert!(f1.try_merge(&f2).is_none());



        let f1 = InstructionFilter::parse("01000__0 1111___0 01010100 __111111 ________");
        let f2 = InstructionFilter::parse("____111_ ____0111 01___100 ___0__1_ ________");

        assert!(f1.try_merge(&f2).is_none());
    }

    #[test]
    pub fn test_filter_match_instr() {
        let f = InstructionFilter::parse("00001111 00010111 01___100 __111111 ________");
        assert!(f.matches(&Instr::new(&[ 0x0F, 0x17, 0x74, 0xFF, 0x00 ])));
    }

    #[test]
    pub fn test_filter_performance() {
        let mut c = InstructionCounter::new();
        c.extend(false);
        c.extend(false);
        c.extend(false);
        c.extend(false);
        c.extend(false);

        assert_eq!(c.current(), [ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 ].as_ref().into());

        c.filter(InstructionFilter::new(vec! [ 
            ByteFilter::new(0b1111_1111, 0b0000_0000),
            ByteFilter::new(0b0000_0000, 0),
            ByteFilter::new(0b0000_0000, 0),
            ByteFilter::new(0b0000_0000, 0),
            ByteFilter::new(0b0000_0000, 0),
            ByteFilter::new(0b0000_0000, 0),
        ]));

        for i in 1..=255 { 
            assert_eq!(c.tunnel_next(200), true); 
            assert_eq!(c.current(), [ i ].as_ref().into());
        }

        assert_eq!(c.tunnel_next(200), false);
    }

    #[test]
    pub fn test_simple_next_step() {
        let mut c = InstructionCounter::range([ 0x45, 0xFF, 0xA4, 0x00, 0x00, 0x00, 0x00, 0x00 ].as_ref().into(), None);

        assert_eq!(c.current(), [ 0x45, 0xFF, 0xA4, 0x00, 0x00, 0x00, 0x00, 0x00 ].as_ref().into());

        assert!(c.tunnel_next(200));

        c.filter(InstructionFilter::new(vec! [ 
            ByteFilter::new(0b1111_0011, 0x41),
            ByteFilter::new(0xff, 0xff),
            ByteFilter::new(0xff, 0xA4),
            ByteFilter::new(0, 0),
            ByteFilter::new(0, 0),
            ByteFilter::new(0, 0),
            ByteFilter::new(0, 0),
        ]));

        assert!(c.apply_filters_to_current());
        
        assert_eq!(c.current(), [ 0x45, 0xFF, 0xA5 ].as_ref().into());
    }

    #[test]
    pub fn test_next_step2() {
        let mut c = InstructionCounter::range([ 0x0F, 0x17, 0x74, 0x29, 0x00 ].as_ref().into(), None);

        assert_eq!(c.current(), [ 0x0F, 0x17, 0x74, 0x29, 0x00 ].as_ref().into());

        c.filter(InstructionFilter::parse("00001111 00010111 01110000 ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 01110001 ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 01110010 ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 01110011 ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 01110101 ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 01110110 ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 01110111 ________"));
        c.filter(InstructionFilter::parse("00001111 1010_100 10___000 ________ ________ ________ ________ ___00000"));
        c.filter(InstructionFilter::parse("00001111 1010_100 10___001 ________ ________ ________ ________ ___00000"));
        c.filter(InstructionFilter::parse("00001111 1010_100 10___010 ________ ________ ________ ________ ___00000"));
        c.filter(InstructionFilter::parse("00001111 1010_100 10___011 ________ ________ ________ ________ ___00000"));
        c.filter(InstructionFilter::parse("00001111 1010_100 10___101 ________ ________ ________ ________ ___00000"));
        c.filter(InstructionFilter::parse("00001111 1010_100 10___110 ________ ________ ________ ________ ___00000"));
        c.filter(InstructionFilter::parse("00001111 1010_100 10___111 ________ ________ ________ ________ ___00000"));
        c.filter(InstructionFilter::parse("00001111 00010111 01010100 ___00000 ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 01___100 ___0__1_ ________"));
        c.filter(InstructionFilter::parse("01001_00 00110011 01___100 ___00000 ________"));
        c.filter(InstructionFilter::parse("01000100 11110110 01010100 __000000 ________"));
        c.filter(InstructionFilter::parse("01000100 11110110 01010100 __000001 ________"));
        c.filter(InstructionFilter::parse("01000100 11110110 01010100 __000010 ________"));
        c.filter(InstructionFilter::parse("01000100 11110110 01010100 __000011 ________"));
        c.filter(InstructionFilter::parse("01000100 11110110 01010100 __000100 ________"));
        c.filter(InstructionFilter::parse("01000100 11110110 01010100 __000101 ________"));
        c.filter(InstructionFilter::parse("01000100 11110110 01010100 __000110 ________"));
        c.filter(InstructionFilter::parse("01000100 11110110 01010100 __000111 ________"));
        c.filter(InstructionFilter::parse("01000101 11110110 01010100 __000001 ________"));
        c.filter(InstructionFilter::parse("01000101 11110110 01010100 __000010 ________"));
        c.filter(InstructionFilter::parse("01000101 11110110 01010100 __000011 ________"));
        c.filter(InstructionFilter::parse("01000101 11110110 01010100 __000100 ________"));
        c.filter(InstructionFilter::parse("01000101 11110110 01010100 __000101 ________"));
        c.filter(InstructionFilter::parse("01000101 11110110 01010100 __000110 ________"));
        c.filter(InstructionFilter::parse("01000101 11110110 01010100 __000111 ________"));
        c.filter(InstructionFilter::parse("01000100 11110110 01010100 __010000 ________"));
        c.filter(InstructionFilter::parse("01000100 11110110 01010100 __010001 ________"));
        c.filter(InstructionFilter::parse("01000100 11110110 01010100 __010010 ________"));
        c.filter(InstructionFilter::parse("01000100 11110110 01010100 __010011 ________"));
        c.filter(InstructionFilter::parse("01000100 11110110 01010100 __010100 ________"));
        c.filter(InstructionFilter::parse("01000100 11110110 01010100 __010101 ________"));
        c.filter(InstructionFilter::parse("01000100 11110110 01010100 __010110 ________"));
        c.filter(InstructionFilter::parse("01000100 11110110 01010100 __010111 ________"));
        c.filter(InstructionFilter::parse("01000101 11110110 01010100 __010001 ________"));
        c.filter(InstructionFilter::parse("01000101 11110110 01010100 __010010 ________"));
        c.filter(InstructionFilter::parse("01000101 11110110 01010100 __010011 ________"));
        c.filter(InstructionFilter::parse("01000101 11110110 01010100 __010100 ________"));
        c.filter(InstructionFilter::parse("01000101 11110110 01010100 __010101 ________"));
        c.filter(InstructionFilter::parse("01000101 11110110 01010100 __010110 ________"));
        c.filter(InstructionFilter::parse("01000101 11110110 01010100 __010111 ________"));
        c.filter(InstructionFilter::parse("01000100 11110110 01010100 __011000 ________"));
        c.filter(InstructionFilter::parse("01000100 11110110 01010100 __011001 ________"));
        c.filter(InstructionFilter::parse("01000100 11110110 01010100 __011010 ________"));
        c.filter(InstructionFilter::parse("01000100 11110110 01010100 __011011 ________"));
        c.filter(InstructionFilter::parse("01000100 11110110 01010100 __011100 ________"));
        c.filter(InstructionFilter::parse("01000100 11110110 01010100 __011101 ________"));
        c.filter(InstructionFilter::parse("01000100 11110110 01010100 __011110 ________"));
        c.filter(InstructionFilter::parse("01000100 11110110 01010100 __011111 ________"));
        c.filter(InstructionFilter::parse("01000101 11110110 01010100 __011001 ________"));
        c.filter(InstructionFilter::parse("01000101 11110110 01010100 __011010 ________"));
        c.filter(InstructionFilter::parse("01000101 11110110 01010100 __011011 ________"));
        c.filter(InstructionFilter::parse("01000101 11110110 01010100 __011100 ________"));
        c.filter(InstructionFilter::parse("01000101 11110110 01010100 __011101 ________"));
        c.filter(InstructionFilter::parse("01000101 11110110 01010100 __011110 ________"));
        c.filter(InstructionFilter::parse("01000101 11110110 01010100 __011111 ________"));
        c.filter(InstructionFilter::parse("01000100 11110110 01010100 __100000 ________"));
        c.filter(InstructionFilter::parse("01000100 11110110 01010100 __100001 ________"));
        c.filter(InstructionFilter::parse("01000100 11110110 01010100 __100010 ________"));
        c.filter(InstructionFilter::parse("01000100 11110110 01010100 __100011 ________"));
        c.filter(InstructionFilter::parse("01000100 11110110 01010100 __100100 ________"));
        c.filter(InstructionFilter::parse("01000100 11110110 01010100 __100101 ________"));
        c.filter(InstructionFilter::parse("01000100 11110110 01010100 __100110 ________"));
        c.filter(InstructionFilter::parse("01000100 11110110 01010100 __100111 ________"));
        c.filter(InstructionFilter::parse("01000101 11110110 01010100 __100001 ________"));
        c.filter(InstructionFilter::parse("01000101 11110110 01010100 __100010 ________"));
        c.filter(InstructionFilter::parse("01000101 11110110 01010100 __100011 ________"));
        c.filter(InstructionFilter::parse("01000101 11110110 01010100 __100100 ________"));
        c.filter(InstructionFilter::parse("01000101 11110110 01010100 __100101 ________"));
        c.filter(InstructionFilter::parse("01000101 11110110 01010100 __100110 ________"));
        c.filter(InstructionFilter::parse("01000101 11110110 01010100 __100111 ________"));
        c.filter(InstructionFilter::parse("01000100 11110110 01010100 __101000 ________"));
        c.filter(InstructionFilter::parse("01000100 11110110 01010100 __101001 ________"));
        c.filter(InstructionFilter::parse("01000100 11110110 01010100 __101010 ________"));
        c.filter(InstructionFilter::parse("01000100 11110110 01010100 __101011 ________"));
        c.filter(InstructionFilter::parse("01000100 11110110 01010100 __101100 ________"));
        c.filter(InstructionFilter::parse("01000100 11110110 01010100 __101101 ________"));
        c.filter(InstructionFilter::parse("01000100 11110110 01010100 __101110 ________"));
        c.filter(InstructionFilter::parse("01000100 11110110 01010100 __101111 ________"));
        c.filter(InstructionFilter::parse("01000101 11110110 01010100 __101001 ________"));
        c.filter(InstructionFilter::parse("01000101 11110110 01010100 __101010 ________"));
        c.filter(InstructionFilter::parse("01000101 11110110 01010100 __101011 ________"));
        c.filter(InstructionFilter::parse("01000101 11110110 01010100 __101100 ________"));
        c.filter(InstructionFilter::parse("01000101 11110110 01010100 __101101 ________"));
        c.filter(InstructionFilter::parse("01000101 11110110 01010100 __101110 ________"));
        c.filter(InstructionFilter::parse("01000101 11110110 01010100 __101111 ________"));
        c.filter(InstructionFilter::parse("01000100 11110110 01010100 __110000 ________"));
        c.filter(InstructionFilter::parse("01000100 11110110 01010100 __110001 ________"));
        c.filter(InstructionFilter::parse("01000100 11110110 01010100 __110010 ________"));
        c.filter(InstructionFilter::parse("01000100 11110110 01010100 __110011 ________"));
        c.filter(InstructionFilter::parse("01000100 11110110 01010100 __110100 ________"));
        c.filter(InstructionFilter::parse("01000100 11110110 01010100 __110101 ________"));
        c.filter(InstructionFilter::parse("01000100 11110110 01010100 __110110 ________"));
        c.filter(InstructionFilter::parse("01000100 11110110 01010100 __110111 ________"));
        c.filter(InstructionFilter::parse("01000101 11110110 01010100 __110001 ________"));
        c.filter(InstructionFilter::parse("01000101 11110110 01010100 __110010 ________"));
        c.filter(InstructionFilter::parse("01000101 11110110 01010100 __110011 ________"));
        c.filter(InstructionFilter::parse("01000101 11110110 01010100 __110100 ________"));
        c.filter(InstructionFilter::parse("01000101 11110110 01010100 __110101 ________"));
        c.filter(InstructionFilter::parse("01000101 11110110 01010100 __110110 ________"));
        c.filter(InstructionFilter::parse("01000101 11110110 01010100 __110111 ________"));
        c.filter(InstructionFilter::parse("01000100 11110110 01010100 __111000 ________"));
        c.filter(InstructionFilter::parse("01000100 11110110 01010100 __111001 ________"));
        c.filter(InstructionFilter::parse("01000100 11110110 01010100 __111010 ________"));
        c.filter(InstructionFilter::parse("01000100 11110110 01010100 __111011 ________"));
        c.filter(InstructionFilter::parse("01000100 11110110 01010100 __111100 ________"));
        c.filter(InstructionFilter::parse("01000100 11110110 01010100 __111101 ________"));
        c.filter(InstructionFilter::parse("01000100 11110110 01010100 __111110 ________"));
        c.filter(InstructionFilter::parse("01000100 11110110 01010100 __111111 ________"));
        c.filter(InstructionFilter::parse("01000101 11110110 01010100 __111001 ________"));
        c.filter(InstructionFilter::parse("01000101 11110110 01010100 __111010 ________"));
        c.filter(InstructionFilter::parse("01000101 11110110 01010100 __111011 ________"));
        c.filter(InstructionFilter::parse("01000101 11110110 01010100 __111100 ________"));
        c.filter(InstructionFilter::parse("01000101 11110110 01010100 __111101 ________"));
        c.filter(InstructionFilter::parse("01000101 11110110 01010100 __111110 ________"));
        c.filter(InstructionFilter::parse("01000101 11110110 01010100 __111111 ________"));
        c.filter(InstructionFilter::parse("01000110 11110110 01010100 __000000 ________"));
        c.filter(InstructionFilter::parse("01000110 11110110 01010100 __000001 ________"));
        c.filter(InstructionFilter::parse("01000110 11110110 01010100 __000010 ________"));
        c.filter(InstructionFilter::parse("01000110 11110110 01010100 __000011 ________"));
        c.filter(InstructionFilter::parse("01000110 11110110 01010100 __000100 ________"));
        c.filter(InstructionFilter::parse("01000110 11110110 01010100 __000101 ________"));
        c.filter(InstructionFilter::parse("01000110 11110110 01010100 __000110 ________"));
        c.filter(InstructionFilter::parse("01000110 11110110 01010100 __000111 ________"));
        c.filter(InstructionFilter::parse("01000111 11110110 01010100 __000001 ________"));
        c.filter(InstructionFilter::parse("01000111 11110110 01010100 __000010 ________"));
        c.filter(InstructionFilter::parse("01000111 11110110 01010100 __000011 ________"));
        c.filter(InstructionFilter::parse("01000111 11110110 01010100 __000100 ________"));
        c.filter(InstructionFilter::parse("01000111 11110110 01010100 __000101 ________"));
        c.filter(InstructionFilter::parse("01000111 11110110 01010100 __000110 ________"));
        c.filter(InstructionFilter::parse("01000111 11110110 01010100 __000111 ________"));
        c.filter(InstructionFilter::parse("01000110 11110110 01010100 __001000 ________"));
        c.filter(InstructionFilter::parse("01000110 11110110 01010100 __001001 ________"));
        c.filter(InstructionFilter::parse("01000110 11110110 01010100 __001010 ________"));
        c.filter(InstructionFilter::parse("01000110 11110110 01010100 __001011 ________"));
        c.filter(InstructionFilter::parse("01000110 11110110 01010100 __001100 ________"));
        c.filter(InstructionFilter::parse("01000110 11110110 01010100 __001101 ________"));
        c.filter(InstructionFilter::parse("01000110 11110110 01010100 __001110 ________"));
        c.filter(InstructionFilter::parse("01000110 11110110 01010100 __001111 ________"));
        c.filter(InstructionFilter::parse("01000111 11110110 01010100 __001001 ________"));
        c.filter(InstructionFilter::parse("01000111 11110110 01010100 __001010 ________"));
        c.filter(InstructionFilter::parse("01000111 11110110 01010100 __001011 ________"));
        c.filter(InstructionFilter::parse("01000111 11110110 01010100 __001100 ________"));
        c.filter(InstructionFilter::parse("01000111 11110110 01010100 __001101 ________"));
        c.filter(InstructionFilter::parse("01000111 11110110 01010100 __001110 ________"));
        c.filter(InstructionFilter::parse("01000111 11110110 01010100 __001111 ________"));
        c.filter(InstructionFilter::parse("01000110 11110110 01010100 __010000 ________"));
        c.filter(InstructionFilter::parse("01000110 11110110 01010100 __010001 ________"));
        c.filter(InstructionFilter::parse("01000110 11110110 01010100 __010010 ________"));
        c.filter(InstructionFilter::parse("01000110 11110110 01010100 __010011 ________"));
        c.filter(InstructionFilter::parse("01000110 11110110 01010100 __010100 ________"));
        c.filter(InstructionFilter::parse("01000110 11110110 01010100 __010101 ________"));
        c.filter(InstructionFilter::parse("01000110 11110110 01010100 __010110 ________"));
        c.filter(InstructionFilter::parse("01000110 11110110 01010100 __010111 ________"));
        c.filter(InstructionFilter::parse("01000111 11110110 01010100 __010001 ________"));
        c.filter(InstructionFilter::parse("01000111 11110110 01010100 __010010 ________"));
        c.filter(InstructionFilter::parse("01000111 11110110 01010100 __010011 ________"));
        c.filter(InstructionFilter::parse("01000111 11110110 01010100 __010100 ________"));
        c.filter(InstructionFilter::parse("01000111 11110110 01010100 __010101 ________"));
        c.filter(InstructionFilter::parse("01000111 11110110 01010100 __010110 ________"));
        c.filter(InstructionFilter::parse("01000111 11110110 01010100 __010111 ________"));
        c.filter(InstructionFilter::parse("01000110 11110110 01010100 __011000 ________"));
        c.filter(InstructionFilter::parse("01000110 11110110 01010100 __011001 ________"));
        c.filter(InstructionFilter::parse("01000110 11110110 01010100 __011010 ________"));
        c.filter(InstructionFilter::parse("01000110 11110110 01010100 __011011 ________"));
        c.filter(InstructionFilter::parse("01000110 11110110 01010100 __011100 ________"));
        c.filter(InstructionFilter::parse("01000110 11110110 01010100 __011101 ________"));
        c.filter(InstructionFilter::parse("01000110 11110110 01010100 __011110 ________"));
        c.filter(InstructionFilter::parse("01000110 11110110 01010100 __011111 ________"));
        c.filter(InstructionFilter::parse("01000111 11110110 01010100 __011001 ________"));
        c.filter(InstructionFilter::parse("01000111 11110110 01010100 __011010 ________"));
        c.filter(InstructionFilter::parse("01000111 11110110 01010100 __011011 ________"));
        c.filter(InstructionFilter::parse("01000111 11110110 01010100 __011100 ________"));
        c.filter(InstructionFilter::parse("01000111 11110110 01010100 __011101 ________"));
        c.filter(InstructionFilter::parse("01000111 11110110 01010100 __011110 ________"));
        c.filter(InstructionFilter::parse("01000111 11110110 01010100 __011111 ________"));
        c.filter(InstructionFilter::parse("01000110 11110110 01010100 __100000 ________"));
        c.filter(InstructionFilter::parse("01000110 11110110 01010100 __100001 ________"));
        c.filter(InstructionFilter::parse("01000110 11110110 01010100 __100010 ________"));
        c.filter(InstructionFilter::parse("01000110 11110110 01010100 __100011 ________"));
        c.filter(InstructionFilter::parse("01000110 11110110 01010100 __100100 ________"));
        c.filter(InstructionFilter::parse("01000110 11110110 01010100 __100101 ________"));
        c.filter(InstructionFilter::parse("01000110 11110110 01010100 __100110 ________"));
        c.filter(InstructionFilter::parse("01000110 11110110 01010100 __100111 ________"));
        c.filter(InstructionFilter::parse("01000111 11110110 01010100 __100001 ________"));
        c.filter(InstructionFilter::parse("01000111 11110110 01010100 __100010 ________"));
        c.filter(InstructionFilter::parse("01000111 11110110 01010100 __100011 ________"));
        c.filter(InstructionFilter::parse("01000111 11110110 01010100 __100100 ________"));
        c.filter(InstructionFilter::parse("01000111 11110110 01010100 __100101 ________"));
        c.filter(InstructionFilter::parse("01000111 11110110 01010100 __100110 ________"));
        c.filter(InstructionFilter::parse("01000111 11110110 01010100 __100111 ________"));
        c.filter(InstructionFilter::parse("01000110 11110110 01010100 __101000 ________"));
        c.filter(InstructionFilter::parse("01000110 11110110 01010100 __101001 ________"));
        c.filter(InstructionFilter::parse("01000110 11110110 01010100 __101010 ________"));
        c.filter(InstructionFilter::parse("01000110 11110110 01010100 __101011 ________"));
        c.filter(InstructionFilter::parse("01000110 11110110 01010100 __101100 ________"));
        c.filter(InstructionFilter::parse("01000110 11110110 01010100 __101101 ________"));
        c.filter(InstructionFilter::parse("01000110 11110110 01010100 __101110 ________"));
        c.filter(InstructionFilter::parse("01000110 11110110 01010100 __101111 ________"));
        c.filter(InstructionFilter::parse("01000111 11110110 01010100 __101001 ________"));
        c.filter(InstructionFilter::parse("01000111 11110110 01010100 __101010 ________"));
        c.filter(InstructionFilter::parse("01000111 11110110 01010100 __101011 ________"));
        c.filter(InstructionFilter::parse("01000111 11110110 01010100 __101100 ________"));
        c.filter(InstructionFilter::parse("01000111 11110110 01010100 __101101 ________"));
        c.filter(InstructionFilter::parse("01000111 11110110 01010100 __101110 ________"));
        c.filter(InstructionFilter::parse("01000111 11110110 01010100 __101111 ________"));
        c.filter(InstructionFilter::parse("01000110 11110110 01010100 __110000 ________"));
        c.filter(InstructionFilter::parse("01000110 11110110 01010100 __110001 ________"));
        c.filter(InstructionFilter::parse("01000110 11110110 01010100 __110010 ________"));
        c.filter(InstructionFilter::parse("01000110 11110110 01010100 __110011 ________"));
        c.filter(InstructionFilter::parse("01000110 11110110 01010100 __110100 ________"));
        c.filter(InstructionFilter::parse("01000110 11110110 01010100 __110101 ________"));
        c.filter(InstructionFilter::parse("01000110 11110110 01010100 __110110 ________"));
        c.filter(InstructionFilter::parse("01000110 11110110 01010100 __110111 ________"));
        c.filter(InstructionFilter::parse("01000111 11110110 01010100 __110001 ________"));
        c.filter(InstructionFilter::parse("01000111 11110110 01010100 __110010 ________"));
        c.filter(InstructionFilter::parse("01000111 11110110 01010100 __110011 ________"));
        c.filter(InstructionFilter::parse("01000111 11110110 01010100 __110100 ________"));
        c.filter(InstructionFilter::parse("01000111 11110110 01010100 __110101 ________"));
        c.filter(InstructionFilter::parse("01000111 11110110 01010100 __110110 ________"));
        c.filter(InstructionFilter::parse("01000111 11110110 01010100 __110111 ________"));
        c.filter(InstructionFilter::parse("01000110 11110110 01010100 __111000 ________"));
        c.filter(InstructionFilter::parse("01000110 11110110 01010100 __111001 ________"));
        c.filter(InstructionFilter::parse("01000110 11110110 01010100 __111010 ________"));
        c.filter(InstructionFilter::parse("01000110 11110110 01010100 __111011 ________"));
        c.filter(InstructionFilter::parse("01000110 11110110 01010100 __111100 ________"));
        c.filter(InstructionFilter::parse("01000110 11110110 01010100 __111101 ________"));
        c.filter(InstructionFilter::parse("01000110 11110110 01010100 __111110 ________"));
        c.filter(InstructionFilter::parse("01000110 11110110 01010100 __111111 ________"));
        c.filter(InstructionFilter::parse("01000111 11110110 01010100 __111001 ________"));
        c.filter(InstructionFilter::parse("01000111 11110110 01010100 __111010 ________"));
        c.filter(InstructionFilter::parse("01000111 11110110 01010100 __111011 ________"));
        c.filter(InstructionFilter::parse("01000111 11110110 01010100 __111100 ________"));
        c.filter(InstructionFilter::parse("01000111 11110110 01010100 __111101 ________"));
        c.filter(InstructionFilter::parse("01000111 11110110 01010100 __111110 ________"));
        c.filter(InstructionFilter::parse("01000111 11110110 01010100 __111111 ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 01___100 __000000 ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 01___100 __000010 ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 01___100 __000011 ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 01___100 __000100 ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 01___100 __000101 ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 01___100 __000110 ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 01___100 __000111 ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 01___100 __001000 ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 01___100 __001010 ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 01___100 __001011 ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 01___100 __001100 ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 01___100 __001101 ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 01___100 __001110 ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 01___100 __001111 ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 01___100 __011000 ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 01___100 __011010 ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 01___100 __011011 ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 01___100 __011100 ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 01___100 __011101 ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 01___100 __011110 ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 01___100 __011111 ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 01___100 __100000 ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 01___100 __100010 ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 01___100 __100011 ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 01___100 __100100 ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 01___100 __100101 ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 01___100 __100110 ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 01___100 __100111 ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 01___100 __101000 ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 01___100 __101010 ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 01___100 __101011 ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 01___100 __101100 ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 01___100 __101101 ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 01___100 __101110 ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 01___100 __101111 ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 01___100 __110000 ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 01___100 __110010 ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 01___100 __110011 ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 01___100 __110100 ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 01___100 __110101 ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 01___100 __110110 ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 01___100 __110111 ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 01___100 __111000 ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 01___100 __111010 ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 01___100 __111011 ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 01___100 __111100 ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 01___100 __111101 ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 01___100 __111110 ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 01___100 __111111 ________"));

        println!("Before: {:02X?}", c.current().bytes());
        assert!(c.apply_filters_to_current());

        println!("Advanced one: {:02X?}", c.current().bytes());
        
        c.filter(InstructionFilter::parse("00001111 00010111 01___100 __001000 ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 01___100 __001001 ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 01___100 __001010 ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 01___100 __001011 ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 01___100 __001100 ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 01___100 __001101 ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 01___100 __001110 ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 01___100 __010000 ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 01___100 __010001 ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 01___100 __010010 ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 01___100 __010011 ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 01___100 __010100 ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 01___100 __010101 ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 01___100 __010110 ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 01___100 __011000 ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 01___100 __011001 ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 01___100 __011010 ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 01___100 __011011 ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 01___100 __011100 ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 01___100 __011101 ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 01___100 __011110 ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 01___100 __100000 ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 01___100 __100001 ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 01___100 __100010 ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 01___100 __100011 ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 01___100 __100100 ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 01___100 __100101 ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 01___100 __100110 ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 01___100 __101000 ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 01___100 __101001 ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 01___100 __101010 ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 01___100 __101011 ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 01___100 __101100 ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 01___100 __101101 ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 01___100 __101110 ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 01___100 __110000 ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 01___100 __110001 ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 01___100 __110010 ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 01___100 __110011 ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 01___100 __110100 ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 01___100 __110101 ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 01___100 __110110 ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 01___100 __111000 ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 01___100 __111001 ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 01___100 __111010 ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 01___100 __111011 ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 01___100 __111100 ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 01___100 __111101 ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 01___100 __111110 ________"));

        // for v in 0..=0b111_111 {
        //     if v & 0b111 != 0b111 && (v >> 3) != 0b000 {
        //         let f = InstructionFilter::new(vec! [ 
        //             ByteFilter::new(0xff, 0x0F),
        //             ByteFilter::new(0xff, 0x17),
        //             ByteFilter::new(0b11000111, 0b01000100),
        //             ByteFilter::new(0b00111111, v),
        //             ByteFilter::new(0, 0),
        //         ]);
        //         println!("Adding filter: {:?}", f);
        //         c.filter(f);
        //     }
        // }

        println!("Before applying filters = {:02X?}", c.current().bytes());
        assert!(c.apply_filters_to_current());
        println!("Current = {:02X?}", c.current().bytes());
        
        assert_eq!(c.current(), [ 0x0F, 0x17, 0x74, 0x41 ].as_ref().into());
    }


    #[test]
    pub fn test_next_step3() {
        let mut c = InstructionCounter::range([ 0x0F, 0x17, 0x74, 0x12, 0x00 ].as_ref().into(), None);

        c.filter(InstructionFilter::parse("00001111 00010111 01110000 ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 01110001 ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 01110010 ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 01110011 ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 01110101 ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 01110110 ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 01110111 ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 01___100 ___00000 ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 01010100 ___00000 ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 01___100 ____0__1 ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 01___100 __000000 ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 01___100 __000001 ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 01___100 __000011 ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 01___100 __000100 ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 01___100 __000101 ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 01___100 __000110 ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 01___100 __000111 ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 01___100 __010000 ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 01___100 __010001 ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 01___100 __010011 ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 01___100 __010100 ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 01___100 __010101 ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 01___100 __010110 ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 01___100 __010111 ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 01___100 __011000 ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 01___100 __011001 ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 01___100 __011011 ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 01___100 __011100 ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 01___100 __011101 ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 01___100 __011110 ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 01___100 __011111 ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 01___100 __100000 ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 01___100 __100001 ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 01___100 __100011 ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 01___100 __100100 ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 01___100 __100101 ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 01___100 __100110 ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 01___100 __100111 ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 01___100 __101000 ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 01___100 __101001 ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 01___100 __101011 ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 01___100 __101100 ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 01___100 __101101 ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 01___100 __101110 ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 01___100 __101111 ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 01___100 __110000 ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 01___100 __110001 ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 01___100 __110011 ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 01___100 __110100 ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 01___100 __110101 ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 01___100 __110110 ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 01___100 __110111 ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 01___100 __111000 ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 01___100 __111001 ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 01___100 __111011 ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 01___100 __111100 ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 01___100 __111101 ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 01___100 __111110 ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 01___100 __111111 ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 01___100 ___0__1_ ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 01___100 __000000 ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 01___100 __000010 ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 01___100 __000011 ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 01___100 __000100 ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 01___100 __000101 ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 01___100 __000110 ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 01___100 __000111 ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 01___100 __001000 ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 01___100 __001010 ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 01___100 __001011 ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 01___100 __001100 ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 01___100 __001101 ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 01___100 __001110 ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 01___100 __001111 ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 01___100 __011000 ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 01___100 __011010 ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 01___100 __011011 ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 01___100 __011100 ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 01___100 __011101 ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 01___100 __011110 ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 01___100 __011111 ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 01___100 __100000 ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 01___100 __100010 ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 01___100 __100011 ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 01___100 __100100 ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 01___100 __100101 ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 01___100 __100110 ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 01___100 __100111 ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 01___100 __101000 ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 01___100 __101010 ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 01___100 __101011 ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 01___100 __101100 ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 01___100 __101101 ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 01___100 __101110 ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 01___100 __101111 ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 01___100 __110000 ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 01___100 __110010 ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 01___100 __110011 ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 01___100 __110100 ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 01___100 __110101 ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 01___100 __110110 ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 01___100 __110111 ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 01___100 __111000 ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 01___100 __111010 ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 01___100 __111011 ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 01___100 __111100 ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 01___100 __111101 ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 01___100 __111110 ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 01___100 __111111 ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 01___100 __001001 ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 01___100 __001001 ________"));

        assert!(c.apply_filters_to_current());

        c.filter(InstructionFilter::parse("00001111 00010111 01___100 __010010 ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 01___100 __010010 ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 011110__ ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 01_____1 ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 01_____1 ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 01____1_ ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 01____1_ ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 100000__ ________ ________ ________ ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 10___100 ___00000 ________ ________ ________ ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 10___100 ___00000 ________ ________ ________ ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 10___100 ____0__1 ________ ________ ________ ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 10___100 __000000 ________ ________ ________ ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 10___100 __000001 ________ ________ ________ ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 10___100 __000011 ________ ________ ________ ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 10___100 __000100 ________ ________ ________ ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 10___100 __000101 ________ ________ ________ ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 10___100 __000110 ________ ________ ________ ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 10___100 __000111 ________ ________ ________ ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 10___100 __010000 ________ ________ ________ ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 10___100 __010001 ________ ________ ________ ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 10___100 __010011 ________ ________ ________ ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 10___100 __010100 ________ ________ ________ ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 10___100 __010101 ________ ________ ________ ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 10___100 __010110 ________ ________ ________ ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 10___100 __010111 ________ ________ ________ ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 10___100 __011000 ________ ________ ________ ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 10___100 __011001 ________ ________ ________ ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 10___100 __011011 ________ ________ ________ ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 10___100 __011100 ________ ________ ________ ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 10___100 __011101 ________ ________ ________ ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 10___100 __011110 ________ ________ ________ ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 10___100 __011111 ________ ________ ________ ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 10___100 __100000 ________ ________ ________ ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 10___100 __100001 ________ ________ ________ ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 10___100 __100011 ________ ________ ________ ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 10___100 __100100 ________ ________ ________ ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 10___100 __100101 ________ ________ ________ ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 10___100 __100110 ________ ________ ________ ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 10___100 __100111 ________ ________ ________ ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 10___100 __101000 ________ ________ ________ ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 10___100 __101001 ________ ________ ________ ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 10___100 __101011 ________ ________ ________ ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 10___100 __101100 ________ ________ ________ ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 10___100 __101101 ________ ________ ________ ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 10___100 __101110 ________ ________ ________ ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 10___100 __101111 ________ ________ ________ ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 10___100 __110000 ________ ________ ________ ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 10___100 __110001 ________ ________ ________ ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 10___100 __110011 ________ ________ ________ ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 10___100 __110100 ________ ________ ________ ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 10___100 __110101 ________ ________ ________ ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 10___100 __110110 ________ ________ ________ ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 10___100 __110111 ________ ________ ________ ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 10___100 __111000 ________ ________ ________ ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 10___100 __111001 ________ ________ ________ ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 10___100 __111011 ________ ________ ________ ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 10___100 __111100 ________ ________ ________ ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 10___100 __111101 ________ ________ ________ ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 10___100 __111110 ________ ________ ________ ________"));
        c.filter(InstructionFilter::parse("00001111 00010111 10___100 __111111 ________ ________ ________ ________"));

        assert!(c.apply_filters_to_current());

        println!("Current = {:02X?}", c.current().bytes());

        assert_eq!(c.current(), [ 0x0F, 0x17, 0x84, 0x02 ].as_ref().into());
    }

    #[test]
    pub fn test_counter_merge() {
        let mut c = InstructionCounter::range(Instr::new(&[ 0x0F, 0xAC, 0x9C, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 ]), None);

        c.filter_nomerge(InstructionFilter::parse("00001111 10101100 10___100 ___00000 ________ ________ ________ ________ _____010"));
        c.filter_nomerge(InstructionFilter::parse("00001111 10101100 10___100 ___00000 ________ ________ ________ ________ _____0_1"));
        c.filter_nomerge(InstructionFilter::parse("00001111 10101100 10___100 ___00000 ________ ________ ________ ________ _____100"));
        c.filter_nomerge(InstructionFilter::parse("00001111 10101100 10___100 ___00000 ________ ________ ________ ________ ______01"));
        c.filter_nomerge(InstructionFilter::parse("00001111 10101100 10___100 ___00000 ________ ________ ________ ________ ______10"));
        c.filter_nomerge(InstructionFilter::parse("00001111 10101100 10___100 ___00000 ________ ________ ________ ________ _______1"));
        c.filter_nomerge(InstructionFilter::parse("00001111 1010_100 10___100 ___00000 ________ ________ ________ ________ ___0000_"));
        c.filter_nomerge(InstructionFilter::parse("00001111 10101100 10___100 ___00000 ________ ________ ________ ________ ___0001_"));
        c.filter_nomerge(InstructionFilter::parse("00001111 10101100 10___100 ___00000 ________ ________ ________ ________ ___0010_"));
        c.filter_nomerge(InstructionFilter::parse("00001111 10101100 10___100 ___00000 ________ ________ ________ ________ ___00_1_"));
        c.filter_nomerge(InstructionFilter::parse("00001111 10101100 10___100 ___00000 ________ ________ ________ ________ ___0100_"));
        c.filter_nomerge(InstructionFilter::parse("00001111 10101100 10___100 ___00000 ________ ________ ________ ________ ___0_010"));
        c.filter_nomerge(InstructionFilter::parse("00001111 10101100 10___100 ___00000 ________ ________ ________ ________ ___0_0_1"));
        c.filter_nomerge(InstructionFilter::parse("00001111 10101100 10___100 ___00000 ________ ________ ________ ________ ___0_100"));
        c.filter_nomerge(InstructionFilter::parse("00001111 10101100 10___100 ___00000 ________ ________ ________ ________ ___0__01"));
        c.filter_nomerge(InstructionFilter::parse("00001111 10101100 10___100 ___00000 ________ ________ ________ ________ ___0__10"));
        c.filter_nomerge(InstructionFilter::parse("00001111 10101100 10___100 ___00000 ________ ________ ________ ________ ___0___1"));
        c.filter_nomerge(InstructionFilter::parse("00001111 10101100 10___100 ___00000 ________ ________ ________ ________ ___1000_"));
        c.filter_nomerge(InstructionFilter::parse("00001111 10101100 10___100 ___00000 ________ ________ ________ ________ ____0010"));
        c.filter_nomerge(InstructionFilter::parse("00001111 10101100 10___100 ___00000 ________ ________ ________ ________ ____00_1"));
        c.filter_nomerge(InstructionFilter::parse("00001111 10101100 10___100 ___00000 ________ ________ ________ ________ ____0100"));
        c.filter_nomerge(InstructionFilter::parse("00001111 10101100 10___100 ___00000 ________ ________ ________ ________ ____0_01"));
        c.filter_nomerge(InstructionFilter::parse("00001111 10101100 10___100 ___00000 ________ ________ ________ ________ ____0_10"));
        c.filter_nomerge(InstructionFilter::parse("00001111 10101100 10___100 ___00000 ________ ________ ________ ________ ____0__1"));
        c.filter_nomerge(InstructionFilter::parse("00001111 10101100 10___100 ___00000 ________ ________ ________ ________ ____1000"));
        c.filter_nomerge(InstructionFilter::parse("00001111 10101100 10___100 ___00000 ________ ________ ________ ________ _____001"));
        
        assert!(c.apply_filters_to_current());

        assert_eq!(c.current(), Instr::new(&[ 0x0F, 0xAC, 0x9C, 0x01 ]));
    }


    #[test]
    pub fn test_counter_next_step4() {
        let mut c = InstructionCounter::range(Instr::new(&[ 0x03, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00 ]), None);

        c.filter(InstructionFilter::parse("00000011 10___100 00000000 ________ ________ ________ ________"));
        c.filter(InstructionFilter::parse("00000011 10___100 ___00000 ________ ________ ________ ________"));
        assert!(c.apply_filters_to_current());

        println!("Currently: {:02X?}", c.current().bytes());

        assert_eq!(c.current(), Instr::new(&[ 0x03, 0x84, 0x01 ]));
    }

    #[test]
    pub fn test_next_step5() {
        let mut c = InstructionCounter::range([ 0x43, 0xC0, 0x04, 0x05, 0x00, 0x17, 0xCB, 0x9C ].as_ref().into(), None);

        assert_eq!(c.current(), [ 0x43, 0xC0, 0x04, 0x05, 0x00, 0x17, 0xCB, 0x9C ].as_ref().into());

        c.filter(InstructionFilter::parse("01000___ 11000000 00___100 _____101 ________ ________ ________ ________ ___00000"));
        c.filter(InstructionFilter::parse("0100____ 11000000 00000100 _____101 ________ ________ ________ ________ _______1"));
        c.filter(InstructionFilter::parse("0100____ 11000000 00000100 _____101 ________ ________ ________ ________ ______1_"));
        c.filter(InstructionFilter::parse("0100____ 11000000 00000100 _____101 ________ ________ ________ ________ _____1__"));
        c.filter(InstructionFilter::parse("0100____ 11000000 00000100 _____101 ________ ________ ________ ________ ____1___"));
        c.filter(InstructionFilter::parse("0100____ 11000000 00000100 _____101 ________ ________ ________ ________ ___1____"));
        assert!(c.apply_filters_to_current());

        println!("Currently: {:02X?}", c.current().bytes());

        assert_eq!(c.current(), Instr::new(&[ 0x43, 0xC0, 0x04, 0x06 ]));
    }

    #[test]
    pub fn test_next_step6() {
        let mut c = InstructionCounter::range([ 0xC0, 0x24, 0x05, 0x00, 0x02, 0x70, 0x1A, 0x00 ].as_ref().into(), None);

        c.filter(InstructionFilter::parse("11000000 0010_100 _____101 ________ ________ ________ ________ ____0000"));
        c.filter(InstructionFilter::parse("11000000 001_0100 _____101 ________ ________ ________ ________ ___00___"));
        c.filter(InstructionFilter::parse("11000000 001_0100 _____101 ________ ________ ________ ________ ___0_000"));
        c.filter(InstructionFilter::parse("11000000 0010_100 _____101 ________ ________ ________ ________ ____1__1"));
        c.filter(InstructionFilter::parse("11000000 0010_100 _____101 ________ ________ ________ ________ ____1_1_"));
        c.filter(InstructionFilter::parse("11000000 0010_100 _____101 ________ ________ ________ ________ ____11__"));
        c.filter(InstructionFilter::parse("11000000 0010_100 _____101 ________ ________ ________ ________ ___1____"));
        assert!(c.apply_filters_to_current());

        println!("Currently: {:02X?}", c.current().bytes());

        assert_eq!(c.current(), Instr::new(&[ 0xC0, 0x24, 0x06 ]));
    }

    #[test]
    pub fn test_next_step7() {
        let mut c = InstructionCounter::range([ 0xC0, 0x2C, 0x05, 0x00, 0x05, 0xC3, 0xE4 ].as_ref().into(), None);

        c.extend(false);
        
        c.filter(InstructionFilter::parse("11000000 0010_100 _____101 ________ ________ ________ ________ ______00"));
        c.filter(InstructionFilter::parse("11000000 0010_100 _____101 ________ ________ ________ ________ _____00_"));
        c.filter(InstructionFilter::parse("11000000 0010_100 _____101 ________ ________ ________ ________ _____0_0"));
        c.filter(InstructionFilter::parse("11000000 0010_100 _____101 ________ ________ ________ ________ ____0___"));
        c.filter(InstructionFilter::parse("11000000 0010_100 _____101 ________ ________ ________ ________ ______00"));
        c.filter(InstructionFilter::parse("11000000 0010_100 _____101 ________ ________ ________ ________ _____00_"));
        c.filter(InstructionFilter::parse("11000000 0010_100 _____101 ________ ________ ________ ________ _____0_0"));
        c.filter(InstructionFilter::parse("11000000 0010_100 _____101 ________ ________ ________ ________ ______11"));
        c.filter(InstructionFilter::parse("11000000 0010_100 _____101 ________ ________ ________ ________ ______00"));
        c.filter(InstructionFilter::parse("11000000 0010_100 _____101 ________ ________ ________ ________ _____1_1"));
        c.filter(InstructionFilter::parse("11000000 001__100 _____101 ________ ________ ________ ________ _____11_"));
        assert!(c.apply_filters_to_current());

        println!("Currently: {:02X?}", c.current().bytes());

        assert_eq!(c.current(), Instr::new(&[ 0xC0, 0x2C, 0x06 ]));
    }

    #[test]
    pub fn test_next_step8() {
        let mut c = InstructionCounter::range([ 0xC0, 0xB5, 0x00, 0xA1, 0x65, 0xEF ].as_ref().into(), None);

        c.extend(false);
        
        c.filter_nomerge(InstructionFilter::parse("11000000 101_0__1 ________ ________ ________ ________ ____0___"));
        c.filter_nomerge(InstructionFilter::parse("11000000 101_0__1 ________ ________ ________ ________ ___1____"));
        c.filter_nomerge(InstructionFilter::parse("11000000 101_0__1 ________ ________ ________ ________ ____11__"));
        c.filter_nomerge(InstructionFilter::parse("11000000 101_0__1 ________ ________ ________ ________ ____1_1_"));
        c.filter_nomerge(InstructionFilter::parse("11000000 101_0__1 ________ ________ ________ ________ ____1__1"));
        c.filter_nomerge(InstructionFilter::parse("11000000 101_0__1 ________ ________ ________ ________ _____000"));
        c.filter_nomerge(InstructionFilter::parse("11000000 1011___1 ________ ________ ________ ________ ___00___"));
        assert!(c.apply_filters_to_current());

        println!("Currently: {:02X?}", c.current().bytes());

        assert_eq!(c.current(), Instr::new(&[ 0xC0, 0xB6 ]));
    }

    #[test]
    pub fn test_next_step9() {
        let mut c = InstructionCounter::range([ 0xC0, 0xB5 ].as_ref().into(), None);

        c.filter_nomerge(InstructionFilter::parse("11000000 101_0__1 ________ ________ ________ ________ ____0___"));
        c.filter_nomerge(InstructionFilter::parse("11000000 101_0__1 ________ ________ ________ ________ ___1____"));
        c.filter_nomerge(InstructionFilter::parse("11000000 101_0__1 ________ ________ ________ ________ ____11__"));
        c.filter_nomerge(InstructionFilter::parse("11000000 101_0__1 ________ ________ ________ ________ ____1_1_"));
        c.filter_nomerge(InstructionFilter::parse("11000000 101_0__1 ________ ________ ________ ________ ____1__1"));
        c.filter_nomerge(InstructionFilter::parse("11000000 101_0__1 ________ ________ ________ ________ _____000"));
        c.filter_nomerge(InstructionFilter::parse("11000000 1011___1 ________ ________ ________ ________ ___00___"));
        assert!(c.apply_filters_to_current());

        println!("Currently: {:02X?}", c.current().bytes());

        assert_eq!(c.current(), Instr::new(&[ 0xC0, 0xB6 ]));
    }

    #[test]
    pub fn test_simple_next_step_partial_mask() {
        let mut c = InstructionCounter::range([ 0x45, 0xFF, 0xA4, 0x00, 0x00, 0x00, 0x00, 0x00 ].as_ref().into(), None);

        assert_eq!(c.current(), [ 0x45, 0xFF, 0xA4, 0x00, 0x00, 0x00, 0x00, 0x00 ].as_ref().into());

        assert!(c.apply_filters_to_current());

        c.filter(InstructionFilter::new(vec! [ 
            ByteFilter::new(0b1111_0011, 0x41),
            ByteFilter::new(0xff, 0xff),
            ByteFilter::new(0b10110110, 0xA4),
            ByteFilter::new(0, 0),
            ByteFilter::new(0, 0),
            ByteFilter::new(0, 0),
            ByteFilter::new(0, 0),
        ]));

        assert!(c.apply_filters_to_current());
        
        assert_eq!(c.current(), [ 0x45, 0xFF, 0xA6 ].as_ref().into());
    }

    #[test]
    pub fn test_filter_wildcard_count() {
        assert_eq!(InstructionFilter::new(vec! [ 
            ByteFilter::new(0b1111_1001, 0b0000_0000),
            ByteFilter::new(0b0000_0000, 0),
            ByteFilter::new(0b0011_0000, 0),
        ]).num_wildcard_bits(), 16);
    }

    #[test]
    pub fn normal_tunneling() {
        let mut c = InstructionCounter::new();
        c.extend(false);
        c.extend(false);

        assert_eq!(c.current(), [ 0, 0, 0 ].as_ref().into());
        for b in 1..=255u8 {
            assert!(c.tunnel_next(200));
            assert_eq!(c.current(), [ 0, 0, b ].as_ref().into());
        }

        for b in 1..=255u8 {
            assert!(c.tunnel_next(200));
            assert_eq!(c.current(), [ 0, b, 0 ].as_ref().into());
        }

        assert!(c.tunnel_next(200));
        assert_eq!(c.current(), [ 1, 0, 0 ].as_ref().into());
        c.reduce(false);
        assert_eq!(c.current(), [ 1, 0 ].as_ref().into());

        for b in 1..=255u8 {
            assert!(c.tunnel_next(200));
            assert_eq!(c.current(), [ 1, b ].as_ref().into());
        }

        assert!(c.tunnel_next(200));
        assert_eq!(c.current(), [ 2, 0 ].as_ref().into());

        assert!(c.tunnel_next(200));
        assert_eq!(c.current(), [ 3, 0 ].as_ref().into());

        assert!(c.extend(false));
        assert_eq!(c.current(), [ 3, 0, 0 ].as_ref().into());
        for b in 1..=255u8 {
            assert!(c.tunnel_next(200));
            assert_eq!(c.current(), [ 3, 0, b ].as_ref().into());
        }
    }

    #[test]
    pub fn fast_tunneling() {
        let mut c = InstructionCounter::new();
        c.extend(false);
        c.extend(false);

        assert_eq!(c.current(), [ 0, 0, 0 ].as_ref().into());
        for b in 1..=255u8 {
            assert!(c.tunnel_next(200));
            assert_eq!(c.current(), [ 0, 0, b ].as_ref().into());
        }

        for b in 1..=255u8 {
            assert!(c.tunnel_next(200));
            assert_eq!(c.current(), [ 0, b, 0 ].as_ref().into());
        }

        assert!(c.tunnel_next(200));
        assert_eq!(c.current(), [ 1, 0, 0 ].as_ref().into());
        c.reduce(true);
        assert_eq!(c.current(), [ 1, 0 ].as_ref().into());

        for b in 2..=255u8 {
            assert!(c.tunnel_next(200));
            assert_eq!(c.current(), [ b, 0 ].as_ref().into());
        }

        assert!(!c.tunnel_next(200));
    }

    #[test]
    pub fn test_tunneling2() {
        let mut c = InstructionCounter::range(Instr::new(&[ 0x4f, 0x8e, 0x87, 0x01, 0x1d, 0xc5, 0x00 ]), None);

        for _ in 0..255 {
            assert!(c.tunnel_next(200));
        }

        assert_eq!(c.current(), [ 0x4f, 0x8e, 0x87, 0x01, 0x1d, 0xc5, 0xff ].as_ref().into());

        assert!(c.tunnel_next(200));
        assert!(c.apply_filters_to_current());
        assert_eq!(c.current(), [ 0x4f, 0x8e, 0x87, 0x01, 0x1d, 0xc6, 0x00 ].as_ref().into());

        assert!(c.tunnel_next(200));
        assert!(c.apply_filters_to_current());
        assert_eq!(c.current(), [ 0x4f, 0x8e, 0x87, 0x01, 0x1d, 0xc7, 0x00 ].as_ref().into());

        assert!(c.tunnel_next(200));
        assert!(c.apply_filters_to_current());
        assert_eq!(c.current(), [ 0x4f, 0x8e, 0x87, 0x01, 0x1d, 0xc8, 0x00 ].as_ref().into());

        assert!(c.tunnel_next(200));
        assert!(c.apply_filters_to_current());
        assert_eq!(c.current(), [ 0x4f, 0x8e, 0x87, 0x01, 0x1d, 0xc9, 0x00 ].as_ref().into());
    }

    #[test]
    pub fn test_tunnel_delay() {
        let mut c = InstructionCounter::range(Instr::new(&[ 0x44, 0xff ]), None);

        assert!(c.tunnel_next(200));

        assert_eq!(c.current(), [ 0x45 ].as_ref().into());

        assert!(c.extend(true));

        assert_eq!(c.current(), [ 0x45, 0x00 ].as_ref().into());

        assert!(c.tunnel_next(200));
        assert_eq!(c.current(), [ 0x45, 0x01 ].as_ref().into());
    }

    #[test]
    pub fn test_tunnel_no_skipping() {
        let mut c = InstructionCounter::range(Instr::new(&[ 0x45, 0xff, 0x9d ]), None);

        c.filter(InstructionFilter::new(vec![
            ByteFilter::new(0xF0, 0x40),
            ByteFilter::new(0b01111110, 0b01111110),
            ByteFilter::new(0b00000010, 0b00000010),
        ]));

        c.filter(InstructionFilter::new(vec![
            ByteFilter::new(0xF0, 0x40),
            ByteFilter::new(0b10110111, 0b10110111),
            ByteFilter::new(0b00001100, 0),
            ByteFilter::new(0, 0),
            ByteFilter::new(0, 0),
            ByteFilter::new(0, 0),
            ByteFilter::new(0, 0),
        ]));

        c.filter(InstructionFilter::new(vec![
            ByteFilter::new(0xF0, 0x40),
            ByteFilter::new(0b01111110, 0b01111110),
            ByteFilter::new(0b00100000, 0b00100000),
        ]));

        c.filter(InstructionFilter::new(vec![
            ByteFilter::new(0xF0, 0x40),
            ByteFilter::new(0b01111110, 0b01111110),
            ByteFilter::new(0b01000000, 0b01000000),
        ]));

        assert!(c.tunnel_next(200));
        println!("Current: {:02X?}", c.current().bytes());
        assert_eq!(c.current(), [ 0x46, 0x00 ].as_ref().into());
    }
}