use std::{collections::HashMap, fmt};
use arrayvec::ArrayVec;
use serde::{Serialize, Deserialize};
use std::fmt::Write;

#[derive(Copy, Clone, Serialize, Deserialize)] 
pub struct BitwiseOp {
    /// Stores a bitwise operation as a truth table. The Nth bit represents the Nth entry in the truth table, starting from [0, 0, .. for the inputs.
    ///
    /// For example, A & B as a truth table would be:
    /// A | B | Out
    /// 0 | 0 | 0
    /// 0 | 1 | 0
    /// 1 | 0 | 0
    /// 1 | 1 | 1
    ///
    /// This would be encoded by storing the bits in the 'Out' column, i.e., 0b1000.
    /// 
    /// NOTE: Using an u32 limits us to max. 5 parameters (2**5 = 32). This is fine, since 5 parameters is most likely already infeasible to enumerate (2**32 = 4 billion possibilities)
    table: u32, 
}

impl BitwiseOp {
    pub fn new(table: u32) -> Self {
        BitwiseOp {
            table,
        }
    }

    pub fn first(num_inputs: usize) -> Self { 
        let mut op = BitwiseOp::new(1);
        while !op.uses_all_parameters(num_inputs) {
            op.table += 1;
        }

        op
    }

    pub fn evaluate(&self, inputs: &[i128]) -> u64 {
        assert!(inputs.len() <= 5, "Too many inputs");

        let mut result = 0;
        let mut c = self.table;
        let mut m = 0;
        while c != 0 {
            if c & 1 == 1 {
                result |= inputs.iter()
                    .enumerate()
                    .fold(u64::MAX, |acc: u64, (index, value)| acc & if (m >> index) & 1 == 0 {
                        !(*value as u64)
                    } else {
                        *value as u64
                    });
            }

            m += 1;
            c >>= 1;
        }

        result
    }

    pub fn max_config(num_inputs: usize) -> u32 {
        ((1u64 << (1 << num_inputs)) - 1) as u32
    }

    pub fn uses_all_parameters(&self, num_inputs: usize) -> bool {
        if num_inputs <= 1 {
            return true;
        }

        let base_mask = Self::max_config(num_inputs);
        for mask in [
            0x5555_5555,
            0x3333_3333,
            0x0f0f_0f0f,
            0x00ff_00ff,
            0x0000_ffff,
        ].iter().take(num_inputs).map(|m| m & base_mask) {
            let nmask = (!mask) & base_mask;
            if (self.table & mask == 0 && self.table & nmask == nmask)
                || (self.table & mask == mask && self.table & nmask == 0) {
                return false;
            }
        }

        true
    }
}

#[derive(Copy, Clone, Debug, Serialize, Deserialize)]
pub struct ArithOp {
    /// This field determines which terms occur in the expression. 
    /// The expression is a sum of products.
    /// Each bit that is set represents a single product in that sum.
    /// If bit N (counting from 0) is set, then term (N + 1) is a product in the sum.
    /// Let's call this (N + 1) the term T. We once again interpret T as a bitsequence.
    /// If the Ith bit is set in T, then the Ith argument is one of the terms in the product.
    ///
    /// Example #1: configuration=011 splits into a T1=0b01 and a T2=0b10. T1 represents the first input, and T2 represents the second input.
    /// Therefore, this example represents the expression inputs[0] + inputs[1].
    ///
    /// Example #2: configuration=100 splits into a T=0b11. This represents inputs[0] * inputs[1], which is also the full expression.
    configuration: u64,
}

impl ArithOp {
    pub fn new(configuration: u64) -> Self {
        ArithOp {
            configuration,
        }
    }

    pub fn first(num_params: usize) -> Self {
        let mut op = Self::new(1);
        while op.parameter_usage() != (1 << num_params) - 1 {
            op.configuration += 1;
        }

        op
    }

    pub fn max_config(num_inputs: usize) -> u64 {
        1 << ((1 << num_inputs) - 1)
    }

    pub fn evaluate(&self, inputs: &[i128]) -> i128 {
        assert!(inputs.len() <= 5, "Too many inputs");

        let mut result = 0i128;
        let mut c = self.configuration;
        let mut m = 1;
        while c != 0 {
            if c & 1 == 1 {
                // bit N in m represents the fact that the Nth input is being used in this term
                result = result.wrapping_add(inputs.iter()
                    .enumerate()
                    .fold(1, |acc: i128, (index, value)| if (m >> index) & 1 == 1 {
                        acc.wrapping_mul(*value)
                    } else {
                        acc
                    }));
            }

            m += 1;
            c >>= 1;
        }

        result
    }

    pub fn parameter_usage(&self) -> u32 {
        let mut result = 0;
        let mut c = self.configuration;
        let mut m = 1;
        while c != 0 {
            if c & 1 == 1 {
                result |= m;
            }

            m += 1;
            c >>= 1;
        }

        result
    }
}

#[derive(Copy, Clone, Debug, Serialize, Deserialize)]
pub struct InputMux(pub u16);

/// Source: https://stackoverflow.com/questions/506807/creating-multiple-numbers-with-certain-number-of-bits-set
/// Returns the next (small-to-large) number that has the same number of bits set as the number x.
fn next_set_of_n_elements(x: u64) -> u64 {
    if x == 0 {
        0
    } else {
        let smallest     = x & -(x as i64) as u64;
        let ripple       = x + smallest;
        let new_smallest = ripple & -(ripple as i64) as u64;
        let ones         = ((new_smallest/smallest) >> 1) - 1;

        ripple | ones
    }
}


impl InputMux {
    pub fn new(max_params: usize) -> InputMux {
        InputMux((1 << max_params) - 1)
    }

    /// Returns true if all possibilities have been enumerated and we're back at the start
    pub fn next(&mut self, num_inputs: usize, max_params: usize) -> bool {
        debug_assert!(max_params <= num_inputs);
        debug_assert!(num_inputs < 16);

        let next = next_set_of_n_elements(self.0 as u64);
        if next >= 1 << num_inputs {
            self.0 = (1 << max_params) - 1;
            true
        } else {
            self.0 = next as u16;
            false
        }
    }

    pub fn num_params(&self) -> usize {
        self.0.count_ones() as usize
    }

    pub fn mux<'a>(&self, inputs: &[i128], output: &'a mut [i128]) -> &'a mut [i128] {
        let mut output_index = 0;
        for (bit, value) in inputs.iter().enumerate() {
            if (self.0 >> bit) & 1 == 1 {
                output[output_index] = *value;
                output_index += 1;
            }
        }

        &mut output[0..output_index]
    }

    pub fn mux_to_vec<T: Clone>(&self, inputs: &[T]) -> Vec<T> {
        let mut v = Vec::new();
        for (bit, value) in inputs.iter().enumerate() {
            if (self.0 >> bit) & 1 == 1 {
                v.push(value.clone());
            }
        }

        v
    }
}

pub struct InputConnector {
    num_inputs: usize,
    num_params: usize,
    use_mask: u16,
}

impl InputConnector {
    pub fn new(num_inputs: usize, num_consts: usize, param_kinds: &[Kind], inputs: &mut [InputMux]) -> Option<InputConnector> {
        debug_assert!(
            // Returning a const value
            num_consts == 1 && param_kinds.len() == 0 
            
            // Using the const values in a computation
            || num_consts <= param_kinds.iter().map(Kind::num_params).sum()
        );

        for (input, &kind) in inputs.iter_mut().zip(param_kinds.iter()) {
            *input = InputMux::new(kind.num_params());
        }

        let mut ic = InputConnector {
            num_inputs,
            num_params: num_inputs + num_consts,
            use_mask: 0,
        };

        ic.update_use_mask(inputs);

        if !ic.valid_state(inputs) {
            if ic.next(param_kinds, inputs) {
                return None;
            }
        }

        Some(ic)
    }

    /// Returns an InputConnector where next() will always return true.
    pub fn empty() -> InputConnector {
        InputConnector {
            num_inputs: 0,
            num_params: 0,
            use_mask: 0,
        }
    }

    pub fn internal_next(&mut self, param_kinds: &[Kind], inputs: &mut [InputMux]) -> bool {
        let mut carry = true;
        for (index, (input, &kind)) in inputs.iter_mut().zip(param_kinds.iter()).enumerate() {
            if !input.next(self.num_params + index, kind.num_params()) {
                carry = false; 
                break
            }
        }

        self.update_use_mask(inputs);
        carry
    }

    fn update_use_mask(&mut self, inputs: &[InputMux]) {
        self.use_mask = inputs.iter().fold(0, |acc, value| acc | value.0);
    }

    pub fn use_mask(&self) -> u16 {
        self.use_mask
    }

    // Returns whether all constants are connected.
    pub fn valid_state(&mut self, inputs: &[InputMux]) -> bool {
        let use_mask = self.use_mask();
        let ignore = (1 << self.num_inputs) - 1;
        let use_mask = use_mask & !ignore;
        let full_mask = (1 << (self.num_params + inputs.len() - 1)) - 1;
        let full_mask = full_mask & !ignore;

        if full_mask != use_mask {
            // Not all non-inputs are being used
            return false;
        }

        true
    }

    /// Returns true when all possiblities have been enumerated.
    pub fn next(&mut self, param_kinds: &[Kind], inputs: &mut [InputMux]) -> bool {
        loop {
            if self.internal_next(param_kinds, inputs) {
                return true;
            }

            if self.valid_state(inputs) {
                return false;
            }
        }
    }
}

#[derive(Copy, Clone, Debug, Serialize, Deserialize)]
pub struct Const(pub i128);

#[derive(Copy, Clone, Serialize, Deserialize)]
pub enum Operation {
    Bitwise(BitwiseOp),
    Arith(ArithOp),
    Divide,
    DivideFlipped,
    Shl(bool),
    Shr(bool),
    X86ParityBit,
    IsZero,
}

#[derive(Copy, Clone, Debug, Serialize, Deserialize)]
pub enum Sign {
    Unsigned,
    Signed,
}

#[derive(Copy, Clone, Debug, Serialize, Deserialize)]
pub enum Endianness {
    Little,
    Big,
}

#[derive(Copy, Clone, Debug, Serialize, Deserialize)]
pub struct Input {
    pub sign: Sign,
    pub endianness: Endianness,
    pub num_bits: usize,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Expr {
    inputs: Vec<Input>,
    consts: Vec<Const>,
    muxes: Vec<InputMux>,
    operations: Vec<Operation>,
}

fn sign_extend(v: i128, n: usize) -> i128 {
    (-1 << n) | (v & ((1 << n) - 1))
}

fn flip_endianness(v: i128, n: usize) -> i128 {
    let mut tmp = v;
    let mut acc = 0;

    for _ in 0..n / 8 {
        acc = (acc << 8) | (tmp & 0xFF);
        tmp >>= 8;
    }

    acc
}

impl Expr {
    pub fn new(inputs: Vec<Input>, consts: Vec<Const>, muxes: Vec<InputMux>, operations: Vec<Operation>) -> Self {
        Expr {
            inputs,
            consts,
            muxes,
            operations,
        }
    }

    pub fn evaluate<T: Into<i128> + Copy>(&self, inputs: &[T]) -> i128 {
        let mut data = ArrayVec::<_, 32>::new();
        for (input, &v) in self.inputs.iter().zip(inputs.iter()) {
            let mut v: i128 = v.into();

            // Correct for endianness (we assume all values are big-endian by default)
            if matches!(input.endianness, Endianness::Little) {
                v = flip_endianness(v, input.num_bits);
            }

            // Optionally use the most significant bit of the instruction as the sign bit
            let n = input.num_bits - 1;
            if matches!(input.sign, Sign::Signed) && v >> n > 0 {
                v = sign_extend(v, n);
            }

            data.push(v);
        }

        let mut muxed = [0; 8];
        for Const(c) in self.consts.iter() {
            data.push(*c);
        }

        for (op, mux) in self.operations.iter().zip(self.muxes.iter()) {
            data.push(match op {
                Operation::Bitwise(op) => op.evaluate(mux.mux(data.as_ref(), &mut muxed)) as i128,
                Operation::Arith(op) => op.evaluate(mux.mux(data.as_ref(), &mut muxed)) as i128,
                Operation::Divide => {
                    let params = mux.mux(data.as_ref(), &mut muxed);
                    params[0].checked_div(params[1]).unwrap_or(0)
                },
                Operation::DivideFlipped => {
                    let params = mux.mux(data.as_ref(), &mut muxed);
                    params[1].checked_div(params[0]).unwrap_or(0)
                },
                Operation::Shl(flipped) => {
                    let params = mux.mux(data.as_ref(), &mut muxed);
                    if *flipped {
                        params[1].checked_shl(params[0] as u32).unwrap_or(0)
                    } else {
                        params[0].checked_shl(params[1] as u32).unwrap_or(0)
                    }
                },
                Operation::Shr(flipped) => {
                    let params = mux.mux(data.as_ref(), &mut muxed);
                    if *flipped {
                        params[1].checked_shr(params[0] as u32).unwrap_or(0)
                    } else {
                        params[0].checked_shr(params[1] as u32).unwrap_or(0)
                    }
                },
                Operation::X86ParityBit => {
                    let params = mux.mux(data.as_ref(), &mut muxed);
                    ((params[0] as u8).count_ones() & 1) as i128
                }
                Operation::IsZero => {
                    let params = mux.mux(data.as_ref(), &mut muxed);
                    if params[0] == 0 {
                        1
                    } else {
                        0
                    }
                }
            });
        }

        data.pop().unwrap()
    }
}

pub struct PermutationIterator<T: Ord + Copy> {
    current: Vec<T>,
}

impl<'a, T: Ord + Copy> PermutationIterator<T> {
    pub fn new(current: &[T]) -> PermutationIterator<T> {
        let mut current = current.to_vec();
        current.sort();
        PermutationIterator {
            current,
        }
    }

    pub fn current(&self) -> &[T] {
        &self.current
    }

    /// Generates the next permutation in current
    pub fn next(&mut self) -> bool {
        if let Some((i, i2)) = self.current
            .windows(2)
            .enumerate()
            .rfind(|(_, w)| w[0] < w[1])
            .map(|(j, w)| {
                let i2 = self.current[j + 1..].iter().rposition(|x| w[0] < *x).unwrap_or(0);
                (j, i2)
            })
        {
            self.current.swap(i, i2 + i + 1);
            self.current[i + 1..].reverse();
            true
        } else {
            false
        }
    }
}

pub struct ExprEnumerator {
    expr: Expr,
    num_inputs: usize,
    input_connector: InputConnector,
    steps: Vec<Step>,
    param_counts: Vec<Kind>,
    num_consts: usize,
}

macro_rules! chain {
    ($v:ident # ($a:pat) ($b:expr); { $($arms:tt)* } | $final:expr) => {
        match $v { 
            $($arms)*
            $a => $b,
            $b => $final,
            n => panic!("Unexpected value: {:?}", n),
        }
    };
    ($v:ident # ($a:pat) ($b:expr) $(($rest:expr))*; { $($arms:tt)* } | $final:expr) => {
        chain!($v # ($b) $(($rest))*; { 
            $($arms)*
            $a => $b,
        } | $final)
    };
    ($v:ident => $($rest:expr);*; / $final:expr) => {
        chain!($v # $(($rest))*; {} | $final)
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ParamCount {
    P1,
    P2,
    P3,
    P4,
    P5,
}

impl ParamCount {
    fn value(&self) -> usize {
        match self {
            ParamCount::P1 => 1,
            ParamCount::P2 => 2,
            ParamCount::P3 => 3,
            ParamCount::P4 => 4,
            ParamCount::P5 => 5,
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Kind {
    ArithBitwise(ParamCount),
    Shift(ParamCount),
    Divide,
    Special,
}

impl Kind {
    fn num_params(&self) -> usize {
        match self {
            Kind::ArithBitwise(p) => p.value(),
            Kind::Shift(p) => p.value() + 1,
            Kind::Divide => 2,
            Kind::Special => 1,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Step(pub usize, pub Vec<Kind>);

pub fn steps() -> Vec<Step> {
    let g = StepGenerator::new();
    g.steps(true)
}

pub struct StepGenerator {
    seen: HashMap<Step, usize>,
}

impl StepGenerator {
    pub fn new() -> Self {
        StepGenerator {
            seen: HashMap::new(),
        }
    }

    pub fn add(&mut self, enumerator: &ExprEnumerator) {
        *self.seen
            .entry(Step(enumerator.num_consts, enumerator.param_counts.clone()))
            .or_insert(0) += 1;
    }

    pub fn steps(&self, single_bit: bool) -> Vec<Step> {
        let mut single_ops = Vec::new();
        for &p in &[ParamCount::P1, ParamCount::P2, ParamCount::P3, ParamCount::P4] {
            single_ops.push(Kind::ArithBitwise(p));
        }

        for &p in &[ParamCount::P1, ParamCount::P2, ParamCount::P3] {
            single_ops.push(Kind::Shift(p));
        }

        single_ops.push(Kind::Divide);

        if single_bit {
            single_ops.push(Kind::Special);
        }

        let mut ops = single_ops.iter().map(|&o| vec![ o ]).collect::<Vec<_>>();
        for _ in 0..4 {
            let new = ops.iter().flat_map(|base| single_ops.iter().map(move |&extended| {
                let mut v = base.clone();
                v.push(extended);
                v
            })).collect::<Vec<_>>();
            ops.extend(new.into_iter());
        }

        ops.push(Vec::new());

        ops.sort();
        ops.dedup();

        let mut result = (0..4)
            .flat_map(|c| ops.iter().map(move |ops| Step(c, ops.clone())))
            .collect::<Vec<_>>();

        // Only allow the parity bit computation at the end
        result.retain(|Step(c, ops)| 
            ops.iter().enumerate().all(|(index, op)| op != &Kind::Special || index == ops.len() - 1)
            && ops.iter().all(|op| op != &Kind::ArithBitwise(ParamCount::P1) || ops.len() == 1)
            && (*c == 1 || ops.len() != 0)
        );
        
        result.sort_by_cached_key(|step| {
            let Step(c, ops) = step;
            if ops.len() == 0 {
                0
            } else {
                let param_weight = ops.iter().map(|op| 1usize << op.num_params()).fold(1, |a, b| a + b);
                let score = (c + param_weight) * 10 + c + 100;
                let score = score.checked_sub(self.seen.get(step).copied().unwrap_or(0) * 5).unwrap_or(0);
                score
            }
        });

        result.reverse();

        result
    }
}

impl ExprEnumerator {
    pub fn new(input_sizes: &[usize], steps: Vec<Step>) -> Self {
        ExprEnumerator {
            num_inputs: input_sizes.len(),
            steps,
            input_connector: InputConnector::empty(),
            param_counts: vec![],
            num_consts: 0,
            expr: Expr {
                inputs: input_sizes.iter().map(|&num_bits| Input {
                    sign: Sign::Unsigned,
                    endianness: Endianness::Big,
                    num_bits, 
                }).collect(),
                consts: Vec::new(),
                muxes: Vec::new(),
                operations: Vec::new(),
            }
        }
    }

    pub fn default(input_sizes: &[usize]) -> Self {
        Self::new(input_sizes, steps())
    }

    fn next_bitwise(op: &mut BitwiseOp, num_inputs: usize) -> bool {
        // TODO: Can we enforce that all N inputs are used?
        let max = BitwiseOp::max_config(num_inputs);
        while op.table < max {
            op.table += 1;

            if op.uses_all_parameters(num_inputs) {
                break
            }
        }

        op.table >= max
    }

    fn next_arith(op: &mut ArithOp, num_inputs: usize) -> bool {
        let max = ArithOp::max_config(num_inputs);

        while op.configuration < max {
            op.configuration += 1;

            // Enforce that all inputs are used
            if op.parameter_usage() as usize == (1 << num_inputs) - 1 {
                break
            }
        }
        op.configuration >= max
    }

    fn next_input(i: &mut Input) -> bool {
        let Input {
            sign,
            endianness,
            ..
        } = i;

        match (*sign, *endianness) {
            (Sign::Unsigned, Endianness::Big) => {
                *sign = Sign::Signed;
            },
            (Sign::Signed, Endianness::Big) => {
                *sign = Sign::Unsigned;
                if i.num_bits % 8 == 0 {
                    *endianness = Endianness::Little;
                } else {
                    // endianness only makes sense if we can split the input into bytes
                    return true;
                }
            },
            (Sign::Unsigned, Endianness::Little) => {
                *sign = Sign::Signed;
            },
            (Sign::Signed, Endianness::Little) => {
                *sign = Sign::Unsigned;
                *endianness = Endianness::Big;

                return true;
            },
        }
        
        false
    }

    fn next_const(c: &mut Const) -> bool {
        let Const(c) = c;
        let v = *c;
        *c = chain! {
            v => 
            // Everything between 0-15 for instruction byte lengths
            0; -1; 1; 2; 3; 4; 5; 6; 7; 8; 9; 10; 11; 12; 13; 14; 15;
            // Only every 8 (=1 byte) for 16 and up
            16; 24; 32; 40; 48; 56; 64;
            // Common bitmasks that we have missed so far
            31; 63;
            / {
                *c = 0;
                return true;
            }
        };

        false
    }

    fn next_operation(op: &mut Operation, params: usize) -> bool {
        match op {
            Operation::Bitwise(bop) => {
                if Self::next_bitwise(bop, params) {
                    if params <= 1 {
                        // For 1 parameter, doing arithmetic operations makes no sense so we just reset immediately
                        *op = Operation::Bitwise(BitwiseOp::first(params));
                        return true;
                    } else {
                        *op = Operation::Arith(ArithOp::first(params));
                    }
                }
            }
            Operation::Arith(aop) => {
                if Self::next_arith(aop, params) {
                    *op = Operation::Bitwise(BitwiseOp::first(params));
                    return true;
                }
            }
            Operation::Shl(flipped) => {
                if !*flipped {
                    *flipped = true;
                } else {
                    *op = Operation::Shr(false);
                }
            }
            Operation::Shr(flipped) => {
                if !*flipped {
                    *flipped = true;
                } else {
                    *op = Operation::Shl(false);
                    return true;
                }
            }
            Operation::Divide => *op = Operation::DivideFlipped,
            Operation::DivideFlipped => {
                *op = Operation::Divide;
                return true;
            }
            Operation::X86ParityBit => {
                *op = Operation::IsZero;
            }
            Operation::IsZero => {
                return true;
            }
        }

        false
    }
    
    fn next_permutation(&mut self) {
        loop {
            let current = self.steps.pop().unwrap();

            self.num_consts = current.0;
            self.param_counts = current.1;

            let enough_inputs = self.param_counts.iter()
                .enumerate()
                .all(|(index, kind)| index + self.num_inputs + self.num_consts >= kind.num_params());

            if enough_inputs {
                break
            }
        }
    }

    fn kind_to_op(kind: Kind) -> Operation {
        match kind {
            Kind::ArithBitwise(_) => Operation::Bitwise(BitwiseOp::first(kind.num_params())),
            Kind::Shift(_) => Operation::Shl(false),
            Kind::Divide => Operation::Divide,
            Kind::Special => Operation::X86ParityBit,
        }
    }

    pub fn next(&mut self) -> &Expr {
        let use_mask = self.input_connector.use_mask();
        let mut carry = true;
        for (index, i) in self.expr.inputs.iter_mut().enumerate() {
            // Only iterate over input kinds if it is actually being used in the computation
            if (use_mask >> index) & 1 == 1 {
                carry = Self::next_input(i);
                if !carry {
                    break
                }
            }
        }

        if carry {
            for (index, c) in self.expr.consts.iter_mut().enumerate() {
                carry = Self::next_const(c);
                if !carry {
                    let value = *c;
                    for c in self.expr.consts.iter_mut().take(index) {
                        *c = value;
                    }

                    break
                }
            }

            if carry {
                for (operation, &kind) in self.expr.operations.iter_mut()
                    .zip(&self.param_counts) {
                    carry = Self::next_operation(operation, kind.num_params());
                    if !carry { 
                        break
                    }
                }

                if carry {
                    if self.input_connector.next(&self.param_counts, &mut self.expr.muxes) {
                        loop {
                            self.next_permutation();
                            self.expr.consts.clear();
                            self.expr.operations.clear();
                            self.expr.muxes.clear();

                            for _ in 0..self.num_consts {
                                self.expr.consts.push(Const(0));
                            }

                            for &kind in self.param_counts.iter() {
                                self.expr.muxes.push(InputMux::new(kind.num_params()));
                                self.expr.operations.push(Self::kind_to_op(kind));
                            }

                            // If there are no valid input connections, new() returns None, in which case we should move to the next entry immediately
                            if let Some(ic) = InputConnector::new(self.num_inputs, self.num_consts, &self.param_counts, &mut self.expr.muxes) {
                                self.input_connector = ic;
                                break
                            }
                        }
                    }
                }
            }
        }

        &self.expr
    }
}

impl fmt::Debug for ExprEnumerator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} inputs; {:2?}; {:?}", self.expr.inputs.len(), self.expr.consts, &self.param_counts)
    }
}

pub struct ExprWithNumParams<'a, S: AsRef<str>> {
    expr: &'a Expr,
    input_names: &'a [S]
}

const DEFAULT_NAMES: &[&str] = &[
    "A", 
    "B", 
    "C", 
    "D", 
    "E", 
    "F", 
    "G", 
    "H", 
    "J", 
    "K", 
    "L", 
    "M", 
    "N",
];

impl Expr {
    pub fn display<'a>(&'a self) -> ExprWithNumParams<'a, &str> {
        self.display_with_names(DEFAULT_NAMES)
    }

    pub fn display_with_names<'a, S: AsRef<str>>(&'a self, input_names: &'a [S]) -> ExprWithNumParams<'a, S> {
        ExprWithNumParams {
            expr: self,
            input_names,
        }
    }
}

impl fmt::Debug for Expr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self.display())
    }
}

impl<S: AsRef<str>> fmt::Debug for ExprWithNumParams<'_, S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut list = f.debug_list();

        let params = [ "a", "b", "c", "d", "e", "f", "g", "h", "j", "k", "l", "m", "n", "p", "q" ].iter()
            .map(|s| s.to_string())
            .collect::<Vec<_>>();

        list.entry(&self.expr.inputs);
        list.entry(&self.expr.consts);
        list.entry(&self.expr.muxes);

        for (op, input) in self.expr.operations.iter().zip(self.expr.muxes.iter()) {
            let params = params.iter().take(input.num_params()).collect::<Vec<_>>();
            list.entry(&op.display(params));
        }

        list.finish()
    }
}

impl<S: AsRef<str>> fmt::Display for ExprWithNumParams<'_, S> {
    fn fmt<'a>(&'a self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut v = Vec::new();
        for (input, name) in self.expr.inputs.iter()
            .zip(self.input_names.iter().map(|s| s.as_ref())) {
            let mut s = String::new();
            s.push_str(name);

            match input.sign {
                Sign::Unsigned => s.push_str("u"),
                Sign::Signed => s.push_str("i"),
            }

            write!(&mut s, "{}", input.num_bits).ok();

            match input.endianness {
                Endianness::Little => s.push_str("_le"),
                Endianness::Big => s.push_str("_be"),
            }

            v.push(s);
        }

        for c in self.expr.consts.iter() {
            v.push(format!("{}", c.0));
        }
        
        for (op, mux) in self.expr.operations.iter().zip(self.expr.muxes.iter()) {
            let params = v.iter().collect::<Vec<_>>();
            let s = format!("{}", op.display(mux.mux_to_vec(&params)));
            v.push(s);
        }

        write!(f, "{}", v[v.len() - 1])
    }
}

pub struct OperationWithNumParams<'a> {
    inner: &'a Operation,
    params: Vec<&'a String>,
}

impl Operation {
    pub fn display<'a>(&'a self, params: Vec<&'a String>) -> OperationWithNumParams<'a> {
        OperationWithNumParams {
            inner: self,
            params,
        }
    }
}

impl fmt::Debug for OperationWithNumParams<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.inner {
            Operation::Bitwise(op) => {
                write!(f, "{:b}: {:?}", op.table, op.display(self.params.clone()))?;
            },
            Operation::Arith(op) => {
                write!(f, "{:b}: {:?}", op.configuration, op.display(self.params.clone()))?;
            },
            Operation::Divide => {
                write!(f, "({} / {})", self.params[0], self.params[1])?;
            },
            Operation::DivideFlipped => {
                write!(f, "({} / {})", self.params[1], self.params[0])?;
            },
            Operation::Shl(flipped) => {
                if *flipped {
                    write!(f, "({} << {})", self.params[1], self.params[0])?;
                } else {
                    write!(f, "({} << {})", self.params[0], self.params[1])?;
                }
            },
            Operation::Shr(flipped) => {
                if *flipped {
                    write!(f, "({} >> {})", self.params[1], self.params[0])?;
                } else {
                    write!(f, "({} >> {})", self.params[0], self.params[1])?;
                }
            },
            Operation::X86ParityBit => {
                write!(f, "Parity({})", self.params[0])?;
            },
            Operation::IsZero => {
                write!(f, "IsZero({})", self.params[0])?;
            },
        }

        Ok(())
    }
}

impl fmt::Display for OperationWithNumParams<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.inner {
            Operation::Bitwise(op) => {
                write!(f, "({})", op.display(self.params.clone()))?;
            },
            Operation::Arith(op) => {
                write!(f, "({})", op.display(self.params.clone()))?;
            },
            Operation::Divide => {
                write!(f, "({} / {})", self.params[0], self.params[1])?;
            },
            Operation::DivideFlipped => {
                write!(f, "({} / {})", self.params[1], self.params[0])?;
            },
            Operation::Shl(flipped) => {
                if *flipped {
                    write!(f, "({} << {})", self.params[1], self.params[0])?;
                } else {
                    write!(f, "({} << {})", self.params[0], self.params[1])?;
                }
            },
            Operation::Shr(flipped) => {
                if *flipped {
                    write!(f, "({} >> {})", self.params[1], self.params[0])?;
                } else {
                    write!(f, "({} >> {})", self.params[0], self.params[1])?;
                }
            },
            Operation::X86ParityBit => {
                write!(f, "Parity({})", self.params[0])?;
            },
            Operation::IsZero => {
                write!(f, "IsZero({})", self.params[0])?;
            },
        }

        Ok(())
    }
}

pub struct BitwiseOpWithNumParams<'a> {
    inner: &'a BitwiseOp,
    params: Vec<&'a String>,
}

impl BitwiseOp {
    pub fn display<'a>(&'a self, params: Vec<&'a String>) -> BitwiseOpWithNumParams<'a> {
        BitwiseOpWithNumParams {
            inner: self,
            params,
        }
    }
}

impl fmt::Debug for BitwiseOpWithNumParams<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match (self.inner.table, &self.params[..]) {
            // Some shorthands for some common operators
            (0b0110, [a, b]) => write!(f, "{} ^ {}", a, b)?,
            (0b1001, [a, b]) => write!(f, "!{} ^ !{}", a, b)?,
            (table, _) => {
                let max = 1 << self.params.len();
                let num = table.count_ones();
                let (negate_full, table) = if num * 2 > max {
                    (true, (!table) & BitwiseOp::max_config(self.params.len()))
                } else {
                    (false, table)
                };
        
                // if negate_full {
                //     write!(f, "!(")?;
                // }

                let need_inner_brackets = table.count_ones() > 1;
         
                let mut first = true;
                for lookup in 0..(1u64 << self.params.len()) {
                    let value = table.checked_shr(lookup as u32).unwrap_or(0) & 1;
        
                    if value != 0 {
                        if !first {
                            write!(f, "{}", if negate_full {
                                " & "
                            } else {
                                " | "
                            })?;
                        }
        
                        first = false;
        
                        if need_inner_brackets {
                            write!(f, "(")?;
                        }

                        for index in 0..self.params.len() {
                            if index != 0 {
                                write!(f, "{}", if negate_full {
                                    " | "
                                } else {
                                    " & "
                                })?;
                            }
        
                            if (lookup >> index) & 1 == 0 && !negate_full {
                                write!(f, "!")?;
                            } else if (lookup >> index) & 1 == 1 && negate_full {
                                write!(f, "!")?;
                            }
        
                            write!(f, "{}", self.params[index])?;
                        }

                        if need_inner_brackets {
                            write!(f, ")")?;
                        }
                    }
                }
        
                // if negate_full {
                //     write!(f, ")")?;
                // }
            }
        }
        Ok(())
    }
}

impl fmt::Display for BitwiseOpWithNumParams<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        <Self as fmt::Debug>::fmt(self, f)
    }
}

pub struct ArithOpWithNumParams<'a> {
    inner: &'a ArithOp,
    params: Vec<&'a String>,
}

impl ArithOp {
    pub fn display<'a>(&'a self, params: Vec<&'a String>) -> ArithOpWithNumParams<'a> {
        ArithOpWithNumParams {
            inner: self,
            params,
        }
    }
}

impl fmt::Debug for ArithOpWithNumParams<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut first = true;
        for bit in 0..64 {
            if (self.inner.configuration >> bit) & 1 == 1 {
                // bit N in m represents the fact that the Nth input is being used in this term
                let m = bit + 1;
                if !first {
                    write!(f, " + ")?;
                }

                first = false;

                let mut first_mul = true;
                for index in 0..self.params.len() {
                    if (m >> index) & 1 == 1 {
                        if first_mul {
                            first_mul = false;
                        } else {   
                            write!(f, " * ")?;
                        }
    
                        write!(f, "{}", self.params[index])?;
                    }
                }
            }
        }

        Ok(())
    }
}

impl fmt::Display for ArithOpWithNumParams<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        <Self as fmt::Debug>::fmt(self, f)
    }
}

#[allow(unused)]
#[cfg(test)]
mod tests {
    use rand::Rng;
    use crate::gen::{Step, StepGenerator};

    use super::{ArithOp, BitwiseOp, Expr, ExprEnumerator, InputMux, Operation, PermutationIterator, Const, Input, Sign, Endianness};

    fn can_find_examples(g: &mut StepGenerator, input_sizes: &[usize], cases: &[(&[i128], u64)]) -> bool {
        let mut e = ExprEnumerator::new(input_sizes, g.steps(true));
        for n in 0..100_000_000_000u64 {
            if n % 50_000_000 == 0 {
                println!("Evaluated: {}M ({:?})", n / 1_000_000, e);
            }

            let expr = e.next();
            if cases.iter().all(|(inputs, result)| {
                let v = expr.evaluate(inputs);
                
                v as u64 == *result
            }) {
                println!("Found @ {}: {} | {:#?}", n, expr.display(), expr.display());
                g.add(&e);
                return true;
            }
        }

        false
    }

    fn can_find_fn(g: &mut StepGenerator, input_sizes: &[usize], f: impl Fn(&[u64]) -> u64) -> bool {
        let mut cases = Vec::new();
        let mut rng = rand::thread_rng();
        for _ in 0..10000 {
            let inputs = (0..input_sizes.len()).map(|_| rng.gen()).collect::<Vec<_>>();
            let output = f(&inputs);

            cases.push((inputs.into_iter().map(|i| i as i128).collect::<Vec<_>>(), output));
        }
        
        let cases = cases.iter().map(|(inputs, output)| (&inputs[..], *output)).collect::<Vec<_>>();
        can_find_examples(g, input_sizes, &cases)
    }

    #[test]
    pub fn bitwise_evaluate() {
        let and = BitwiseOp::new(0b1000);
        let or = BitwiseOp::new(0b1110);
        let xor = BitwiseOp::new(0b0110);

        assert_eq!(and.evaluate(&[ 0x33, 0x55 ]), 0x11);
        assert_eq!(or.evaluate(&[ 0x33, 0x55 ]), 0x77);
        assert_eq!(xor.evaluate(&[ 0x33, 0x55 ]), 0x66);

        let and3 = BitwiseOp::new(0b10000000);
        assert_eq!(and3.evaluate(&[ 0x33, 0x55, 0xf0 ]), 0x10);
    }

    #[test]
    pub fn bitwise_parameter_usage() {
        let neg = BitwiseOp::new(0b1);
        assert!(neg.uses_all_parameters(1));

        let useless = BitwiseOp::new(0b1100);
        assert!(!useless.uses_all_parameters(2));

        let id = BitwiseOp::new(0b10);
        assert!(id.uses_all_parameters(1));

        let and = BitwiseOp::new(0b1000);
        assert!(and.uses_all_parameters(2));

        let or = BitwiseOp::new(0b1110);
        assert!(or.uses_all_parameters(2));
        
        let xor = BitwiseOp::new(0b0110);
        assert!(xor.uses_all_parameters(2));

        let and3 = BitwiseOp::new(0b10000000);
        assert!(and3.uses_all_parameters(3));
    }

    #[test]
    pub fn arith_evaluate() {
        let add = ArithOp::new(0b011);
        let madd1 = ArithOp::new(0b100001);
        let madd2 = ArithOp::new(0b001100);

        assert_eq!(add.evaluate(&[ 0x33, 0x55 ]), 0x88);
        assert_eq!(add.evaluate(&[ 0xff, 0x01 ]), 0x100);
        assert_eq!(madd1.evaluate(&[ 0x15, 0x43, 0x17 ]), 0x15 + (0x43 * 0x17));
        assert_eq!(madd2.evaluate(&[ 0x15, 0x43, 0x17 ]), (0x15 * 0x43) + 0x17);
    }

    #[test]
    pub fn arith_parameter_usage() {
        let id = ArithOp::new(0b1);
        assert_eq!(id.parameter_usage(), 0b1);

        let add = ArithOp::new(0b011);
        assert_eq!(add.parameter_usage(), 0b11);

        let madd1 = ArithOp::new(0b100001);
        assert_eq!(madd1.parameter_usage(), 0b111);

        let madd2 = ArithOp::new(0b001100);
        assert_eq!(madd2.parameter_usage(), 0b111);
    }

    #[test]
    pub fn expr_ror() {
        let rol = Expr::new(vec![
            Input {
                sign: Sign::Unsigned,
                endianness: Endianness::Big,
                num_bits: 64,
            },
            Input {
                sign: Sign::Unsigned,
                endianness: Endianness::Big,
                num_bits: 64,
            },
        ], vec! [
            // 0: value
            // 1: rotate amount
            Const(-1), // 2
            Const(64), // 3
        ], vec![
            InputMux(0b11),
            InputMux(0b1110),
            InputMux(0b100001),
            InputMux(0b1010000),
        ], vec![
            Operation::Shl(false), // 4
            Operation::Arith(ArithOp::new(0b1100)), // 5
            Operation::Shr(false), // 6
            Operation::Bitwise(BitwiseOp::new(0b1110)) // 7, result
        ]);

        println!("{}", rol.display());
        println!("{:?}", rol.display());

        assert_eq!(rol.evaluate::<u64>(&[ 0x1122334455667788, 24 ]) as u64, 0x4455667788112233);
        assert_eq!(rol.evaluate::<u64>(&[ 0x1122334455667788, 20 ]) as u64, 0x3445566778811223);
        assert_eq!(rol.evaluate::<u64>(&[ 0x0123456789ABCDEF, 20 ]) as u64, 0x56789ABCDEF01234);
    }


    #[test]
    pub fn expr_sign_extend() {
        let sign_extend = Expr::new(vec![
            Input {
                sign: Sign::Signed,
                endianness: Endianness::Big,
                num_bits: 8,
            },
        ], vec! [ ], vec![
            InputMux(0b1),
        ], vec![
            Operation::Arith(ArithOp::new(0b1))
        ]);

        println!("{}", sign_extend.display());
        println!("{:?}", sign_extend.display());

        assert_eq!(sign_extend.evaluate::<u64>(&[ 0xff ]) as u64, 0xffffffff_ffffffff);
        assert_eq!(sign_extend.evaluate::<u64>(&[ 0x80 ]) as u64, 0xffffffff_ffffff80);
        assert_eq!(sign_extend.evaluate::<u64>(&[ 0x11 ]) as u64, 0x11);
    }

    #[test]
    pub fn permutations() {
        let mut p = PermutationIterator::new(&[ 1, 4, 2, 2 ]);

        assert_eq!(p.current(), &[ 1, 2, 2, 4 ]);

        assert!(p.next());
        assert_eq!(p.current(), &[ 1, 2, 4, 2 ]);

        assert!(p.next());
        assert_eq!(p.current(), &[ 1, 4, 2, 2 ]);

        assert!(p.next());
        assert_eq!(p.current(), &[ 2, 1, 2, 4 ]);

        assert!(p.next());
        assert_eq!(p.current(), &[ 2, 1, 4, 2 ]);

        assert!(p.next());
        assert_eq!(p.current(), &[ 2, 2, 1, 4 ]);

        assert!(p.next());
        assert_eq!(p.current(), &[ 2, 2, 4, 1 ]);

        assert!(p.next());
        assert_eq!(p.current(), &[ 2, 4, 1, 2 ]);

        assert!(p.next());
        assert_eq!(p.current(), &[ 2, 4, 2, 1 ]);

        assert!(p.next());
        assert_eq!(p.current(), &[ 4, 1, 2, 2 ]);

        assert!(p.next());
        assert_eq!(p.current(), &[ 4, 2, 1, 2 ]);

        assert!(p.next());
        assert_eq!(p.current(), &[ 4, 2, 2, 1 ]);

        assert!(!p.next());
    }

    #[test]
    pub fn enumerates_at_least_10_000_000_params_1() {
        let mut e = ExprEnumerator::new(&[ 64 ], super::steps());
        for _ in 0..10_000_000u64 {
            let expr = e.next();
            println!("Expr: {}", expr.display());
        }
    }

    #[test]
    pub fn enumerates_at_least_10_000_000_params_2() {
        let mut e = ExprEnumerator::new(&[ 64, 64 ], super::steps());
        for _ in 0..10_000_000u64 {
            let expr = e.next();
            println!("Expr: {}", expr.display());
        }
    }

    #[test]
    pub fn enumerates_at_least_10_000_000_params_3() {
        let mut e = ExprEnumerator::new(&[ 64, 64, 64 ], super::steps());
        for _ in 0..10_000_000u64 {
            let expr = e.next();
            println!("Expr: {}", expr.display());
        }
    }

    #[test]
    pub fn enumerate_2_021() {
        use super::Kind::*;
        use super::ParamCount::*;
        let mut e = ExprEnumerator::new(&[ 64, 64, 64 ], vec![Step(2, vec![ Shift(P2), Shift(P1), ArithBitwise(P2) ])]);
        for _ in 0..200_000_000u64 {
            let expr = e.next();
        }
    }

    #[test]
    pub fn enumerate_1_02() {
        use super::Kind::*;
        use super::ParamCount::*;
        let mut e = ExprEnumerator::new(&[ 64 ], vec![Step(1, vec![ ArithBitwise(P2), ArithBitwise(P2) ])]);
        for _ in 0..20_000_000u64 {
            let expr = e.next();
            println!("Expr: {}", expr.display());
        }
    }

    #[test]
    pub fn enumerate_2_3() {
        use super::Kind::*;
        use super::ParamCount::*;
        let mut e = ExprEnumerator::new(&[ 64 ], vec![Step(2, vec![ ArithBitwise(P3) ])]);
        for _ in 0..20_000_000u64 {
            let expr = e.next();
            println!("Expr: {}", expr.display());
        }
    }

    #[test]
    pub fn const_sub() {
        let mut g = StepGenerator::new();

        // Needed to synthesize a + [1/2/4/8]*b for memory accesses
        assert!(can_find_fn(&mut g, &[ 64 ], |x| x[0].wrapping_sub(1)));
        assert!(can_find_fn(&mut g, &[ 64 ], |x| x[0].wrapping_sub(2)));
        assert!(can_find_fn(&mut g, &[ 64 ], |x| x[0].wrapping_sub(3)));

        assert!(can_find_fn(&mut g, &[ 64 ], |x| (x[0] & 3).wrapping_sub(3)));

        assert!(can_find_fn(&mut g, &[ 64 ], |x| x[0] - 14));
        assert!(can_find_fn(&mut g, &[ 64 ], |x| (x[0] & 15) - 14));
    }

    #[test]
    pub fn const_sub_complex() {
        let mut g = StepGenerator::new();

        // Needed to synthesize a + [1/2/4/8]*b for memory accesses
        assert!(can_find_fn(&mut g, &[ 64, 64, 64 ], |x| x[2].wrapping_sub(1)));
        assert!(can_find_fn(&mut g, &[ 64, 64, 64 ], |x| x[2].wrapping_sub(2)));
        assert!(can_find_fn(&mut g, &[ 64, 64, 64 ], |x| x[2].wrapping_sub(3)));

        // Complexer set in case the bit size is bigger
        assert!(can_find_fn(&mut g, &[ 64, 64, 64 ], |x| (x[2] & 3).wrapping_sub(0)));
        assert!(can_find_fn(&mut g, &[ 64, 64, 64 ], |x| (x[2] & 3).wrapping_sub(1)));
        assert!(can_find_fn(&mut g, &[ 64, 64, 64 ], |x| (x[2] & 3).wrapping_sub(2)));
        assert!(can_find_fn(&mut g, &[ 64, 64, 64 ], |x| (x[2] & 3).wrapping_sub(3)));
    }


    #[test]
    pub fn match_fn_zex_arith() {
        let mut g = StepGenerator::new();

        // Constant offsets
        assert!(can_find_fn(&mut g, &[ 64 ], |x| (x[0] - 1) & 0xffffffff));
        assert!(can_find_fn(&mut g, &[ 64 ], |x| (x[0] + 1) & 0xffffffff));
        assert!(can_find_fn(&mut g, &[ 64 ], |x| (x[0] + 2) & 0xffffffff));
        assert!(can_find_fn(&mut g, &[ 64 ], |x| (x[0] + 3) & 0xffffffff));
        assert!(can_find_fn(&mut g, &[ 64 ], |x| (x[0] + 4) & 0xffffffff));

        // Simple math
        assert!(can_find_fn(&mut g, &[ 64 ], |x| ((x[0] as i64 * -1) as u64) & 0xffffffff));
        assert!(can_find_fn(&mut g, &[ 64, 64 ], |x| (x[0] + x[1]) & 0xffffffff));
        assert!(can_find_fn(&mut g, &[ 64, 64 ], |x| (x[0] - x[1]) & 0xffffffff));
        assert!(can_find_fn(&mut g, &[ 64, 64 ], |x| (x[0] * x[1]) & 0xffffffff));
        assert!(can_find_fn(&mut g, &[ 64, 64 ], |x| (x[0].wrapping_shr(x[1] as u32)) & 0xffffffff));
        assert!(can_find_fn(&mut g, &[ 64, 64 ], |x| (x[0].wrapping_shl(x[1] as u32)) & 0xffffffff));
        assert!(can_find_fn(&mut g, &[ 64, 64 ], |x| (x[0].wrapping_shl(x[1] as u32 & 63)) & 0xffffffff));
    }

    #[test]
    pub fn match_fn_rotate_arith() {
        let mut g = StepGenerator::new();

        // TODO: This takes too long, can we speed it up?
        assert!(can_find_fn(&mut g, &[ 64, 64 ], |x| x[0].rotate_left(x[1] as u32)));
        assert!(can_find_fn(&mut g, &[ 64, 64 ], |x| x[0].rotate_right(x[1] as u32)));
    }

    #[test]
    pub fn match_fn_arith() {
        let mut g = StepGenerator::new();

        // Constant offsets (i.e, usually for instruction length)
        assert!(can_find_fn(&mut g, &[ 64 ], |x| x[0] - 1));
        assert!(can_find_fn(&mut g, &[ 64 ], |x| x[0] + 1));
        assert!(can_find_fn(&mut g, &[ 64 ], |x| x[0] + 2));
        assert!(can_find_fn(&mut g, &[ 64 ], |x| x[0] + 3));
        assert!(can_find_fn(&mut g, &[ 64 ], |x| x[0] + 4));
        assert!(can_find_fn(&mut g, &[ 64 ], |x| x[0] + 5));
        assert!(can_find_fn(&mut g, &[ 64 ], |x| x[0] + 6));
        assert!(can_find_fn(&mut g, &[ 64 ], |x| x[0] + 7));
        assert!(can_find_fn(&mut g, &[ 64 ], |x| x[0] + 8));
        assert!(can_find_fn(&mut g, &[ 64 ], |x| x[0] + 9));
        assert!(can_find_fn(&mut g, &[ 64 ], |x| x[0] + 10));
        assert!(can_find_fn(&mut g, &[ 64 ], |x| x[0] + 11));
        assert!(can_find_fn(&mut g, &[ 64 ], |x| x[0] + 12));
        assert!(can_find_fn(&mut g, &[ 64 ], |x| x[0] + 13));
        assert!(can_find_fn(&mut g, &[ 64 ], |x| x[0] + 14));
        assert!(can_find_fn(&mut g, &[ 64 ], |x| x[0] + 15));

        // Simple math
        assert!(can_find_fn(&mut g, &[ 64 ], |x| (x[0] as i64 * -1) as u64));
        assert!(can_find_fn(&mut g, &[ 64, 64 ], |x| x[0].wrapping_add(x[1])));
        assert!(can_find_fn(&mut g, &[ 64, 64 ], |x| x[0].wrapping_sub(x[1])));
        assert!(can_find_fn(&mut g, &[ 64, 64 ], |x| x[0].wrapping_mul(x[1])));
        assert!(can_find_fn(&mut g, &[ 64, 64 ], |x| x[0].wrapping_shr(x[1] as u32)));
        assert!(can_find_fn(&mut g, &[ 64, 64 ], |x| x[0].wrapping_shl(x[1] as u32)));
        assert!(can_find_fn(&mut g, &[ 64, 64 ], |x| x[0].wrapping_shl(x[1] as u32 & 63)));
        assert!(can_find_fn(&mut g, &[ 64, 64 ], |x| ((x[0] as u128 * x[1] as u128) >> 64) as u64)); // upper 64 bits of a 64x64 bit multiplication

        // Bitwise operations
        assert!(can_find_fn(&mut g, &[ 64, 64 ], |x| x[0] ^ ((1u64).wrapping_shl(x[1] as u32)))); // toggle bit
        assert!(can_find_fn(&mut g, &[ 64, 64 ], |x| x[0] & !((1u64).wrapping_shl(x[1] as u32)))); // clear bit
        assert!(can_find_fn(&mut g, &[ 64, 64 ], |x| x[0] | ((1u64).wrapping_shl(x[1] as u32)))); // set bit
        assert!(can_find_fn(&mut g, &[ 64, 64 ], |x| x[0].wrapping_shr(x[1] as u32) & 1)); // test bit

        assert!(can_find_fn(&mut g, &[ 64 ], |x| !x[0]));
        assert!(can_find_fn(&mut g, &[ 64, 64 ], |x| x[0] & x[1]));
        assert!(can_find_fn(&mut g, &[ 64, 64 ], |x| x[0] | x[1]));
        assert!(can_find_fn(&mut g, &[ 64, 64 ], |x| x[0] ^ x[1]));
        assert!(can_find_fn(&mut g, &[ 64, 64 ], |x| x[0] & !x[1]));

        // Mixed computation
        assert!(can_find_fn(&mut g, &[ 64 ], |x| x[0] & (x[0] as i64 * -1) as u64)); // blsi
        assert!(can_find_fn(&mut g, &[ 64 ], |x| x[0] ^ x[0].wrapping_sub(1))); // blsmsk
        assert!(can_find_fn(&mut g, &[ 64 ], |x| x[0] & x[0].wrapping_sub(1))); // blsr
        assert!(can_find_fn(&mut g, &[ 64, 64 ], |x| x[0] & ((1u64).wrapping_shl(x[0] as u32) - 1))); // bzhi

        // Memory address calculations
        assert!(can_find_fn(&mut g, &[ 64, 64, 64 ], |x| x[0] + x[1] * 1 + x[2]));
        assert!(can_find_fn(&mut g, &[ 64, 64, 64 ], |x| x[0] + x[1] * 2 + x[2]));
        assert!(can_find_fn(&mut g, &[ 64, 64, 64 ], |x| x[0] + x[1] * 4 + x[2]));
        assert!(can_find_fn(&mut g, &[ 64, 64, 64 ], |x| x[0] + x[1] * 8 + x[2]));
    }

    #[test]
    pub fn sign_extend() {
        assert_eq!(super::sign_extend(0xff, 7) as u64, 0xffffffff_ffffffff);
        assert_eq!(super::sign_extend(0x80, 7) as u64, 0xffffffff_ffffff80);
        assert_eq!(super::sign_extend(0xc3, 7) as u64, 0xffffffff_ffffffc3);
    }

    #[test]
    pub fn flip_endianness() {
        assert_eq!(super::flip_endianness(0x11223344, 32), 0x44332211);
        assert_eq!(super::flip_endianness(0x1122334455667788, 64), 0x8877665544332211);
    }

    #[test]
    pub fn match_arith() {
        let mut g = StepGenerator::new();

        // sign extension
        assert!(can_find_examples(&mut g, &[ 8 ], &[
            (&[ 0xff ], 0xffffffff_ffffffff),
            (&[ 0x7f ], 0x7f),
            (&[ 0x12 ], 0x12),
            (&[ 0x80 ], 0xffffffff_ffffff80),
            (&[ 0x88 ], 0xffffffff_ffffff88),
        ]));

        // endianness
        assert!(can_find_examples(&mut g, &[ 64 ], &[
            (&[ 0xaabbccddeeff0011 ], 0x1100ffeeddccbbaa),
        ]));

        // a + b
        assert!(can_find_examples(&mut g, &[ 64, 64 ], &[
            (&[ 0x55, 0x33 ], 0x88),
            (&[ 123, 123000 ], 123123),
            (&[ 1, 1 ], 2),
            (&[ 1, 0 ], 1),
        ]));

        // a + 4 * b
        assert!(can_find_examples(&mut g, &[ 64, 64 ], &[
            (&[ 0x55, 0x11 ], 0x55 + 4 * 0x11),
            (&[ 783, 12 ], 783 + 4 * 12),
            (&[ 0x10000, 1 ], 0x10000 + 4 * 1),
            (&[ 123, 23 ], 123 + 4 * 23),
            (&[ 1, 1 ], 1 + 4 * 1),
            (&[ 1, 0 ], 1 + 4 * 0),
        ]));

        // a & b
        assert!(can_find_examples(&mut g, &[ 64, 64 ], &[
            (&[ 0x55, 0x11 ], 0x55 & 0x11),
            (&[ 123, 23 ], 123 & 23),
            (&[ 1, 1 ], 1),
            (&[ 1, 0 ], 0),
        ]));

        // a | b
        assert!(can_find_examples(&mut g, &[ 64, 64 ], &[
            (&[ 0x55, 0x11 ], 0x55 | 0x11),
            (&[ 783, 12 ], 783 | 12),
            (&[ 0x10000, 1 ], 0x10000 | 1),
            (&[ 123, 23 ], 123 | 23),
            (&[ 1, 1 ], 1 | 1),
            (&[ 1, 0 ], 1 | 0),
        ]));

        // not (a ^ b)
        assert!(can_find_examples(&mut g, &[ 64, 64 ], &[
            (&[ 0x55, 0x11 ], !(0x55 ^ 0x11)),
            (&[ 783, 12 ], !(783 ^ 12)),
            (&[ 0x10000, 1 ], !(0x10000 ^ 1)),
            (&[ 123, 23 ], !(123 ^ 23)),
            (&[ 1, 1 ], !(1 ^ 1)),
            (&[ 1, 0 ], !(1 ^ 0)),
        ]));

        // not (a & b)
        assert!(can_find_examples(&mut g, &[ 64, 64 ], &[
            (&[ 0x55, 0x11 ], !(0x55 & 0x11)),
            (&[ 783, 12 ], !(783 & 12)),
            (&[ 0x10000, 1 ], !(0x10000 & 1)),
            (&[ 123, 23 ], !(123 & 23)),
            (&[ 1, 1 ], !(1 & 1)),
            (&[ 1, 0 ], !(1 & 0)),
        ]));

        // a << 12
        assert!(can_find_examples(&mut g, &[ 64 ], &[
            (&[ 0x55 ], 0x55 << 12),
            (&[ 783 ], 783 << 12),
            (&[ 0x10000 ], 0x10000 << 12),
            (&[ 123 ], 123 << 12),
            (&[ 1 ], 1 << 12),
        ]));

        // (a - 1) & a
        assert!(can_find_examples(&mut g, &[ 64 ], &[
            (&[ 0x55 ], (0x55 - 1) & 0x55),
            (&[ 783 ], (783 - 1) & 783),
            (&[ 0x10000 ], (0x10000 - 1) & 0x10000),
            (&[ 123 ], (123-1) & 123),
            (&[ 1 ], 0),
            (&[ 0x789437428 ], (0x789437428 - 1) & 0x789437428),
            (&[ 0xffffffff ], (0xffffffff - 1) & 0xffffffff),
            (&[ 0x100 ], (0x100 - 1) & 0x100),
            (&[ 0x5 ], (0x5 - 1) & 0x5),
        ]));

        // a rol b
        assert!(can_find_examples(&mut g, &[ 64, 64 ], &[
            (&[ 0x1122334455667788, 24 ], 0x4455667788112233),
            (&[ 0x1122334455667788, 20 ], 0x3445566778811223),
            (&[ 0x0123456789ABCDEF, 20 ], 0x56789ABCDEF01234),
        ]));
    }
}