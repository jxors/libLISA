use std::time::Duration;

use criterion::{Criterion, black_box, criterion_group, criterion_main};
use liblisa_synth::gen::*;

fn evaluate(c: &mut Criterion) {
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

    c.bench_function("Evaluate(rol)", |b| b.iter(|| {
        black_box(rol.evaluate(&[ 0x123, 0x456 ]))
    }));
}

criterion_group!(
    name = benches;    
    config = Criterion::default().measurement_time(Duration::from_secs(60)).sample_size(1000);
    targets = evaluate
);
criterion_main!(benches);