use std::time::Duration;

use criterion::{Criterion, black_box, criterion_group, criterion_main};
use liblisa_core::{arch::{Instr, MemoryState, Permissions, Register, State, SystemState}, oracle::Oracle};
use liblisa_x64::{X64State, x64_kmod_ptrace_oracle, x64_simple_ptrace_oracle};

fn simple_ptrace(c: &mut Criterion) {
    let mut o = x64_simple_ptrace_oracle();
    let pc = o.valid_executable_addresses().start;
    let instr = Instr::new(&[ 0x48, 0x31, 0xD0 ]); // XOR rax, rdx
    let state = SystemState::new(X64State::create(|reg| if reg.is_pc() {
        pc
    } else {
        0
    }, |_| false), MemoryState::new(vec![
        (pc, Permissions::Execute, instr.bytes().to_owned())
    ].into_iter()));

    c.bench_function("PtraceOracle::observe[XOR rax, rdx]", |b| b.iter(|| {
        black_box(o.observe(&state).unwrap())
    }));

    let instr = Instr::new(&[ 0x48, 0x31, 0xD0 ]); // XOR rax, rdx
    let state2 = SystemState::new(X64State::create(|reg| if reg.is_pc() {
        pc
    } else {
        0
    }, |_| false), MemoryState::new(vec![
        (pc, Permissions::Execute, instr.bytes().to_owned()),
        (0x11223344, Permissions::Read, vec![ 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3 ]),
        (0x11323344, Permissions::Read, vec![ 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3 ]),
        (0x11423344, Permissions::Read, vec![ 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3 ]),
        (0x11523344, Permissions::Read, vec![ 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3 ]),
    ].into_iter()));

    c.bench_function("PtraceOracle::observe[XOR rax, rdx + 4 memory mappings]", |b| b.iter(|| {
        black_box(o.observe(&state2).unwrap())
    }));

    c.bench_function("PtraceOracle::observe_carefully[XOR rax, rdx + 4 memory mappings]", |b| b.iter(|| {
        black_box(o.observe_carefully(&state2).unwrap())
    }));

    c.bench_function("PtraceOracle::observe[XOR rax, rdx + 4 memory mappings alternating]", |b| b.iter(|| {
        black_box(o.observe(&state).unwrap());
        black_box(o.observe(&state2).unwrap());
    }));
}

fn kmod_ptrace(c: &mut Criterion) {
    let mut o = x64_kmod_ptrace_oracle();
    let pc = o.valid_executable_addresses().start;
    let instr = Instr::new(&[ 0x48, 0x31, 0xD0 ]); // XOR rax, rdx
    let state = SystemState::new(X64State::create(|reg| if reg.is_pc() {
        pc
    } else {
        0
    }, |_| false), MemoryState::new(vec![
        (pc, Permissions::Execute, instr.bytes().to_owned())
    ].into_iter()));

    c.bench_function("KmodPtraceOracle::observe[XOR rax, rdx]", |b| b.iter(|| {
        black_box(o.observe(&state).unwrap())
    }));

    let instr = Instr::new(&[ 0x48, 0x31, 0xD0 ]); // XOR rax, rdx
    let state2 = SystemState::new(X64State::create(|reg| if reg.is_pc() {
        pc
    } else {
        0
    }, |_| false), MemoryState::new(vec![
        (pc, Permissions::Execute, instr.bytes().to_owned()),
        (0x11223344, Permissions::Read, vec![ 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3 ]),
        (0x11323344, Permissions::Read, vec![ 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3 ]),
        (0x11423344, Permissions::Read, vec![ 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3 ]),
        (0x11523344, Permissions::Read, vec![ 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3 ]),
    ].into_iter()));

    c.bench_function("KmodPtraceOracle::observe[XOR rax, rdx + 4 memory mappings]", |b| b.iter(|| {
        black_box(o.observe(&state2).unwrap())
    }));

    c.bench_function("KmodPtraceOracle::observe_carefully[XOR rax, rdx + 4 memory mappings]", |b| b.iter(|| {
        black_box(o.observe_carefully(&state2).unwrap())
    }));

    c.bench_function("KmodPtraceOracle::observe[XOR rax, rdx + 4 memory mappings alternating]", |b| b.iter(|| {
        black_box(o.observe(&state).unwrap());
        black_box(o.observe(&state2).unwrap());
    }));
}

criterion_group! {
    name = benches; 
    config = Criterion::default().measurement_time(Duration::from_secs(60));
    targets = simple_ptrace, kmod_ptrace
}
criterion_main!(benches);