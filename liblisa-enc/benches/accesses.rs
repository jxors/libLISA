use std::time::Duration;

use criterion::{Criterion, black_box, criterion_group, criterion_main};
use liblisa_core::{Location, StateGen, arch::{Instr, Register}};
use liblisa_enc::accesses::MemoryAccessAnalysis;
use liblisa_x64::{X64Reg, x64_simple_ptrace_oracle};
use rand::SeedableRng;

fn infer(c: &mut Criterion) {
    let mut o = x64_simple_ptrace_oracle();

    let instr = Instr::new(&[ 0x48, 0x31, 0xD0 ]);
    c.bench_function("Accesses::<X64Arch, PtraceOracle>::infer[XOR rax, rdx]", |b| b.iter(|| {
        black_box(MemoryAccessAnalysis::infer(&mut o, instr))
    }));

    let instr = Instr::new(&[ 0xFF, 0x74, 0xB8, 0x01 ]);
    c.bench_function("Accesses::<X64Arch, PtraceOracle>::infer[PUSH QWORD PTR [rax+rdi*4+0x1]]", |b| b.iter(|| {
        black_box(MemoryAccessAnalysis::infer(&mut o, instr))
    }));
}

fn randomize_new(c: &mut Criterion) {
    let mut o = x64_simple_ptrace_oracle();
    let mut rng: rand::rngs::StdRng = SeedableRng::seed_from_u64(0);

    let instr = Instr::new(&[ 0x48, 0x31, 0xD0 ]);
    let accesses = MemoryAccessAnalysis::infer(&mut o, instr).unwrap();
    c.bench_function("Accesses::<X64Arch, PtraceOracle>::randomize[XOR rax, rdx]", |b| b.iter(|| {
        black_box(StateGen::randomize_new(&accesses, &mut rng, &mut o).unwrap())
    }));

    let instr = Instr::new(&[ 0xFF, 0x74, 0xB8, 0x01 ]);
    let accesses = MemoryAccessAnalysis::infer(&mut o, instr).unwrap();
    c.bench_function("Accesses::<X64Arch, PtraceOracle>::randomize[PUSH QWORD PTR [rax+rdi*4+0x1]]", |b| b.iter(|| {
        black_box(StateGen::randomize_new(&accesses, &mut rng, &mut o).unwrap())
    }));
}

fn randomize_modify(c: &mut Criterion) {
    let mut o = x64_simple_ptrace_oracle();
    let mut rng: rand::rngs::StdRng = SeedableRng::seed_from_u64(0);

    let instr = Instr::new(&[ 0x48, 0x31, 0xD0 ]); // XOR rax, rdx
    let accesses = MemoryAccessAnalysis::infer(&mut o, instr).unwrap();
    let base = StateGen::randomize_new(&accesses, &mut rng, &mut o).unwrap();
    c.bench_function("Accesses::<X64Arch, PtraceOracle>::modify_locations[XOR rax, rdx]", |b| b.iter(|| {
        for reg in X64Reg::iter() {
            black_box(StateGen::modify_locations(&accesses, &mut rng, &mut o, base.clone(), &[ Location::Reg(reg) ]).unwrap());
        }
    }));

    let instr = Instr::new(&[ 0xFF, 0x74, 0xB8, 0x01 ]);
    let accesses = MemoryAccessAnalysis::infer(&mut o, instr).unwrap();
    let base = StateGen::randomize_new(&accesses, &mut rng, &mut o).unwrap();
    c.bench_function("Accesses::<X64Arch, PtraceOracle>::modify_locations[PUSH QWORD PTR [rax+rdi*4+0x1]]", |b| b.iter(|| {
        for reg in X64Reg::iter() {
            black_box(StateGen::modify_locations(&accesses, &mut rng, &mut o, base.clone(), &[ Location::Reg(reg) ]).unwrap());
        }
    }));
}

criterion_group! {
    name = benches; 
    config = Criterion::default().measurement_time(Duration::from_secs(15));
    targets = infer, randomize_new, randomize_modify
}
criterion_main!(benches);