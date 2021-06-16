use criterion::{Criterion, black_box, criterion_group, criterion_main};
use liblisa_core::arch::Instr;
use liblisa_enc::{accesses::MemoryAccessAnalysis, dataflow::DataflowAnalysis};
use liblisa_x64::x64_simple_ptrace_oracle;

fn infer(c: &mut Criterion) {
    let mut o = x64_simple_ptrace_oracle();

    let instr = Instr::new(&[ 0x30, 0xD0 ]);
    let memory_accesses = MemoryAccessAnalysis::infer(&mut o, instr).unwrap();
    c.bench_function("Dataflow::<X64Arch, PtraceOracle>::infer[XOR al, dl]", |b| b.iter(|| {
        black_box(DataflowAnalysis::infer(&mut o, &memory_accesses).unwrap())
    }));

    let instr = Instr::new(&[ 0x48, 0x31, 0xD0 ]);
    let memory_accesses = MemoryAccessAnalysis::infer(&mut o, instr).unwrap();
    c.bench_function("Dataflow::<X64Arch, PtraceOracle>::infer[XOR rax, rdx]", |b| b.iter(|| {
        black_box(DataflowAnalysis::infer(&mut o, &memory_accesses).unwrap())
    }));

    let instr = Instr::new(&[ 0xFF, 0x74, 0xB8, 0x01 ]);
    let memory_accesses = MemoryAccessAnalysis::infer(&mut o, instr).unwrap();
    c.bench_function("Dataflow::<X64Arch, PtraceOracle>::infer[PUSH QWORD PTR [rax+rdi*4+0x1]]", |b| b.iter(|| {
        black_box(DataflowAnalysis::infer(&mut o, &memory_accesses).unwrap())
    }));
}

criterion_group!(benches, infer);
criterion_main!(benches);