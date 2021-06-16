use criterion::{Criterion, black_box, criterion_group, criterion_main};
use liblisa_core::arch::Instr;
use liblisa_enc::Validity;
use liblisa_x64::x64_simple_ptrace_oracle;

fn infer(c: &mut Criterion) {
    let mut o = x64_simple_ptrace_oracle();

    let instr = Instr::new(&[ 0x48, 0x31, 0xD0 ]);
    c.bench_function("Validity::<X64Arch, PtraceOracle>::infer[XOR rax, rdx]", |b| b.iter(|| {
        black_box(Validity::infer(&mut o, instr))
    }));

    let instr = Instr::new(&[ 0xFF, 0x74, 0xB8, 0x01 ]);
    c.bench_function("Validity::<X64Arch, PtraceOracle>::infer[PUSH QWORD PTR [rax+rdi*4+0x1]]", |b| b.iter(|| {
        black_box(Validity::infer(&mut o, instr))
    }));
}

criterion_group!(benches, infer);
criterion_main!(benches);