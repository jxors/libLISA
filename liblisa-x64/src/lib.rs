use oracle::{X64Oracle, kmod_ptrace::KmodPtraceBackend, simple_ptrace::PtraceBackend};
pub use arch::{X64Arch, X64State, X64Reg, X64Flag};

pub mod oracle;
pub mod arch;
mod memory;

pub type KmodPtraceOracle = X64Oracle<KmodPtraceBackend>;
pub type PtraceOracle = X64Oracle<PtraceBackend>;

pub fn x64_simple_ptrace_oracle() -> PtraceOracle {
    match PtraceOracle::new("utils/minimal-executable") {
        Ok(o) => o,
        Err(_) => PtraceOracle::new("../utils/minimal-executable").unwrap(),
    }
}

pub fn x64_kmod_ptrace_oracle() -> KmodPtraceOracle {
    match KmodPtraceOracle::new("utils/minimal-executable") {
        Ok(o) => o,
        Err(_) => KmodPtraceOracle::new("../utils/minimal-executable").unwrap(),
    }
}