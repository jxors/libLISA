use std::{sync::Arc, error::Error, fmt::Debug, marker::PhantomData, ops::Range};
use crate::arch::{Arch, SystemState};
use thiserror::Error;

#[derive(Error, Debug, Clone)]
pub enum OracleError {
    #[error("Encountered a memory access at {:X}", .0)]
    MemoryAccess(u64),

    #[error("Invalid instruction")]
    InvalidInstruction,

    #[error("Tried to read from unadressable memory")]
    GeneralFault,

    #[error("A computation error occurred")]
    ComputationError,

    #[error("Oracle failed with {}", .0)]
    ApiError(Arc<Box<dyn Error + Send + Sync>>)
}

impl OracleError {
    pub fn api<E: Error + Send + Sync + 'static>(e: E) -> Self {
        OracleError::ApiError(Arc::new(Box::new(e)))
    }
}

pub trait Oracle<A: Arch> {
    fn valid_executable_addresses(&mut self) -> Range<u64>;

    fn can_map(&mut self, addr: u64) -> bool;

    fn page_size(&mut self) -> u64;

    fn observe(&mut self, before: &SystemState<A>) -> Result<SystemState<A>, OracleError>;

    fn observe_carefully(&mut self, before: &SystemState<A>) -> Result<SystemState<A>, OracleError> {
        let result = self.observe(before)?;
        let accesses = self.scan_unspecified_memory_accesses(before)?;

        if accesses.len() > 0 {
            Err(OracleError::MemoryAccess(accesses[0]))
        } else {
            Ok(result)
        }
    }

    fn scan_unspecified_memory_accesses(&mut self, before: &SystemState<A>) -> Result<Vec<u64>, OracleError>;

    fn debug_dump(&mut self);

    fn restart(&mut self);

    fn kill(self);
}

pub struct InvocationCounter<A: Arch, O: Oracle<A>> {
    oracle: O,
    observations: usize,
    _phantom: PhantomData<A>,
}

impl<A: Arch, O: Oracle<A>> Oracle<A> for InvocationCounter<A, O> {
    fn valid_executable_addresses(&mut self) -> Range<u64> {
        self.oracle.valid_executable_addresses()
    }

    fn can_map(&mut self, addr: u64) -> bool {
        self.oracle.can_map(addr)
    }

    fn page_size(&mut self) -> u64 {
        self.oracle.page_size()
    }

    fn observe(&mut self, before: &SystemState<A>) -> Result<SystemState<A>, OracleError> {
        self.observations += 1;
        self.oracle.observe(before)
    }

    fn debug_dump(&mut self) {
        self.oracle.debug_dump()
    }

    fn scan_unspecified_memory_accesses(&mut self, before: &SystemState<A>) -> Result<Vec<u64>, OracleError> {
        self.oracle.scan_unspecified_memory_accesses(before)
    }

    fn restart(&mut self) {
        self.oracle.restart()
    }

    fn kill(self) {
        self.oracle.kill()
    }
}

impl<A: Arch, O: Oracle<A>> Debug for InvocationCounter<A, O> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "InvocationCounter {{ observations: {} }} ", self.observations)
    }
}

impl<A: Arch, O: Oracle<A>> InvocationCounter<A, O> {
    pub fn new(oracle: O) -> Self {
        InvocationCounter {
            oracle,
            observations: 0,
            _phantom: Default::default(),
        }
    }
}

pub struct CarefulOracle<'a, A: Arch, O: Oracle<A>> {
    oracle: &'a mut O,
    _phantom: PhantomData<A>,
}

impl<'a, A: Arch, O: Oracle<A>> Oracle<A> for CarefulOracle<'a, A, O> {
    fn valid_executable_addresses(&mut self) -> Range<u64> {
        self.oracle.valid_executable_addresses()
    }

    fn can_map(&mut self, addr: u64) -> bool {
        self.oracle.can_map(addr)
    }

    fn page_size(&mut self) -> u64 {
        self.oracle.page_size()
    }

    fn observe(&mut self, before: &SystemState<A>) -> Result<SystemState<A>, OracleError> {
        self.observe_carefully(before)
    }

    fn debug_dump(&mut self) {
        self.oracle.debug_dump()
    }

    fn observe_carefully(&mut self, before: &SystemState<A>) -> Result<SystemState<A>, OracleError> {
        self.oracle.observe_carefully(before)
    }

    fn scan_unspecified_memory_accesses(&mut self, before: &SystemState<A>) -> Result<Vec<u64>, OracleError> {
        self.oracle.scan_unspecified_memory_accesses(before)
    }

    fn restart(&mut self) {
        self.oracle.restart()
    }

    fn kill(self) {
        todo!()
    }
}

impl<'a, A: Arch, O: Oracle<A>> CarefulOracle<'a, A, O> {
    pub fn new(oracle: &'a mut O) -> Self {
        CarefulOracle {
            oracle,
            _phantom: Default::default(),
        }
    }
}