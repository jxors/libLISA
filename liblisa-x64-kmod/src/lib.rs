use std::{error::Error, fs::File, marker::PhantomData, mem, os::unix::prelude::CommandExt, path::PathBuf, process::{Child, Command}};
use std::os::unix::io::AsRawFd;
use libc::{pid_t, user_regs_struct};
use log::{error, info, trace};
use nix::{errno::Errno, request_code_readwrite, sys::{ptrace::{self, Options, Request, traceme}, signal::Signal, uio::IoVec, wait::{WaitStatus, waitpid}}, unistd::Pid};
use nix::libc::{self, MAP_FIXED, MAP_SHARED};

#[allow(unused, non_snake_case, non_camel_case_types, non_upper_case_globals)]
mod sys {
    include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
}

#[allow(unused, non_snake_case, non_camel_case_types, non_upper_case_globals)]
mod sys_ext {
    include!(concat!(env!("OUT_DIR"), "/ptrace_bindings.rs"));
}

pub struct ObservationProcess {
    pid: Pid,
    child: Child,
    control: File,
}

fn spawn_process(cmd: &mut Command) -> Result<(Pid, Child), Box<dyn Error>> {
    for _ in 0..100 {
        let mut child = cmd.spawn()?;
        let raw_pid = child.id() as i32;
        info!("raw_pid = {}", raw_pid);
        let pid = Pid::from_raw(raw_pid);

        waitpid(pid, None)?;
        if let Err(e) = ptrace::setoptions(pid, Options::PTRACE_O_EXITKILL) {
            if let nix::Error::Sys(Errno::ESRCH) = e {
                error!("Failed to attach to the process ({} / {})! Retrying...", pid, child.id());
            } else {
                Err(e)?;
            }
        } else {
            return Ok((pid, child));
        }

        error!("Still not able to attach to the process! Retrying...");

        child.kill().ok();
        child.wait().ok();
    }

    panic!("Process failed to spawn");
}

impl ObservationProcess {
    pub fn new(binary_path: PathBuf) -> Result<ObservationProcess, Box<dyn Error>> {
        let mut cmd = Command::new(binary_path);
        let (pid, child) = spawn_process(unsafe {
            cmd.pre_exec(|| {
                traceme().expect("Unable to trace process");
                return Ok(())
            })
        })?;

        // Prepare the process by clearing all mapped memory
        let control = File::open("/proc/lisa").expect("Kernel module is not available");
        unsafe {
            let ret = libc::ioctl(control.as_raw_fd(), request_code_readwrite!(0x33, 0, 4), &mut pid.as_raw().as_raw_fd() as *mut i32);
            trace!("ioctl(.., PREPARE, ..) = {}", ret);

            if ret != 0 {
                return Err(Errno::from_i32(-ret).into());
            }
        }

        Ok(ObservationProcess {
            pid,
            child,
            control,
        })
    }

    pub fn raw_pid(&self) -> pid_t {
        self.pid.as_raw()
    }

    pub fn get_basic_regs(&mut self) -> Result<user_regs_struct, nix::Error> {
        let mut output = [0u8; mem::size_of::<user_regs_struct>()];
        Ok(unsafe {
            let addr = sys_ext::NT_PRSTATUS;
            let mut data = IoVec::from_mut_slice(&mut output);
            let data_ptr = &mut data as *mut _;

            // The ptrace function has been deprecated without implementing an actual alternative to PTRACE_GETREGSET
            // So we can ignore the deprecation for now until a safe alternative is provided.
            #[allow(deprecated)]
            let result = libc::ptrace(Request::PTRACE_GETREGSET as u32, self.pid, addr, data_ptr);

            if result != 0 {
                Err(nix::Error::from_errno(Errno::from_i32(-result as i32)))?
            }

            output.align_to::<user_regs_struct>().1[0]
        })
    }

    // TODO: user_write and user_read are used for the debug registers; Preferrably these should be completely integrated into the ioctl
    pub fn user_write(&mut self, addr: u64, word: u64) -> Result<(), nix::Error> {
        // The ptrace function has been deprecated without implementing an actual alternative to PTRACE_POKEUSER
        // So we can ignore the deprecation for now until a safe alternative is provided.
        #[allow(deprecated)]
        let result = unsafe { libc::ptrace(Request::PTRACE_POKEUSER as u32, self.pid, addr, word) };
        
        if result != 0 {
            Err(nix::Error::from_errno(Errno::from_i32(-result as i32)))
        } else {
            Ok(())
        }
    }

    pub fn user_read(&mut self, addr: u64) -> Result<u64, nix::Error> {
        // The ptrace function has been deprecated without implementing an actual alternative to PTRACE_POKEUSER
        // So we can ignore the deprecation for now until a safe alternative is provided.
        #[allow(deprecated)]
        let result = unsafe { libc::ptrace(Request::PTRACE_PEEKUSER as u32, self.pid, addr, 0) };
        
        if result < 0 {
            Err(nix::Error::from_errno(Errno::from_i32(-result as i32)))
        } else {
            Ok(result as u64)
        }
    }

    pub fn start_observe(&self) -> ObservationBuilder<StageUnmap> {
        ObservationBuilder::new(self)
    }

    pub fn observe(&mut self, regs: &mut user_regs_struct, builder: ObservationBuilder<StageMap>) -> Result<ObservationResult, ObservationError> {
        builder.run(regs, self)
    }

    pub fn kill(mut self) {
        self.child.kill().ok();
        self.child.wait().ok();
    }
}

pub struct StageMap;
pub struct StageUnmap;

pub struct ObservationBuilder<S> {
    data: sys::lisa_ioctl_struct,
    _phantom: PhantomData<S>,
}

impl ObservationBuilder<StageUnmap> {
    fn new(process: &ObservationProcess) -> ObservationBuilder<StageUnmap> {
        const MMAP_SHARE_FLAGS: i32 = MAP_SHARED | MAP_FIXED;

        ObservationBuilder {
            data: sys::lisa_ioctl_struct {
                pid: process.pid.as_raw().as_raw_fd(),
                num_unmaps: 0,
                num_maps: 0,
                unmaps: [sys::cmd_munmap_t {
                    addr: 0,
                }; 32],
                mapping_flags: MMAP_SHARE_FLAGS,
                maps: [sys::cmd_mmap_t {
                    addr: 0,
                    fd: 0,
                    prot: 0,
                }; 32],
                result: std::ptr::null_mut(),
                regs: std::ptr::null_mut(),
            },
            _phantom: PhantomData::default(),
        }
    }

    pub fn unmap(&mut self, addr: u64) -> &mut Self {
        self.data.unmaps[self.data.num_unmaps as usize] = sys::cmd_munmap_t {
            addr,
        };

        self.data.num_unmaps += 1;
        self
    }

    #[allow(unused_mut)]
    pub fn start_mapping(mut self) -> ObservationBuilder<StageMap> {
        ObservationBuilder {
            data: self.data,
            _phantom: PhantomData::default(),
        }
    }
}

#[derive(Debug)]
pub enum ObservationResult {
    Executed,
    Fault {
        signal: Signal,
        si_code: i32,
        si_errno: i32,
        si_addr: u64,
    },
    ProcessExited(i32),
    Killed(Signal),
}

impl ObservationResult {
    /// Returns `true` if the observation_result is [`Executed`].
    pub fn is_executed(&self) -> bool {
        matches!(self, Self::Executed)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ObservationError {
    #[error("System error: {}", .0)]
    Sys(Errno),

    #[error("The ioctl call failed with {}", .0)]
    IoctlFailed(Errno),

    #[error("Encountered a general error: {}", .0)]
    Other(nix::Error),
}

impl From<nix::Error> for ObservationError {
    fn from(e: nix::Error) -> Self {
        ObservationError::Other(e)
    }
}

impl ObservationBuilder<StageMap> {
    pub fn map(&mut self, addr: u64, fd: i32, prot: u8) -> &mut Self {
        self.data.maps[self.data.num_maps as usize] = sys::cmd_mmap_t {
            addr,
            fd,
            prot,
        };

        self.data.num_maps += 1;
        self
    }

    fn run(mut self, regs: &mut user_regs_struct, process: &mut ObservationProcess) -> Result<ObservationResult, ObservationError> {
        let mut result = sys::lisa_observe_result_t {
            status: 0,
            si_code: 0,
            si_errno: 0,
            si_signo: 0,
            optional_addr: 0,
        };

        self.data.result = &mut result;
        self.data.regs = regs as *mut _ as *mut _;
    
        unsafe {
            let ret = libc::ioctl(process.control.as_raw_fd(), request_code_readwrite!(0x33, 1, std::mem::size_of::<sys::lisa_ioctl_struct>()), &mut self.data as *mut _);
    
            if ret != 0 {
                return Err(ObservationError::IoctlFailed(Errno::from_i32(-ret)));
            }
        }
    
        let status = match Errno::result(result.status)? {
            0 => Ok(WaitStatus::StillAlive),
            res => WaitStatus::from_raw(Pid::from_raw(res), result.status),
        }?;

        Ok(match status {
            WaitStatus::Stopped(_, Signal::SIGTRAP) => {
                // Process is paused after executing an instruction
                // We cannot determine the instruction length from the IP, as a jump changes this.
                // Therefore, we just assume the length was correct here.
                ObservationResult::Executed
            },
            WaitStatus::Stopped(_, signal) => {
                ObservationResult::Fault {
                    signal,
                    si_code: result.si_code,
                    si_errno: result.si_errno,
                    si_addr: result.optional_addr,
                }
            },
            WaitStatus::Signaled(_, sig, _) => {
                ObservationResult::Killed(sig)
            },
            WaitStatus::Exited(_, return_code) => {
                ObservationResult::ProcessExited(return_code)
            },
            other => {
                panic!("Got {:?}", other);
            },
        })
    }
}