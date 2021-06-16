use std::error::Error;
use std::os::unix::io::AsRawFd;
use memfd::Memfd;
use memmap::MmapMut;

pub struct SharedMemory {
    fd: Memfd,
    mem: MmapMut,
    len: usize,
}

impl SharedMemory {
    pub fn new(name: &str, len: usize) -> Result<SharedMemory, Box<dyn Error>> {
        let opts = memfd::MemfdOptions::default().allow_sealing(true);
        let mfd = opts.create(name)?;
    
        mfd.as_file().set_len(len as u64)?;
    
        // Add seals to prevent further resizing.
        let mut seals = memfd::SealsHashSet::new();
        seals.insert(memfd::FileSeal::SealShrink);
        seals.insert(memfd::FileSeal::SealGrow);
        mfd.add_seals(&seals)?;
    
        // Prevent further sealing changes.
        mfd.add_seal(memfd::FileSeal::SealSeal)?;

        Ok(SharedMemory {
            mem: unsafe { MmapMut::map_mut(mfd.as_file()) }?,
            fd: mfd,
            len,
        })
    }

    pub fn fd(&self) -> i32 {
        self.fd.as_file().as_raw_fd()
    }

    pub fn write(&mut self, addr: u64, data: &[u8]) {
        let addr = addr as usize & (self.len - 1);
        self.mem[addr..addr + data.len()].copy_from_slice(data);
    }

    pub fn read(&self, addr: u64, len: usize) -> &[u8] {
        let addr = addr as usize & (self.len - 1);
        &self.mem[addr..addr + len]
    }
}

pub struct MemoryPool {
    items: Vec<SharedMemory>,
}

impl MemoryPool {
    pub fn new(len: usize) -> Result<MemoryPool, Box<dyn Error>> {
        let mut items = Vec::new();
        for index in 0..16 {
            items.push(SharedMemory::new(&format!("pooled_shm{}", index), len)?);
        }

        Ok(MemoryPool {
            items,
        })
    }

    pub fn get(&mut self) -> SharedMemory {
        self.items.pop().unwrap()
    }

    pub fn release(&mut self, shm: SharedMemory) {
        self.items.push(shm);
    }
}