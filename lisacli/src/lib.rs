use std::path::PathBuf;
use liblisa::work::SavePaths;

#[derive(Debug, Clone)]
pub struct SavePath {
    pub state: PathBuf,
    pub state_workers: Vec<PathBuf>,
    pub log: Vec<PathBuf>,
    pub state_tmp: PathBuf,
    pub encodings: PathBuf,
    pub base_data: PathBuf,
    dir: PathBuf,
}

impl From<PathBuf> for SavePath {
    fn from(path: PathBuf) -> Self {
        SavePath {
            state: path.join("state.json"),
            state_workers: (0..64).map(|n| path.join(format!("state_{}.json", n))).collect(),
            log: (0..64).map(|n| path.join(format!("log_{}.ndjson", n))).collect(),
            state_tmp: path.join(".tmpstate.json"),
            encodings: path.join("encodings.ndjson"),
            base_data: path.join("base_data.json"),
            dir: path,
        }
    }
}

impl SavePaths for SavePath {
    fn savestate_path(&self) -> &std::path::Path {
        &self.state
    }

    fn savestate_worker_path(&self, index: usize) -> &std::path::Path {
        &self.state_workers[index]
    }

    fn log_worker_path(&self, index: usize) -> &std::path::Path {
        &self.log[index]
    }

    fn savestate_path_tmp(&self) -> &std::path::Path {
        &self.state_tmp
    }

    fn create_dirs(&self) -> Result<(), std::io::Error> {
        std::fs::create_dir_all(&self.dir)
    }

    fn artifact_path(&self) -> &std::path::Path {
        &self.encodings
    }

    fn base_data_path(&self) -> &std::path::Path {
        &self.base_data
    }
}