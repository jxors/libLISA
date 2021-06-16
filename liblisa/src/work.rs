use std::{error::Error, fs::{File, OpenOptions}, io::{BufRead, BufReader, Write}, marker::PhantomData, path::Path, process::exit, sync::{Arc, atomic::{AtomicBool, AtomicUsize, Ordering}, mpsc::{RecvTimeoutError, Sender, channel}}, time::{Duration, Instant}};
use log::error;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::sync::RwLock;

#[derive(Clone, Debug, Serialize, Deserialize)]
struct GlobalState {
    seconds_running: u64,

    #[serde(default)]
    num_workers: usize,
}

pub struct Work<WS: Worker, R, P: SavePaths> {
    paths: P,
    state: GlobalState,
    states: Vec<WorkerState<WS, R>>,
    artifacts: Vec<WS::Artifact>,
    logs: Vec<File>,
    _phantom: PhantomData<WS::LogEntry>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LegacyGlobalState<WS, R> {
    states: Vec<WorkerState<WS, R>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WorkerStateData<WS> {
    state: WS,
    done: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WorkerState<WS, R> {
    id: usize,
    from: R,
    to: Option<R>,
    data: WorkerStateData<WS>,
    artifacts_produced: usize,
}

impl<WS, R> WorkerState<WS, R> {
    /// Get a reference to the worker state's index.
    pub fn id(&self) -> &usize {
        &self.id
    }

    /// Get a reference to the worker state's from.
    pub fn from(&self) -> &R {
        &self.from
    }

    /// Get a reference to the worker state's to.
    pub fn to(&self) -> &Option<R> {
        &self.to
    }

    /// Get a reference to the worker state's artifacts produced.
    pub fn artifacts_produced(&self) -> &usize {
        &self.artifacts_produced
    }

    pub fn inner(&self) -> &WS {
        &self.data.state
    }

    pub fn inner_mut(&mut self) -> &mut WS {
        &mut self.data.state
    }

    pub fn reset_done(&mut self) {
        self.data.done = false;
    }

    pub fn done(&self) -> bool {
        self.data.done
    }
}

pub struct StateUpdater<WS: Worker> {
    index: usize,
    sender: Sender<(usize, WorkerStateData<WS>)>,
    artifact_sender: Sender<(usize, WS::Artifact)>,
    log_sender: Sender<(usize, WS::LogEntry)>,
}

impl<WS: Worker> StateUpdater<WS> {
    pub fn new(index: usize, sender: Sender<(usize, WorkerStateData<WS>)>, artifact_sender: Sender<(usize, WS::Artifact)>, log_sender: Sender<(usize, WS::LogEntry)>) -> StateUpdater<WS> {
        StateUpdater {
            index,
            sender,
            artifact_sender,
            log_sender,
        }
    }

    pub fn update(&mut self, new_state: WS) {
        self.sender.send((self.index, WorkerStateData {
            state: new_state,
            done: false,
        })).unwrap();
    }

    pub fn publish_artifact(&mut self, artifact: WS::Artifact) {
        self.artifact_sender.send((self.index, artifact)).unwrap();
    }

    pub fn log(&mut self, entry: WS::LogEntry) {
        self.log_sender.send((self.index, entry)).unwrap();
    }

    pub fn done(self, final_state: WS) {
        self.sender.send((self.index, WorkerStateData {
            state: final_state,
            done: true,
        })).unwrap();
    }
}

pub trait Worker where Self: Sized {
    type LogEntry: Serialize + DeserializeOwned + Send;
    type Artifact: Serialize + DeserializeOwned + Send;
    type RuntimeData: Sync;

    fn run(&mut self, worker_id: usize, running: &AtomicBool, runtime_data: &Self::RuntimeData, updater: StateUpdater<Self>) -> Result<(), Box<dyn Error>>;
}

pub trait SavePaths {
    fn savestate_path(&self) -> &Path;

    fn savestate_worker_path(&self, index: usize) -> &Path;

    fn log_worker_path(&self, index: usize) -> &Path;
    
    fn savestate_path_tmp(&self) -> &Path;

    fn artifact_path(&self) -> &Path;

    fn base_data_path(&self) -> &Path;

    fn create_dirs(&self) -> Result<(), std::io::Error>;
}

impl<P: SavePaths, R: Serialize + DeserializeOwned + Send + Sync + Clone, WS: Worker + Serialize + DeserializeOwned + Send + Sync + Clone> Work<WS, R, P> {
    pub fn create(paths: P, work: &[R], num_threads: usize, worker: impl Fn(&R, Option<&R>) -> WS) -> Result<Work<WS, R, P>, std::io::Error> {
        assert!(work.len() >= num_threads);

        paths.create_dirs()?;

        File::create(paths.artifact_path())?;

        let w = Work {
            state: GlobalState {
                seconds_running: 0,
                num_workers: num_threads,
            },
            states: (0..num_threads).map(|index| {
                let from = (work.len() * index) / num_threads;
                let to = (work.len() * (index + 1)) / num_threads;
                let from = &work[from];
                let to = work.get(to);
    
                WorkerState {
                    id: index,
                    from: from.clone(),
                    to: to.cloned(),
                    artifacts_produced: 0,
                    data: WorkerStateData {
                        done: false,
                        state: worker(from, to),
                    }
                }
            }).collect::<Vec<_>>(),
            logs: (0..num_threads).map(|index| File::create(paths.log_worker_path(index)).unwrap()).collect(),
            paths,
            artifacts: Vec::new(),
            _phantom: PhantomData,
        };
        w.save_all()?;

        Ok(w)
    }

    fn load_workers(paths: &P, num: usize) -> Result<Vec<WorkerState<WS, R>>, std::io::Error> {
        if num == 0 {
            return Err(std::io::Error::new(std::io::ErrorKind::Other, "Worker count is zero"));
        }

        let mut states = Vec::new();
        for worker_index in 0..num {
            let state = serde_json::from_reader(BufReader::new(File::open(&paths.savestate_worker_path(worker_index))?))?;
            states.push(state); 
        }

        Ok(states)
    }

    pub fn load(paths: P) -> Result<Work<WS, R, P>, std::io::Error> {
        let state: GlobalState = serde_json::from_reader(BufReader::new(File::open(&paths.savestate_path())?))?;
        let states = Self::load_workers(&paths, state.num_workers)?;

        let work = Work {
            state,
            logs: (0..states.len()).map(|index| OpenOptions::new()
                .create(true)
                .append(true)
                .open(paths.log_worker_path(index)).unwrap()
            ).collect(),
            states,
            artifacts: {
                let mut v = Vec::new();
                for line in BufReader::new(File::open(&paths.artifact_path())?).lines() {
                    v.push(serde_json::from_str(&line?)?);
                }

                v
            },
            paths,
            _phantom: PhantomData,
        };

        Ok(work)
    }

    pub fn artifacts(&self) -> &[WS::Artifact] {
        &self.artifacts
    }

    pub fn workers(&self) -> &[WorkerState<WS, R>] {
        &self.states
    }

    pub fn workers_mut(&mut self) -> &mut [WorkerState<WS, R>] {
        &mut self.states
    }

    pub fn seconds_running(&self) -> u64 {
        self.state.seconds_running
    }

    pub fn save_all(&self) -> Result<(), std::io::Error> {
        self.save_global_state()?;
        for (worker_index, _) in self.states.iter().enumerate() {
            self.save_worker(worker_index)?;
        }

        Ok(())
    }

    fn save_global_state(&self) -> Result<(), std::io::Error> {
        serde_json::to_writer(File::create(&self.paths.savestate_path_tmp())?, &self.state)?;
        std::fs::rename(&self.paths.savestate_path_tmp(), &self.paths.savestate_path())?;

        Ok(())
    }

    fn save_worker(&self, worker_index: usize) -> Result<(), std::io::Error> {
        serde_json::to_writer(File::create(&self.paths.savestate_path_tmp())?, &self.states[worker_index])?;
        std::fs::rename(&self.paths.savestate_path_tmp(), &self.paths.savestate_worker_path(worker_index))?;

        Ok(())
    }

    pub fn run(&mut self, runtime_data: &WS::RuntimeData) -> Result<bool, std::io::Error> {
        let running = Arc::new(AtomicBool::new(true));
        let r = running.clone();
        ctrlc::set_handler(move || {
            if !r.load(Ordering::SeqCst) {
                eprintln!("Aborting without saving!");

                // TODO: Gracefully exit with another atomicbool
                exit(0);
            } else {
                eprintln!("Received Control+C! Saving & quitting on next instruction!");
                r.store(false, Ordering::SeqCst);
            }
        }).expect("Error setting Ctrl-C handler");

        let start = Instant::now();
        let base_seconds = self.state.seconds_running;
        let (sender, receiver) = channel();
        let (artifact_sender, artifact_receiver) = channel();
        let (log_sender, log_receiver) = channel();
        let threads_running = AtomicUsize::new(0);
        let threads_running = &threads_running;
        let mut last_save = Instant::now();
        match crossbeam::scope(|s| -> Result<(), std::io::Error> {
            let worker_statuses = self.states.iter().map(|_| Arc::new(AtomicBool::new(false))).collect::<Vec<_>>();
            let threads = self.states.iter().cloned().enumerate().zip(worker_statuses.iter().cloned()).map(|((index, mut state), status_bool)| {
                let running = running.clone();
                let sender = sender.clone();
                let artifact_sender = artifact_sender.clone();
                let log_sender = log_sender.clone();

                s.builder()
                    .name(format!("Worker #{}", index))
                    .spawn(move |_| {
                        let n = threads_running.fetch_add(1, Ordering::SeqCst);
                        println!("[{:02}] Workers started: {}", index, n);
                        status_bool.store(true, Ordering::SeqCst);
                        if state.data.done {
                            println!("[{:02}] No work to do, enumeration is already complete", index);
                        } else {
                            state.data.state.run(index, running.as_ref(), runtime_data, StateUpdater {
                                index,
                                sender,
                                artifact_sender,
                                log_sender,
                            }).unwrap();
                        }

                        status_bool.store(false, Ordering::SeqCst);
                        let n = threads_running.fetch_sub(1, Ordering::SeqCst);
                        println!("[{:02}] Workers remaining: {}", index, n.checked_sub(1).unwrap_or(0));
                    })
                    .expect("Unable to start worker thread")
            }).collect::<Vec<_>>();

            let mut changed = vec![ false; self.states.len() ];
            'main: loop {
                let start_time = Instant::now();
                // Double loop to make sure we can handle receiving state updates at a rate greater than we are
                // able to write to disk. (i.e., we batch N updates and do only a single write to disk)
                loop {
                    match receiver.recv_timeout(Duration::from_secs(2)) {
                        Ok((index, state)) => {
                            self.states[index].data = state;
                            changed[index] = true;

                            // If we are receiving instructions at a rate faster than 1 per 2 seconds, this loop will never
                            // terminate. To make sure we save every now and then anyways, we break after 30 seconds even if 
                            // there is potentially more data available.
                            if Instant::now() - start_time > Duration::from_secs(30) {
                                break;
                            }
                        },
                        Err(RecvTimeoutError::Timeout) => break,
                        Err(RecvTimeoutError::Disconnected) => break 'main,
                    }
                }

                loop {
                    match artifact_receiver.recv_timeout(Duration::from_nanos(1)) {
                        Ok((index, artifact)) => {
                            self.states[index].artifacts_produced += 1;

                            let mut f = OpenOptions::new()
                                .append(true)
                                .create(true)
                                .open(&self.paths.artifact_path())
                                .unwrap();

                            writeln!(f, "{}", serde_json::to_string(&artifact).unwrap()).unwrap();
                        },
                        Err(_) => break,
                    }
                }

                loop {
                    match log_receiver.recv_timeout(Duration::from_nanos(1)) {
                        Ok((index, log_entry)) => {
                            writeln!(self.logs[index], "{}", serde_json::to_string(&log_entry).unwrap()).unwrap();
                        },
                        Err(_) => break,
                    }
                }

                self.state.seconds_running = base_seconds + (Instant::now() - start).as_secs();

                // We save only once every 20 seconds, since saving can take about a second.
                if changed.iter().any(|b| *b) && Instant::now() - last_save > Duration::from_secs(20) {
                    let before = Instant::now();
                    for (worker_index, c) in changed.iter_mut().enumerate() {
                        if *c {
                            *c = false;

                            println!("[{:02}] Saving...", worker_index);
                            self.save_worker(worker_index).unwrap_or_else(|e| {
                                println!("Unable to save worker {} state: {}", worker_index, e);
                                exit(-1);
                            });
                        }
                    }

                    self.save_global_state().unwrap_or_else(|e| { 
                        println!("Unable to save global state: {}", e);
                        exit(-1);
                    });

                    let seconds_running: u64 = self.state.seconds_running;
                    let artifacts = self.states.iter().map(|s| s.artifacts_produced).sum::<usize>();
                    println!("Produced {} artifacts in {}h {}m {}s (~{:.1}/hour)", artifacts, seconds_running / 3600, (seconds_running / 60) % 60, seconds_running % 60, artifacts as f64 / (seconds_running as f64 / (3600.0)));

                    println!("Saving took {}ms", (Instant::now() - before).as_millis());
                    last_save = Instant::now();
                }

                if !running.load(Ordering::SeqCst) {
                    println!("Workers still running: {:02?}", worker_statuses.iter().enumerate().filter(|(_, s)| s.load(Ordering::SeqCst)).map(|(i, _)| i).collect::<Vec<_>>());
                    if threads_running.load(Ordering::SeqCst) <= 0 && Instant::now() - last_save > Duration::from_secs(15) {
                        break;
                    }
                }
            }

            println!("Waiting for all threads to finish...");
            let _ = threads.into_iter().map(|t| t.join()).collect::<Vec<_>>();

            Ok(())
        }) {
            Ok(Ok(_)) => println!("All threads completed successfully"),
            Ok(Err(e)) => error!("Error: {}", e),
            Err(e) => {
                error!("{:?}", e);
            }
        }

        println!("Saving all states...");
        self.state.seconds_running = base_seconds + (Instant::now() - start).as_secs();
        self.save_all()?;

        // TODO: Why return a bool?
        Ok(true)
    }
}

pub struct BroadcastQueue<T: Clone> {
    vec: RwLock<Vec<T>>,
}

impl<T: Clone> BroadcastQueue<T> {
    pub fn new() -> BroadcastQueue<T> {
        BroadcastQueue {
            vec: RwLock::new(Vec::new()),
        }
    }

    pub fn push(&self, v: T) {
        self.vec.write().unwrap().push(v);
    }

    pub fn read<'a>(&'a self) -> BroadcastQueueReader<'a, T> {
        BroadcastQueueReader {
            queue: self,
            index: self.vec.read().unwrap().len(),
        }
    }
}

pub struct BroadcastQueueReader<'a, T: Clone> {
    queue: &'a BroadcastQueue<T>,
    index: usize,
}

impl<'a, T: Clone> BroadcastQueueReader<'a, T> {
    pub fn next(&mut self) -> Option<T> {
        self.queue.vec.read().unwrap().get(self.index).map(|v| {
            self.index += 1;
            v.clone()
        })
    }

    pub fn available(&mut self) -> bool {
        self.index < self.queue.vec.read().unwrap().len()
    }
}