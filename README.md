# libLISA
LibLISA is a library for Learning Instruction Set Architecture semantics. It only needs to know about CPU registers, flags, memory and how to observe the execution of a single instruction. From there, libLISA can learn the semantics of x86-64 instructions that use general-purpose registers and flags.

# Results
We ran libLISA for around 300 hours and enumerated around 25,000 encodings. From that, we learned the correct semantics for around 4,000 encodings in around 40 hours. These 4000 encodings represent around 5% of the x86-64 instruction space. We provide the results in the `results/` directory. The `encodings-enumerated.json` file contains all encodings that we enumerated. The `encodings-correct.json` file contains all encodings with correct semantics.

## Using the results
Results are stored by serializing the structures to JSON via the `serde_json` crate. We provide a file containing all encodings that have been enumerated, as well as a file containing the encodings with correctly synthesized computations. The former are stored as a `Vec<Encoding<X64Arch, BasicComputation>>`, while the latter are stored as a `Vec<Encoding<X64Arch, DecisionTreeComputation>>`.

The easiest way to use the results is to load them using the `serde_json` crate. This can be done as follows:

```rust
let file = File::open("results/encodings-enumerated.json")?;
let enumerated_encodings: Vec<Encoding<X64Arch, BasicComputation>> = serde_json::from_reader(file)?;
```

# Learning semantics
You can build all binaries by running `cargo build --release`. The binaries can then be found in `target/release/`. You can also run binaries directly by running `cargo run --release --bin [name of binary] -- [arguments..]`. Learning the semantics of a CPU is split into three phases:

* Preparation: Create an output directory. Replace `$DIR` with your output directory in all following commands.
* Phase 1: Enumeration
    * (Optional) scan the instruction space by running `scan $DIR/scan-output.json`.
    * Create a new enumerator by running `enumerate $DIR/enumeration/ create --workers 16`. You may optionally specify the instruction scan with `--scan $DIR/scan-output.json`
    * Run enumeration with `enumerate $DIR/enumeration run`. You can terminate this process at any time by sending `^C`. This will gracefully terminate the worker threads and save state to disk. You may also check the progress of the enumeration by running `enumerate $DIR/enumeration/ status`.
    * Once enumeration has finished or you are satisfied with the number of instructions that were enumerated, you can run `enumerate $DIR/enumeration/ extract $DIR/encodings-enumerated.json` to extract all enumerated encodings.
* Phase 2: Synthesis
    * Create an address synthesizer by running `synthesize-addrs $DIR/synthesis/addrs/ create --workers 16`.
    * Run address synthesis with `synthesize-addrs $DIR/synthesis/addrs/ run`. You can terminate this process at any time by sending `^C`. This will gracefully terminate the worker threads and save state to disk. You may also check the progress of the synthesis by running `synthesize-addrs $DIR/synthesis/addrs/ status`.
    * Once address synthesis has finished or you are satisfied with the number of synthesized addresses, you can start synthesizing dataflows. Create a dataflow synthesizer by running `synthesize-dataflows $DIR/synthesis/dataflows/ create $DIR/synthesis/addrs/ --workers 16`.
    * Run address synthesis with `synthesize-dataflows $DIR/synthesis/dataflows/ run`. You can terminate this process at any time by sending `^C`. This will gracefully terminate the worker threads and save state to disk. You may also check the progress of the synthesis by running `synthesize-dataflows $DIR/synthesis/dataflows/ status`.
    * Once dataflow synthesis has finished or you are satisfied with the number of synthesized dataflows, you can extract encodings with computations by running `synthesize-dataflows $DIR/synthesis/dataflows/ extract $DIR/encodings-synthesized.json`. You must pass the `--partial` flag if dataflow synthesis has not finished synthesizing all computations.
* Phase 3: Validation
    * Create a correctness verifier by running `verify-correctness $DIR/correctness/ create $DIR/encodings-synthesized.json`.
    * Run correctness verification with `verify-correctness $DIR/correctness/ run`. You can terminate this process at any time by sending `^C`. This will gracefully terminate the worker threads and save state to disk. You may also check the progress of the synthesis by running `verify-correctness $DIR/correctness/ status`.
    * Once correctness verification has has finished or you are satisfied with the time spent on validation, you can extract the correct encodings by running `verify-correctness $DIR/correctness/ extract $DIR/encodings-correct.json`.

# Project structure
The project is split into six crates:

 * `liblisa-core` contains generic definitions of CPU state, ISAs, encodings, dataflows and other core components of libLISA.
 * `liblisa-enc` contains all code for encoding analysis.
 * `liblisa-synth` contains all code for the synthesis of computations.
 * `liblisa` contains some high-level code for processing encodings as well as code to handle long-running enumeration, synthesis, or validation sessions that can be interrupted at any time.
 * `liblisa-x64` contains all code related to the x64 architecture. It defines registers, flags and CPU state. It also provides implementations for observing the execution of instructions.
 * `liblisa-x64-kmod` contains the kernel module and a wrapper library.
 * `lisacli` contains code for the command-line (CLI) binaries that can be used to invoke libLISA.

# License
The code in this repository is licensed under the AGPLv3, except for the kernel module in `liblisa-x64-kmod/module/` which is licensed under the GNU Public License v2. The results in the `results/` directory are released under a Creative Commons Zero license.