use std::env;
use std::path::PathBuf;

fn main() {
    let bindings = bindgen::Builder::default()
        .header("stddef.h")
        .header("stdint.h")
        .header("asm-generic/siginfo.h")
        .header("module/lisakmod.h")
        .whitelist_type("lisa_ioctl_struct")
        .generate()
        .expect("unable to generate bindings");

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings.write_to_file(out_path.join("bindings.rs"))
        .expect("couldn't write bindings!");

    let bindings = bindgen::Builder::default()
        .header("/usr/include/linux/elf.h")
        .header("/usr/include/sys/ucontext.h")
        .header("/usr/include/sys/syscall.h")
        .parse_callbacks(Box::new(bindgen::CargoCallbacks))
        .generate()
        .expect("Unable to generate bindings");

    // Write the bindings to the $OUT_DIR/bindings.rs file.
    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("ptrace_bindings.rs"))
        .expect("Couldn't write bindings!");
}