use std::{env, path::PathBuf};

fn main() {
    // Tell cargo to invalidate the built crate whenever the wrapper changes
    println!("cargo:rerun-if-changed=/usr/include/linux/elf.h");

    let bindings = bindgen::Builder::default()
        .header("/usr/include/linux/elf.h")
        .header("/usr/include/sys/ucontext.h")
        .header("/usr/include/sys/syscall.h")
        .header("/usr/include/signal.h")
        .parse_callbacks(Box::new(bindgen::CargoCallbacks))
        .generate()
        .expect("Unable to generate bindings");

    // Write the bindings to the $OUT_DIR/bindings.rs file.
    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");
}