//! Building this crate has an undeclared dependency on the `bpf-linker` binary (the actual
//! linking is driven by `aya-build` from the userspace crate's build script). A missing
//! linker is reported as a warning here; it only becomes a hard error at link time.
fn main() {
    match which::which("bpf-linker") {
        Ok(path) => println!("cargo:rerun-if-changed={}", path.display()),
        Err(_) => println!(
            "cargo:warning=bpf-linker not found in PATH; install it with `cargo install bpf-linker`"
        ),
    }
}
