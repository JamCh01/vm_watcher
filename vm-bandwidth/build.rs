use anyhow::{anyhow, Context as _};
use aya_build::Toolchain;

fn toolchain() -> Toolchain<'static> {
    // eBPF bitcode must be produced by an LLVM that the installed bpf-linker can read.
    // Override with e.g. VM_BW_EBPF_TOOLCHAIN=nightly-2026-06-15 when the default nightly
    // is ahead of the linker's LLVM.
    match std::env::var("VM_BW_EBPF_TOOLCHAIN") {
        Ok(name) => {
            let leaked: &'static str = Box::leak(name.into_boxed_str());
            Toolchain::Custom(leaked)
        }
        Err(_) => Toolchain::default(),
    }
}

fn main() -> anyhow::Result<()> {
    // `AYA_BUILD_SKIP=1` builds userspace only (e.g. `cargo test` on a laptop without the
    // nightly/bpf-linker eBPF toolchain). A placeholder object keeps include_bytes_aligned!
    // happy; it can never be loaded at runtime.
    println!("cargo:rerun-if-env-changed=AYA_BUILD_SKIP");
    if std::env::var_os("AYA_BUILD_SKIP").is_some() {
        let out_dir = std::env::var("OUT_DIR").context("OUT_DIR not set")?;
        std::fs::write(std::path::Path::new(&out_dir).join("vm-bandwidth"), b"")
            .context("writing placeholder eBPF object")?;
        return Ok(());
    }

    let cargo_metadata::Metadata { packages, .. } = cargo_metadata::MetadataCommand::new()
        .no_deps()
        .exec()
        .context("MetadataCommand::exec")?;
    let ebpf_package = packages
        .into_iter()
        .find(|cargo_metadata::Package { name, .. }| name.as_str() == "vm-bandwidth-ebpf")
        .ok_or_else(|| anyhow!("vm-bandwidth-ebpf package not found"))?;
    let cargo_metadata::Package {
        name,
        manifest_path,
        ..
    } = ebpf_package;
    let ebpf_package = aya_build::Package {
        name: name.as_str(),
        root_dir: manifest_path
            .parent()
            .ok_or_else(|| anyhow!("no parent for {manifest_path}"))?
            .as_str(),
        ..Default::default()
    };
    aya_build::build_ebpf([ebpf_package], toolchain())
}
