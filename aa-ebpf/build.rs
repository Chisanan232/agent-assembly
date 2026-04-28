//! Build script for `aa-ebpf`.
//!
//! Invokes `aya-build` to cross-compile `aa-ebpf-programs` for the
//! `bpfel-unknown-none` target and embed the resulting ELF bytecode so that
//! the userspace loader can access it at runtime via
//! `include_bytes_aligned!(concat!(env!("OUT_DIR"), "/aa-ebpf-programs"))`.

use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR")
        .expect("CARGO_MANIFEST_DIR not set by Cargo");

    // The eBPF programs crate lives at `../aa-ebpf-programs` relative to
    // this crate's manifest directory.
    let ebpf_programs_dir = PathBuf::from(&manifest_dir)
        .parent()
        .expect("aa-ebpf must be a direct child of the workspace root")
        .join("aa-ebpf-programs");

    aya_build::build_ebpf_programs(&ebpf_programs_dir)?;

    // Re-run when the programs source changes.
    println!("cargo:rerun-if-changed={}", ebpf_programs_dir.display());

    Ok(())
}
