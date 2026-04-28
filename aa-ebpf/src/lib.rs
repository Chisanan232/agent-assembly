//! eBPF-based kernel-level monitoring hooks for Agent Assembly — Layer 3.
//!
//! This crate is the **userspace** half of the aa-ebpf subsystem.  It loads
//! the compiled eBPF programs (from `aa-ebpf-programs`), attaches the probes
//! to the kernel, and reads structured events from the shared BPF ring buffer.
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────┐
//! │  aa-ebpf (userspace)                         │
//! │                                              │
//! │  EbpfLoader ──► UprobeManager  (AAASM-37)   │
//! │             ──► KprobeManager  (AAASM-38)   │
//! │             ──► TracepointManager (AAASM-39) │
//! │                                              │
//! │  RingBufReader ◄── BPF ring buffer           │
//! └─────────────────────────────────────────────┘
//!          │ kernel boundary │
//! ┌─────────────────────────────────────────────┐
//! │  aa-ebpf-programs (bpfel-unknown-none)       │
//! │                                              │
//! │  ssl_write_uprobe / ssl_read_uretprobe       │
//! │  openat_kprobe / write_kprobe / unlink_kprobe│
//! │  sched_process_exec (tracepoint)             │
//! └─────────────────────────────────────────────┘
//! ```
//!
//! ## Shared types
//!
//! Event structs shared between kernel-space and userspace live in
//! [`aa_ebpf_common`].  They are `#[repr(C)]` and `no_std` so they compile
//! for both targets without modification.
//!
//! ## Usage
//!
//! ```rust,ignore
//! use aa_ebpf::{loader::EbpfLoader, ringbuf::RingBufReader};
//! use aa_ebpf::{uprobe::UprobeManager, kprobe::KprobeManager};
//! use aa_ebpf::tracepoint::TracepointManager;
//!
//! let mut bpf = EbpfLoader::load()?;
//! let _uprobes  = UprobeManager::attach(&mut bpf, Some(target_pid))?;
//! let _kprobes  = KprobeManager::attach(&mut bpf, Some(target_pid))?;
//! let _tp       = TracepointManager::attach(&mut bpf)?;
//! let mut reader = RingBufReader::new(bpf)?;
//!
//! while let Some(event) = reader.next().await? {
//!     // forward event to aa-runtime governance pipeline
//! }
//! ```

pub mod error;
pub mod kprobe;
pub mod loader;
pub mod ringbuf;
pub mod tracepoint;
pub mod uprobe;

pub use error::EbpfError;
pub use ringbuf::EbpfEvent;
