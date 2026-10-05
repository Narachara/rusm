//! Architecture backends. Everything ISA-specific (register layout, trap
//! instruction, ELF machine, disassembly) lives behind [`Arch`], so the
//! session and UI stay architecture-neutral.

use std::collections::BTreeMap;

use anyhow::Result;
use clap::ValueEnum;

use crate::tracee::Tracee;

mod seccomp;
mod x86_64;

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum ArchKind {
    #[value(name = "x86_64", alias = "amd64")]
    X86_64,
    // Aarch64, Armv7, X86 ...
}

impl ArchKind {
    pub fn host() -> Option<Self> {
        match std::env::consts::ARCH {
            "x86_64" => Some(Self::X86_64),
            _ => None,
        }
    }
}

pub fn create(kind: ArchKind) -> Box<dyn Arch> {
    match kind {
        ArchKind::X86_64 => Box::new(x86_64::X86_64),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reg {
    pub name: &'static str,
    pub value: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Flag {
    pub name: &'static str,
    pub set: bool,
}

/// A snapshot of the tracee's registers in display-ready form.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RegState {
    /// General purpose registers, including pc and sp, in display order.
    pub gp: Vec<Reg>,
    pub pc: u64,
    pub sp: u64,
    /// Raw flags / status register and its decoded bits.
    pub flags_name: &'static str,
    pub flags_raw: u64,
    pub flags: Vec<Flag>,
    /// Segment / system registers shown next to the flags.
    pub extra: Vec<Reg>,
    /// Vector / FP registers (shown with "all registers").
    pub vector: Vec<(String, u128)>,
}

#[derive(Debug, Clone)]
pub struct Insn {
    pub addr: u64,
    pub bytes: Vec<u8>,
    pub text: String,
}

pub trait Arch {
    fn kind(&self) -> ArchKind;
    /// ELF e_machine value.
    fn elf_machine(&self) -> u16;
    fn word_size(&self) -> usize;
    /// Breakpoint instruction used to fill the code region.
    fn trap(&self) -> &'static [u8];

    fn read_regs(&self, t: &Tracee) -> Result<RegState>;
    /// Move the pc, cancelling any pending restart of an interrupted
    /// system call (it would otherwise be re-issued at the new pc).
    fn set_pc(&self, t: &Tracee, pc: u64) -> Result<()>;
    /// Number of the `read` system call.
    fn read_syscall(&self) -> u64;

    /// A seccomp filter installed in the tracee before exec. It must return
    /// `SECCOMP_RET_TRACE` for the system calls the session wants to catch
    /// at a `PTRACE_EVENT_SECCOMP` stop (currently `execve`), and
    /// `SECCOMP_RET_ALLOW` for all others, so only those calls stop the
    /// tracee and everything else runs at full speed.
    fn seccomp_filter(&self) -> Vec<libc::sock_filter>;
    /// Number of the system call the tracee is entering (at a seccomp stop).
    fn syscall_nr(&self, t: &Tracee) -> Result<u64>;
    /// At a syscall-entry stop, cancel the call so the kernel does not run
    /// it, and make it return `ret` instead.
    fn cancel_syscall(&self, t: &Tracee, ret: u64) -> Result<()>;
    /// Called after the tracee stopped on a trap, so the pc can be moved
    /// back onto the trap instruction (x86 reports the address after int3).
    fn rewind_trap(&self, t: &Tracee) -> Result<()>;

    /// Disassemble `code` loaded at `addr`. Branch targets and addresses
    /// are shown as `symbol+off` using the nearest preceding entry of
    /// `symbols` (address -> name).
    fn disassemble(&self, code: &[u8], addr: u64, symbols: &BTreeMap<u64, String>) -> Vec<Insn>;
}
