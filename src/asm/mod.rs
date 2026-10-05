//! Assembler backends.
//!
//! To add a backend (e.g. keystone): implement [`Assembler`], add a variant
//! to [`Backend`] and a match arm in [`create`]. Nothing else depends on the
//! concrete assembler.

use std::fmt;

use anyhow::{Result, bail};
use clap::ValueEnum;

use crate::arch::ArchKind;

mod nasm;

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum Backend {
    /// External `nasm` binary (x86 only).
    Nasm,
}

/// An assembly error, with the line number within the user's source when
/// the backend can tell.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AsmError {
    pub line: Option<usize>,
    pub msg: String,
}

impl fmt::Display for AsmError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.line {
            Some(l) => write!(f, "line {l}: {}", self.msg),
            None => write!(f, "{}", self.msg),
        }
    }
}

/// Where assembled output is loaded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Layout {
    /// Address of the code (`.text`).
    pub code: u64,
    /// Address of initialized data (`.data`, then `.rodata`); `.bss` follows.
    pub data: u64,
}

/// Output of a successful assembly.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Assembled {
    pub code: Vec<u8>,
    /// Initialized data, loaded at [`Layout::data`].
    pub data: Vec<u8>,
    /// Zeroed bytes reserved right after `data` (`.bss`, with alignment).
    pub bss: u64,
    /// Labels and constants the source defines. Local labels use their full
    /// name (`strlen.loop`). Backends that cannot report symbols leave this
    /// empty.
    pub symbols: Vec<(String, u64)>,
}

pub trait Assembler {
    /// Assemble `src` for `layout`. `externs` are symbols defined elsewhere
    /// (e.g. earlier notebook cells) that `src` may use or redefine.
    fn assemble(
        &self,
        src: &str,
        layout: Layout,
        externs: &[(String, u64)],
    ) -> Result<Assembled, Vec<AsmError>>;
}

pub fn create(backend: Backend, arch: ArchKind) -> Result<Box<dyn Assembler>> {
    match (backend, arch) {
        (Backend::Nasm, ArchKind::X86_64) => Ok(Box::new(nasm::Nasm { bits: 64 })),
        #[allow(unreachable_patterns)]
        (b, a) => bail!("assembler {b:?} does not support {a:?}"),
    }
}
