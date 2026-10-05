use anyhow::Result;
use std::collections::BTreeMap;

use iced_x86::{
    Decoder, DecoderOptions, Formatter, Instruction, IntelFormatter, SymbolResolver, SymbolResult,
};

use super::{Arch, ArchKind, Flag, Insn, Reg, RegState};
use crate::tracee::Tracee;

const EM_X86_64: u16 = 62;
const NT_PRSTATUS: libc::c_int = 1;
const NT_PRFPREG: libc::c_int = 2;

const FLAGS: [(&str, u32); 7] = [
    ("cf", 0),
    ("zf", 6),
    ("of", 11),
    ("sf", 7),
    ("pf", 2),
    ("af", 4),
    ("df", 10),
];

pub struct X86_64;

impl Arch for X86_64 {
    fn kind(&self) -> ArchKind {
        ArchKind::X86_64
    }

    fn elf_machine(&self) -> u16 {
        EM_X86_64
    }

    fn word_size(&self) -> usize {
        8
    }

    fn trap(&self) -> &'static [u8] {
        &[0xcc]
    }

    fn read_regs(&self, t: &Tracee) -> Result<RegState> {
        let r: libc::user_regs_struct = t.get_regset(NT_PRSTATUS)?;
        let fp: libc::user_fpregs_struct = t.get_regset(NT_PRFPREG)?;

        let reg = |name, value| Reg { name, value };
        let gp = vec![
            reg("rax", r.rax),
            reg("rbx", r.rbx),
            reg("rcx", r.rcx),
            reg("rdx", r.rdx),
            reg("rsi", r.rsi),
            reg("rdi", r.rdi),
            reg("rip", r.rip),
            reg("rsp", r.rsp),
            reg("rbp", r.rbp),
            reg("r8", r.r8),
            reg("r9", r.r9),
            reg("r10", r.r10),
            reg("r11", r.r11),
            reg("r12", r.r12),
            reg("r13", r.r13),
            reg("r14", r.r14),
            reg("r15", r.r15),
        ];
        let extra = vec![
            reg("cs", r.cs),
            reg("ss", r.ss),
            reg("ds", r.ds),
            reg("es", r.es),
            reg("fs", r.fs),
            reg("gs", r.gs),
            reg("fs_base", r.fs_base),
            reg("gs_base", r.gs_base),
        ];
        let flags = FLAGS
            .iter()
            .map(|&(name, bit)| Flag {
                name,
                set: r.eflags >> bit & 1 == 1,
            })
            .collect();

        let xmm = |i: usize| {
            let w = &fp.xmm_space[i * 4..i * 4 + 4];
            (0..4).fold(0u128, |acc, j| acc | (w[j] as u128) << (32 * j))
        };
        let st = |i: usize| {
            // 80-bit x87 values stored in 16-byte slots.
            let w = &fp.st_space[i * 4..i * 4 + 4];
            (0..4).fold(0u128, |acc, j| acc | (w[j] as u128) << (32 * j))
        };
        let mut vector: Vec<_> = (0..16).map(|i| (format!("xmm{i}"), xmm(i))).collect();
        vector.extend((0..8).map(|i| (format!("st{i}"), st(i))));
        vector.push(("mxcsr".into(), fp.mxcsr as u128));

        Ok(RegState {
            gp,
            pc: r.rip,
            sp: r.rsp,
            flags_name: "efl",
            flags_raw: r.eflags,
            flags,
            extra,
            vector,
        })
    }

    fn set_pc(&self, t: &Tracee, pc: u64) -> Result<()> {
        let mut r: libc::user_regs_struct = t.get_regset(NT_PRSTATUS)?;
        r.rip = pc;
        // The kernel restarts an interrupted syscall only if orig_rax >= 0.
        r.orig_rax = u64::MAX;
        t.set_regset(NT_PRSTATUS, &r)
    }

    fn read_syscall(&self) -> u64 {
        libc::SYS_read as u64
    }

    fn seccomp_filter(&self) -> Vec<libc::sock_filter> {
        super::seccomp::trace_filter(libc::SYS_execve as u32)
    }

    fn syscall_nr(&self, t: &Tracee) -> Result<u64> {
        let r: libc::user_regs_struct = t.get_regset(NT_PRSTATUS)?;
        Ok(r.orig_rax)
    }

    fn cancel_syscall(&self, t: &Tracee, ret: u64) -> Result<()> {
        let mut r: libc::user_regs_struct = t.get_regset(NT_PRSTATUS)?;
        // orig_rax = -1 makes the kernel skip the system call; rax becomes
        // its "return value" (see set_pc's note on orig_rax).
        r.orig_rax = u64::MAX;
        r.rax = ret;
        t.set_regset(NT_PRSTATUS, &r)
    }

    fn rewind_trap(&self, t: &Tracee) -> Result<()> {
        let mut r: libc::user_regs_struct = t.get_regset(NT_PRSTATUS)?;
        r.rip -= self.trap().len() as u64;
        t.set_regset(NT_PRSTATUS, &r)
    }

    fn disassemble(&self, code: &[u8], addr: u64, symbols: &BTreeMap<u64, String>) -> Vec<Insn> {
        let mut dec = Decoder::with_ip(64, code, addr, DecoderOptions::NONE);
        let resolver = Symbols(symbols.clone());
        let mut fmt = IntelFormatter::with_options(Some(Box::new(resolver)), None);
        let opts = fmt.options_mut();
        opts.set_hex_prefix("0x");
        opts.set_hex_suffix("");
        opts.set_uppercase_hex(false);
        opts.set_small_hex_numbers_in_decimal(false);
        opts.set_space_after_operand_separator(true);
        let mut insn = Instruction::default();
        let mut out = Vec::new();
        while dec.can_decode() {
            dec.decode_out(&mut insn);
            let off = (insn.ip() - addr) as usize;
            let mut text = String::new();
            fmt.format(&insn, &mut text);
            out.push(Insn {
                addr: insn.ip(),
                bytes: code[off..off + insn.len()].to_vec(),
                text,
            });
        }
        out
    }
}

/// Resolves addresses to the nearest preceding symbol; iced prints the
/// difference as `+off`.
struct Symbols(BTreeMap<u64, String>);

/// Don't label addresses further than this past a symbol.
const MAX_SYMBOL_OFFSET: u64 = 0x1000;

impl SymbolResolver for Symbols {
    fn symbol(
        &mut self,
        _instruction: &Instruction,
        _operand: u32,
        _instruction_operand: Option<u32>,
        address: u64,
        _address_size: u32,
    ) -> Option<SymbolResult<'_>> {
        let (&at, name) = self.0.range(..=address).next_back()?;
        (address - at < MAX_SYMBOL_OFFSET).then(|| SymbolResult::with_str(at, name.as_str()))
    }
}
