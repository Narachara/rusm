//! Execution session: owns the tracee and runs code snippets against its
//! persistent register / memory state. This is what the UI drives.

use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Result, bail};
use nix::sys::signal::Signal;

use crate::arch::{Arch, RegState};
use crate::asm::{AsmError, Assembled, Assembler, Layout};
use crate::elf;
use crate::tracee::{Output, Stop, Tracee};

/// Size of the code region at the start address. Notebook cells are laid
/// out one after another in it; it is writable so cells can hold data too.
pub const CODE_REGION: usize = 0x100000;

/// The data region (`.data`, `.rodata`, `.bss`) starts this far after the
/// start address. Readable and writable, not executable; starts zeroed.
pub const DATA_OFFSET: u64 = 0x200000;
pub const DATA_REGION: usize = 0x100000;

pub struct Options {
    pub start: u64,
    pub pass_signals: bool,
    pub timeout: Duration,
    /// Keep address space randomization (stack address changes per process).
    pub aslr: bool,
    pub save_exe: Option<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// Ran to the end of the code.
    Done,
    /// Stopped by a signal that was not delivered.
    Signal { sig: Signal, addr: Option<u64> },
    /// Hit a trap at `at`, not the one right after the code: execution ran
    /// into a label with no code after it, fell off a function without
    /// `ret`, or hit an explicit `int3`.
    StrayTrap { at: u64 },
    /// Interrupted after the timeout (e.g. an infinite loop).
    Timeout,
    /// Blocked reading stdin with nothing to read. Queue input and
    /// [`resume`](Session::resume), or close stdin.
    WaitingForInput,
    /// The process exited or was killed; a fresh one has been started.
    Exited { status: i32 },
}

/// A system call the seccomp filter caught and the session handled without
/// running it (currently only `execve`, which would replace the process).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyscallEvent {
    pub name: &'static str,
    /// The decoded call, e.g. `execve("/bin//sh", ["/bin//sh"], NULL)`.
    pub call: String,
    /// The value put in the return register in place of running it.
    pub ret: i64,
    /// Why it was not run / what the return means.
    pub note: String,
}

pub struct Session {
    arch: Box<dyn Arch>,
    asm: Box<dyn Assembler>,
    opts: Options,
    elf: Vec<u8>,
    seccomp: Vec<libc::sock_filter>,
    tracee: Tracee,
    /// Bytes at `start` that may hold stale code from a previous run.
    dirty: usize,
    pub regs: RegState,
    pub prev_regs: Option<RegState>,
    /// Program output not yet collected with [`take_output`](Self::take_output).
    output: Output,
    /// Intercepted system calls not yet collected with [`take_syscalls`](Self::take_syscalls).
    syscalls: Vec<SyscallEvent>,
}

impl Session {
    pub fn new(arch: Box<dyn Arch>, asm: Box<dyn Assembler>, opts: Options) -> Result<Self> {
        if !opts.start.is_multiple_of(0x1000) {
            bail!("start address {:#x} is not page aligned", opts.start);
        }
        let region: Vec<u8> = arch
            .trap()
            .iter()
            .copied()
            .cycle()
            .take(CODE_REGION)
            .collect();
        let segments = [
            elf::Segment {
                vaddr: opts.start,
                data: &region,
                memsz: CODE_REGION as u64,
                flags: elf::PF_R | elf::PF_W | elf::PF_X,
            },
            elf::Segment {
                vaddr: opts.start + DATA_OFFSET,
                data: &[],
                memsz: DATA_REGION as u64,
                flags: elf::PF_R | elf::PF_W,
            },
        ];
        let elf = elf::build_elf64(arch.elf_machine(), opts.start, &segments);
        if let Some(path) = &opts.save_exe {
            std::fs::write(path, &elf)?;
            std::fs::set_permissions(path, std::os::unix::fs::PermissionsExt::from_mode(0o755))?;
        }
        let seccomp = arch.seccomp_filter();
        let tracee = Tracee::spawn(&elf, opts.aslr, &seccomp)?;
        let regs = arch.read_regs(&tracee)?;
        Ok(Self {
            arch,
            asm,
            opts,
            elf,
            seccomp,
            tracee,
            dirty: 0,
            regs,
            prev_regs: None,
            output: Output::default(),
            syscalls: Vec::new(),
        })
    }

    pub fn pid(&self) -> nix::unistd::Pid {
        self.tracee.pid()
    }

    pub fn arch(&self) -> &dyn Arch {
        self.arch.as_ref()
    }

    pub fn start(&self) -> u64 {
        self.opts.start
    }

    /// End of the code region (exclusive).
    pub fn code_end(&self) -> u64 {
        self.opts.start + CODE_REGION as u64
    }

    /// Start and end (exclusive) of the data region.
    pub fn data_range(&self) -> std::ops::Range<u64> {
        let at = self.opts.start + DATA_OFFSET;
        at..at + DATA_REGION as u64
    }

    /// Assemble for the start of the code and data regions, with no
    /// external symbols (pipe mode and the line REPL).
    pub fn assemble(&self, src: &str) -> Result<Assembled, Vec<AsmError>> {
        let layout = Layout {
            code: self.opts.start,
            data: self.data_range().start,
        };
        self.asm.assemble(src, layout, &[])
    }

    pub fn assemble_at(
        &self,
        src: &str,
        layout: Layout,
        externs: &[(String, u64)],
    ) -> Result<Assembled, Vec<AsmError>> {
        self.asm.assemble(src, layout, externs)
    }

    /// Write initialized data at `addr`. Must fit in the data region.
    pub fn place_data(&mut self, addr: u64, data: &[u8]) -> Result<()> {
        let r = self.data_range();
        let end = addr + data.len() as u64;
        if addr < r.start || end > r.end {
            bail!(
                "data at {addr:#x}..{end:#x} does not fit the data region {:#x}..{:#x}",
                r.start,
                r.end
            );
        }
        self.tracee.write_mem(addr, data)
    }

    /// Load the data of `a` at the start of the data region and run its code
    /// from the start address, as [`run`](Self::run) does.
    pub fn run_assembled(&mut self, a: &Assembled) -> Result<Outcome> {
        if !a.data.is_empty() {
            self.place_data(self.data_range().start, &a.data)?;
        }
        self.run(&a.code)
    }

    /// Write `code` at `addr` followed by a trap. Must fit in the code region.
    pub fn place(&mut self, addr: u64, code: &[u8]) -> Result<()> {
        let trap = self.arch.trap();
        let end = addr + (code.len() + trap.len()) as u64;
        if addr < self.opts.start || end > self.code_end() {
            bail!(
                "code at {addr:#x}..{end:#x} does not fit the code region (ends at {:#x})",
                self.code_end()
            );
        }
        let mut buf = code.to_vec();
        buf.extend_from_slice(trap);
        self.tracee.write_mem(addr, &buf)
    }

    /// Write `code` at the start address, run it until it traps, and update
    /// the register snapshot. Each call replaces the previous code (rappel
    /// semantics); the notebook uses [`place`](Self::place) and
    /// [`exec`](Self::exec) instead.
    pub fn run(&mut self, code: &[u8]) -> Result<Outcome> {
        let trap = self.arch.trap();
        if code.len() + trap.len() > CODE_REGION {
            bail!(
                "code too large ({:#x} bytes, max {:#x})",
                code.len(),
                CODE_REGION - trap.len()
            );
        }

        // Code followed by traps, covering whatever the last run left behind.
        let len = (code.len() + trap.len()).max(self.dirty);
        let mut buf = code.to_vec();
        buf.extend(trap.iter().copied().cycle().take(len - code.len()));
        self.tracee.write_mem(self.opts.start, &buf)?;
        self.dirty = code.len();

        self.exec(self.opts.start, self.opts.start + code.len() as u64)
    }

    /// Run from `addr` until the next trap, fault, timeout or exit. `end`
    /// is where the code's own trap sits (the end of the code).
    pub fn exec(&mut self, addr: u64, end: u64) -> Result<Outcome> {
        self.arch.set_pc(&self.tracee, addr)?;
        self.resume(end)
    }

    /// Continue from where the tracee stopped (e.g. after it waited for
    /// input). An interrupted system call is restarted by the kernel.
    pub fn resume(&mut self, end: u64) -> Result<Outcome> {
        let mut deliver = None;
        let outcome = loop {
            let read_nr = self.arch.read_syscall();
            match self
                .tracee
                .cont(deliver.take(), self.opts.timeout, &mut self.output, read_nr)?
            {
                Stop::Trap => {
                    self.arch.rewind_trap(&self.tracee)?;
                    let pc = self.arch.read_regs(&self.tracee)?.pc;
                    break if pc == end {
                        Outcome::Done
                    } else {
                        Outcome::StrayTrap { at: pc }
                    };
                }
                Stop::Signal { sig, .. } if self.opts.pass_signals || ignored_by_default(sig) => {
                    // Harmless signals go straight through (the kernel ignores
                    // them, or the program's own handler runs).
                    deliver = Some(sig)
                }
                Stop::Seccomp => self.handle_seccomp()?,
                Stop::Signal { sig, addr } => break Outcome::Signal { sig, addr },
                Stop::Timeout {
                    syscall: Some((nr, 0)),
                } if nr == self.arch.read_syscall() => {
                    break Outcome::WaitingForInput;
                }
                Stop::Timeout { .. } => break Outcome::Timeout,
                Stop::Exiting { status } => {
                    // Show the final state of the dying process, then replace it.
                    self.snapshot()?;
                    self.respawn()?;
                    return Ok(Outcome::Exited { status });
                }
                Stop::Gone => {
                    self.respawn()?;
                    self.snapshot()?;
                    return Ok(Outcome::Exited { status: 0 });
                }
            }
        };
        self.snapshot()?;
        Ok(outcome)
    }

    /// A system call the filter caught stopped the tracee at its entry.
    /// Decode it, record it, make it return a plausible value without
    /// running it, and let the tracee carry on (the `execve` case: we show
    /// the call but do not let it replace the process we manage).
    fn handle_seccomp(&mut self) -> Result<()> {
        let nr = self.arch.syscall_nr(&self.tracee)?;
        let regs = self.arch.read_regs(&self.tracee)?;
        let event = if nr == libc::SYS_execve as u64 {
            self.decode_execve(&regs)
        } else {
            // Not expected (the filter only traces execve), but handle it:
            // let the call run normally rather than cancelling it.
            return Ok(());
        };
        self.arch.cancel_syscall(&self.tracee, event.ret as u64)?;
        self.syscalls.push(event);
        Ok(())
    }

    /// Decode `execve(path, argv, envp)` from the argument registers and
    /// judge whether it would have succeeded (the tracee shares our
    /// filesystem and user), choosing the value it returns in its place.
    fn decode_execve(&self, regs: &RegState) -> SyscallEvent {
        let arg = |name: &str| {
            regs.gp
                .iter()
                .find(|r| r.name == name)
                .map_or(0, |r| r.value)
        };
        let path = self.read_cstr(arg("rdi"));
        let argv = self.read_strv(arg("rsi"));
        let envp = arg("rdx");
        let argv_str = match &argv {
            None => "NULL".to_string(),
            Some(v) => format!("[{}]", v.join(", ")),
        };
        let envp_str = if envp == 0 { "NULL" } else { "envp" };
        let path_str = path.as_deref().unwrap_or("<unreadable>");
        let call = format!("execve({path_str:?}, {argv_str}, {envp_str})");

        let (ret, note) = match path.as_deref().and_then(would_exec) {
            Some(true) => (0, "would succeed; not executed".into()),
            Some(false) => (
                -(libc::EACCES as i64),
                "would fail EACCES: not an executable file; not executed".into(),
            ),
            None => (
                -(libc::ENOENT as i64),
                "would fail ENOENT: no such file; not executed".into(),
            ),
        };
        SyscallEvent {
            name: "execve",
            call,
            ret,
            note,
        }
    }

    /// Read a NUL-terminated string from the tracee, capped for display.
    fn read_cstr(&self, addr: u64) -> Option<String> {
        const MAX: usize = 128;
        if addr == 0 {
            return None;
        }
        let bytes = self.tracee.read_mem(addr, MAX).ok()?;
        let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
        Some(String::from_utf8_lossy(&bytes[..end]).into_owned())
    }

    /// Read a NULL-terminated array of string pointers (argv / envp), each
    /// element quoted, capped in count.
    fn read_strv(&self, addr: u64) -> Option<Vec<String>> {
        const MAX_ARGS: usize = 8;
        if addr == 0 {
            return None;
        }
        let word = self.arch.word_size();
        let mut out = Vec::new();
        for i in 0..MAX_ARGS {
            let Ok(bytes) = self.tracee.read_mem(addr + (i * word) as u64, word) else {
                break;
            };
            let mut p = [0u8; 8];
            p[..word].copy_from_slice(&bytes);
            let ptr = u64::from_le_bytes(p);
            if ptr == 0 {
                return Some(out);
            }
            out.push(match self.read_cstr(ptr) {
                Some(s) => format!("{s:?}"),
                None => "<unreadable>".to_string(),
            });
        }
        out.push("...".to_string());
        Some(out)
    }

    /// Output the program wrote since the last call.
    pub fn take_output(&mut self) -> Output {
        std::mem::take(&mut self.output)
    }

    /// System calls intercepted since the last call.
    pub fn take_syscalls(&mut self) -> Vec<SyscallEvent> {
        std::mem::take(&mut self.syscalls)
    }

    pub fn write_stdin(&mut self, data: &[u8]) -> Result<()> {
        self.tracee.write_stdin(data)
    }

    pub fn close_stdin(&mut self) {
        self.tracee.close_stdin();
    }

    /// Kill the tracee and start from a clean process.
    pub fn restart(&mut self) -> Result<()> {
        self.respawn()?;
        self.prev_regs = None;
        self.regs = self.arch.read_regs(&self.tracee)?;
        Ok(())
    }

    fn respawn(&mut self) -> Result<()> {
        self.tracee = Tracee::spawn(&self.elf, self.opts.aslr, &self.seccomp)?;
        self.dirty = 0;
        Ok(())
    }

    fn snapshot(&mut self) -> Result<()> {
        let regs = self.arch.read_regs(&self.tracee)?;
        self.prev_regs = Some(std::mem::replace(&mut self.regs, regs));
        Ok(())
    }

    pub fn read_mem(&self, addr: u64, len: usize) -> Result<Vec<u8>> {
        self.tracee.read_mem(addr, len)
    }

    pub fn write_mem(&self, addr: u64, data: &[u8]) -> Result<()> {
        self.tracee.write_mem(addr, data)
    }

    pub fn maps(&self) -> Result<String> {
        self.tracee.maps()
    }
}

/// Whether `execve(path)` would plausibly succeed: a regular file with an
/// execute bit. `None` means the path does not exist (ENOENT). This is a
/// best-effort check; it does not model `#!` interpreters or ELF arch.
fn would_exec(path: &str) -> Option<bool> {
    use std::os::unix::fs::PermissionsExt;
    let meta = std::fs::metadata(path).ok()?;
    Some(meta.is_file() && meta.permissions().mode() & 0o111 != 0)
}

/// Signals whose default action is to do nothing; they should not stop a cell.
fn ignored_by_default(sig: Signal) -> bool {
    matches!(
        sig,
        Signal::SIGWINCH | Signal::SIGCHLD | Signal::SIGURG | Signal::SIGCONT
    )
}
