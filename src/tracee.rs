//! A traced child process running our minimal ELF.
//!
//! All ptrace calls for a tracee must come from the thread that spawned it.

use std::ffi::CString;
use std::fs::File;
use std::io::{Read, Write};
use std::mem::MaybeUninit;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::FileExt;
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use nix::sys::ptrace::{self, Options};
use nix::sys::signal::{Signal, kill};
use nix::sys::wait::{WaitPidFlag, WaitStatus, waitpid};
use nix::unistd::Pid;

/// Why the tracee stopped after being continued.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stop {
    /// Hit a breakpoint trap (normally the end of the code).
    Trap,
    /// Stopped with a signal; `addr` is the faulting address where relevant.
    Signal { sig: Signal, addr: Option<u64> },
    /// Did not stop within the timeout and was interrupted with SIGSTOP.
    /// `syscall` is the (number, first argument) of the system call it was
    /// blocked in, if any.
    Timeout { syscall: Option<(u64, u64)> },
    /// About to exit (PTRACE_EVENT_EXIT). Registers are still readable.
    /// `status` is a raw wait status.
    Exiting { status: i32 },
    /// Stopped at the entry of a system call the seccomp filter traces
    /// (`PTRACE_EVENT_SECCOMP`); the session inspects and cancels it.
    Seccomp,
    /// Already gone; nothing left to inspect.
    Gone,
}

/// What the tracee wrote to stdout and stderr.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Output {
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

impl Output {
    pub fn is_empty(&self) -> bool {
        self.stdout.is_empty() && self.stderr.is_empty()
    }
}

pub struct Tracee {
    pid: Pid,
    mem: File,
    /// Our ends of the tracee's standard streams. `stdin` is `None` once
    /// closed (the tracee then reads EOF).
    stdin: Option<File>,
    stdout: File,
    stderr: File,
}

/// A close-on-exec pipe: (read end, write end).
fn pipe() -> Result<(File, File)> {
    let mut fds = [0; 2];
    // SAFETY: plain syscall writing two fds we take ownership of.
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } < 0 {
        return Err(std::io::Error::last_os_error()).context("pipe2");
    }
    Ok(unsafe { (File::from_raw_fd(fds[0]), File::from_raw_fd(fds[1])) })
}

fn set_nonblocking(f: &File) {
    // SAFETY: fcntl on an fd we own.
    unsafe {
        let flags = libc::fcntl(f.as_raw_fd(), libc::F_GETFL);
        libc::fcntl(f.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK);
    }
}

/// Read everything currently available from a non-blocking pipe.
fn drain(f: &mut File, out: &mut Vec<u8>) {
    let mut buf = [0u8; 8192];
    while let Ok(n @ 1..) = f.read(&mut buf) {
        out.extend_from_slice(&buf[..n]);
    }
}

impl Tracee {
    /// Fork and exec `elf` under ptrace. Returns once the tracee is stopped
    /// at the post-exec trap, before executing any instruction. Without
    /// `aslr` the stack lands at the same address every time, which keeps
    /// notebook replays reproducible.
    pub fn spawn(elf: &[u8], aslr: bool, seccomp: &[libc::sock_filter]) -> Result<Self> {
        let name = CString::new("rusm-tracee").unwrap();
        // SAFETY: plain syscall; the fd is owned by `exe` from here on.
        let fd = unsafe { libc::memfd_create(name.as_ptr(), libc::MFD_CLOEXEC) };
        if fd < 0 {
            return Err(std::io::Error::last_os_error()).context("memfd_create");
        }
        let mut exe = unsafe { File::from_raw_fd(fd) };
        exe.write_all(elf).context("writing tracee image")?;

        // The tracee gets its own stdin/stdout/stderr, never our terminal.
        let (stdin_r, stdin_w) = pipe()?;
        let (stdout_r, stdout_w) = pipe()?;
        let (stderr_r, stderr_w) = pipe()?;

        let argv: [*const libc::c_char; 1] = [std::ptr::null()];
        let envp: [*const libc::c_char; 1] = [std::ptr::null()];

        // SAFETY: the child only makes async-signal-safe calls before exec.
        let pid = unsafe { libc::fork() };
        if pid < 0 {
            return Err(std::io::Error::last_os_error()).context("fork");
        }
        if pid == 0 {
            unsafe {
                if !aslr {
                    libc::personality(libc::ADDR_NO_RANDOMIZE as libc::c_ulong);
                }
                // Own session, no controlling terminal: terminal signals
                // (SIGWINCH on resize, SIGINT, ...) never reach the tracee.
                libc::setsid();
                // dup2 clears close-on-exec on the new descriptors.
                libc::dup2(stdin_r.as_raw_fd(), 0);
                libc::dup2(stdout_w.as_raw_fd(), 1);
                libc::dup2(stderr_w.as_raw_fd(), 2);
                libc::ptrace(libc::PTRACE_TRACEME, 0, 0, 0);
                // Best effort: without the filter, execve simply is not
                // intercepted (the tracee still runs). NO_NEW_PRIVS lets an
                // unprivileged process install a filter. The bootstrap below
                // uses fexecve (execveat), which the filter does not trace.
                if !seccomp.is_empty() && libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0 {
                    let prog = libc::sock_fprog {
                        len: seccomp.len() as u16,
                        filter: seccomp.as_ptr() as *mut libc::sock_filter,
                    };
                    libc::syscall(
                        libc::SYS_seccomp,
                        libc::SECCOMP_SET_MODE_FILTER,
                        0,
                        &prog as *const libc::sock_fprog,
                    );
                }
                libc::fexecve(exe.as_raw_fd(), argv.as_ptr(), envp.as_ptr());
                libc::_exit(127);
            }
        }
        drop((exe, stdin_r, stdout_w, stderr_w));
        let pid = Pid::from_raw(pid);
        for f in [&stdin_w, &stdout_r, &stderr_r] {
            set_nonblocking(f);
        }
        // Room for plenty of output between polls; best effort.
        for f in [&stdout_r, &stderr_r] {
            unsafe { libc::fcntl(f.as_raw_fd(), libc::F_SETPIPE_SZ, 1 << 20) };
        }

        match wait(pid)? {
            WaitStatus::Stopped(_, Signal::SIGTRAP) => {}
            other => bail!("tracee failed to start: {other:?}"),
        }
        ptrace::setoptions(
            pid,
            Options::PTRACE_O_EXITKILL
                | Options::PTRACE_O_TRACEEXIT
                | Options::PTRACE_O_TRACESECCOMP,
        )
        .context("PTRACE_SETOPTIONS")?;

        let mem = File::options()
            .read(true)
            .write(true)
            .open(format!("/proc/{pid}/mem"))
            .context("opening tracee memory")?;

        Ok(Self {
            pid,
            mem,
            stdin: Some(stdin_w),
            stdout: stdout_r,
            stderr: stderr_r,
        })
    }

    pub fn pid(&self) -> Pid {
        self.pid
    }

    pub fn read_mem(&self, addr: u64, len: usize) -> Result<Vec<u8>> {
        let mut buf = vec![0; len];
        self.mem
            .read_exact_at(&mut buf, addr)
            .with_context(|| format!("reading {len:#x} bytes at {addr:#x}"))?;
        Ok(buf)
    }

    pub fn write_mem(&self, addr: u64, data: &[u8]) -> Result<()> {
        if self.mem.write_all_at(data, addr).is_ok() {
            return Ok(());
        }
        // Some hardened kernels refuse forced writes through /proc/pid/mem
        // (proc_mem.force_override); PTRACE_POKEDATA still works there.
        self.poke(addr, data)
            .with_context(|| format!("writing {:#x} bytes at {addr:#x}", data.len()))
    }

    fn poke(&self, addr: u64, data: &[u8]) -> Result<()> {
        const W: usize = size_of::<libc::c_long>();
        for (i, chunk) in data.chunks(W).enumerate() {
            let at = addr + (i * W) as u64;
            let mut word = [0u8; W];
            if chunk.len() < W {
                let cur = ptrace::read(self.pid, at as ptrace::AddressType)?;
                word = cur.to_ne_bytes();
            }
            word[..chunk.len()].copy_from_slice(chunk);
            ptrace::write(
                self.pid,
                at as ptrace::AddressType,
                libc::c_long::from_ne_bytes(word),
            )?;
        }
        Ok(())
    }

    /// PTRACE_GETREGSET into a plain-old-data register struct.
    pub fn get_regset<T: Copy>(&self, nt: libc::c_int) -> Result<T> {
        let mut val = MaybeUninit::<T>::zeroed();
        let mut iov = libc::iovec {
            iov_base: val.as_mut_ptr().cast(),
            iov_len: size_of::<T>(),
        };
        // SAFETY: the kernel writes at most iov_len bytes into `val`.
        let r = unsafe { libc::ptrace(libc::PTRACE_GETREGSET, self.pid.as_raw(), nt, &mut iov) };
        if r < 0 {
            return Err(std::io::Error::last_os_error()).context("PTRACE_GETREGSET");
        }
        Ok(unsafe { val.assume_init() })
    }

    pub fn set_regset<T: Copy>(&self, nt: libc::c_int, val: &T) -> Result<()> {
        let mut iov = libc::iovec {
            iov_base: (val as *const T).cast_mut().cast(),
            iov_len: size_of::<T>(),
        };
        // SAFETY: the kernel only reads iov_len bytes from `val`.
        let r = unsafe { libc::ptrace(libc::PTRACE_SETREGSET, self.pid.as_raw(), nt, &mut iov) };
        if r < 0 {
            return Err(std::io::Error::last_os_error()).context("PTRACE_SETREGSET");
        }
        Ok(())
    }

    pub fn maps(&self) -> Result<String> {
        std::fs::read_to_string(format!("/proc/{}/maps", self.pid)).context("reading maps")
    }

    /// Queue bytes for the tracee's stdin. Fails if stdin was closed or the
    /// pipe is full (64 KiB not yet read).
    pub fn write_stdin(&mut self, data: &[u8]) -> Result<()> {
        let Some(stdin) = self.stdin.as_mut() else {
            bail!("stdin is closed (restart for a fresh process)");
        };
        stdin
            .write_all(data)
            .context("writing to the program's stdin (buffer full?)")
    }

    /// Close stdin: once queued data is consumed, reads return EOF.
    pub fn close_stdin(&mut self) {
        self.stdin = None;
    }

    /// Collect what the tracee wrote so far.
    pub fn drain_output(&mut self, out: &mut Output) {
        drain(&mut self.stdout, &mut out.stdout);
        drain(&mut self.stderr, &mut out.stderr);
    }

    /// (number, first argument) of the system call the tracee is blocked in,
    /// from `/proc/<pid>/syscall` (`NR ARG0 ... SP PC`, or `running`).
    fn blocking_syscall(&self) -> Option<(u64, u64)> {
        let text = std::fs::read_to_string(format!("/proc/{}/syscall", self.pid)).ok()?;
        let mut f = text.split_whitespace();
        let nr = f.next()?.parse().ok()?;
        let arg0 = u64::from_str_radix(f.next()?.trim_start_matches("0x"), 16).ok()?;
        Some((nr, arg0))
    }

    /// Continue (optionally delivering `sig`) and wait for the next stop.
    /// Output written meanwhile is appended to `out` (read while running,
    /// so a chatty program never blocks on a full pipe). A tracee blocked
    /// in `read(0, ...)` (syscall number `read_nr`) is stopped early, as a
    /// timeout, since nothing but us can feed its stdin.
    pub fn cont(
        &mut self,
        sig: Option<Signal>,
        timeout: Duration,
        out: &mut Output,
        read_nr: u64,
    ) -> Result<Stop> {
        ptrace::cont(self.pid, sig).context("PTRACE_CONT")?;
        let stop = self.wait_stop(timeout, out, read_nr);
        self.drain_output(out);
        stop
    }

    fn wait_stop(&mut self, timeout: Duration, out: &mut Output, read_nr: u64) -> Result<Stop> {
        const STDIN_CHECK: Duration = Duration::from_millis(30);
        let start = Instant::now();
        let deadline = start + timeout;
        let mut next_check = start + STDIN_CHECK;
        let status = loop {
            match waitpid(self.pid, Some(WaitPidFlag::WNOHANG)) {
                Ok(WaitStatus::StillAlive) => {}
                Ok(s) => break s,
                Err(nix::errno::Errno::EINTR) => {}
                Err(e) => return Err(e).context("waitpid"),
            }
            let now = Instant::now();
            let waiting_stdin = now >= next_check && {
                next_check = now + STDIN_CHECK;
                self.blocking_syscall() == Some((read_nr, 0))
            };
            if now >= deadline || waiting_stdin {
                let syscall = self.blocking_syscall();
                kill(self.pid, Signal::SIGSTOP).context("stopping tracee")?;
                match wait(self.pid)? {
                    WaitStatus::Stopped(_, Signal::SIGSTOP) => {
                        return Ok(Stop::Timeout { syscall });
                    }
                    // It stopped for another reason right as we timed out.
                    s => break s,
                }
            }
            self.drain_output(out);
            thread::sleep(Duration::from_micros(200));
        };

        Ok(match status {
            WaitStatus::Stopped(_, Signal::SIGTRAP) => Stop::Trap,
            WaitStatus::Stopped(_, sig) => {
                let addr = match sig {
                    Signal::SIGSEGV | Signal::SIGBUS | Signal::SIGILL | Signal::SIGFPE => {
                        ptrace::getsiginfo(self.pid)
                            .ok()
                            .map(|si| unsafe { si.si_addr() } as u64)
                    }
                    _ => None,
                };
                Stop::Signal { sig, addr }
            }
            WaitStatus::PtraceEvent(_, _, libc::PTRACE_EVENT_EXIT) => {
                let status = ptrace::getevent(self.pid).context("PTRACE_GETEVENTMSG")?;
                Stop::Exiting {
                    status: status as i32,
                }
            }
            WaitStatus::PtraceEvent(_, _, libc::PTRACE_EVENT_SECCOMP) => Stop::Seccomp,
            _ => Stop::Gone,
        })
    }
}

impl Drop for Tracee {
    fn drop(&mut self) {
        let _ = kill(self.pid, Signal::SIGKILL);
        // SIGKILL does not release a tracee parked in a ptrace stop such as
        // PTRACE_EVENT_EXIT; resume it so it can finish dying.
        let _ = ptrace::cont(self.pid, None);
        let _ = waitpid(self.pid, None);
    }
}

fn wait(pid: Pid) -> Result<WaitStatus> {
    loop {
        match waitpid(pid, None) {
            Err(nix::errno::Errno::EINTR) => continue,
            r => return r.context("waitpid"),
        }
    }
}
