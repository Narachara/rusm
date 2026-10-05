//! Minimal classic-BPF seccomp program builder.
//!
//! The filter checks the audit arch, then returns `SECCOMP_RET_TRACE` for a
//! chosen system call (so it stops the tracee at a `PTRACE_EVENT_SECCOMP`)
//! and `SECCOMP_RET_ALLOW` for everything else. A wrong audit arch is killed
//! so a 32-bit syscall cannot slip past the number check.

// Classic BPF opcodes (linux/bpf_common.h); libc does not export these.
const BPF_LD: u16 = 0x00;
const BPF_W: u16 = 0x00;
const BPF_ABS: u16 = 0x20;
const BPF_JMP: u16 = 0x05;
const BPF_JEQ: u16 = 0x10;
const BPF_RET: u16 = 0x06;
const BPF_K: u16 = 0x00;

const SECCOMP_RET_KILL_PROCESS: u32 = 0x8000_0000;
const SECCOMP_RET_TRACE: u32 = 0x7ff0_0000;
const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;

const AUDIT_ARCH_X86_64: u32 = 0xc000_003e;

// Byte offsets into `struct seccomp_data` { nr: i32, arch: u32, ... }.
const OFF_NR: u32 = 0;
const OFF_ARCH: u32 = 4;

fn stmt(code: u16, k: u32) -> libc::sock_filter {
    libc::sock_filter {
        code,
        jt: 0,
        jf: 0,
        k,
    }
}

fn jump(code: u16, k: u32, jt: u8, jf: u8) -> libc::sock_filter {
    libc::sock_filter { code, jt, jf, k }
}

/// A filter that traces (stops at a `PTRACE_EVENT_SECCOMP`) the x86-64 system
/// call `nr` and allows everything else.
pub fn trace_filter(nr: u32) -> Vec<libc::sock_filter> {
    vec![
        // A = arch; kill if it is not x86-64.
        stmt(BPF_LD | BPF_W | BPF_ABS, OFF_ARCH),
        jump(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0),
        stmt(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
        // A = nr; trace the chosen call, allow the rest.
        stmt(BPF_LD | BPF_W | BPF_ABS, OFF_NR),
        jump(BPF_JMP | BPF_JEQ | BPF_K, nr, 0, 1),
        stmt(BPF_RET | BPF_K, SECCOMP_RET_TRACE),
        stmt(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    ]
}
