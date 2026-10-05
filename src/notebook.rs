//! Notebook model: a list of assembly cells executed against one session,
//! with a snapshot of the machine state taken after every cell. Independent
//! of any UI.

use std::collections::BTreeMap;
use std::path::Path;

use anyhow::{Context, Result};

use crate::arch::RegState;
use crate::asm::{AsmError, Layout};
use crate::session::{Outcome, Session, SyscallEvent};
use crate::tracee::Output;

/// Separator between cells in saved notebooks (a comment in most assemblers).
pub const CELL_SEPARATOR: &str = ";; %%";

/// Stack words captured below the stack pointer (to see pushes that were
/// popped again) and in total.
const STACK_WORDS_BELOW: u64 = 4;
const STACK_WORDS: usize = 64;
/// Bytes captured for the memory view (enough for a tall pane).
const WATCH_BYTES: usize = 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mem {
    pub addr: u64,
    pub bytes: Vec<u8>,
}

impl Mem {
    /// Byte at `addr`, if captured.
    pub fn get(&self, addr: u64) -> Option<u8> {
        let off = addr.checked_sub(self.addr)? as usize;
        self.bytes.get(off).copied()
    }
}

/// What the memory view looks at: a fixed address or a register's value,
/// plus an offset. Re-resolved after every cell, so `rsp+0x10` follows the
/// stack.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Watch {
    pub base: WatchBase,
    pub offset: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WatchBase {
    Addr(u64),
    Reg(String),
}

impl Watch {
    pub fn addr(addr: u64) -> Self {
        Self {
            base: WatchBase::Addr(addr),
            offset: 0,
        }
    }

    /// Parse `ADDR`, `REG`, `REG+OFF` or `REG-OFF` (numbers in hex with
    /// `0x` or decimal). Register names are checked against `regs`.
    pub fn parse(s: &str, regs: &RegState) -> Result<Self> {
        let s = s.trim();
        let (base, offset) = match s.find(['+', '-']) {
            Some(i) if i > 0 => {
                let off = crate::parse_u64(s[i + 1..].trim())? as i64;
                (s[..i].trim(), if &s[i..=i] == "-" { -off } else { off })
            }
            _ => (s, 0),
        };
        let base = match reg_value(regs, base) {
            Some(_) => WatchBase::Reg(base.to_ascii_lowercase()),
            None => WatchBase::Addr(
                crate::parse_u64(base)
                    .with_context(|| format!("not a register or address: {base}"))?,
            ),
        };
        Ok(Self { base, offset })
    }

    pub fn resolve(&self, regs: &RegState) -> u64 {
        let base = match &self.base {
            WatchBase::Addr(a) => *a,
            WatchBase::Reg(r) => reg_value(regs, r).unwrap_or(0),
        };
        base.wrapping_add_signed(self.offset)
    }

    pub fn describe(&self) -> String {
        match (&self.base, self.offset) {
            (WatchBase::Addr(a), off) => format!("{:#x}", a.wrapping_add_signed(off)),
            (WatchBase::Reg(r), 0) => r.clone(),
            (WatchBase::Reg(r), off) if off < 0 => format!("{r}-{:#x}", off.unsigned_abs()),
            (WatchBase::Reg(r), off) => format!("{r}+{off:#x}"),
        }
    }
}

fn reg_value(regs: &RegState, name: &str) -> Option<u64> {
    let name = name.to_ascii_lowercase();
    match name.as_str() {
        "pc" => Some(regs.pc),
        "sp" => Some(regs.sp),
        _ => regs
            .gp
            .iter()
            .chain(&regs.extra)
            .find(|r| r.name == name)
            .map(|r| r.value),
    }
}

/// One line of /proc/<pid>/maps.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Region {
    pub lo: u64,
    pub hi: u64,
    pub perms: String,
    pub name: String,
}

pub fn parse_maps(maps: &str) -> Vec<Region> {
    maps.lines()
        .filter_map(|line| {
            let mut p = line.split_whitespace();
            let (lo, hi) = p.next()?.split_once('-')?;
            let perms = p.next()?.to_string();
            let name = p.nth(3).unwrap_or("").to_string();
            Some(Region {
                lo: u64::from_str_radix(lo, 16).ok()?,
                hi: u64::from_str_radix(hi, 16).ok()?,
                perms,
                name,
            })
        })
        .collect()
}

/// Machine state after running a cell. The `prev_*` fields hold the state
/// before it, for change highlighting.
#[derive(Debug, Clone)]
pub struct Snapshot {
    pub outcome: Outcome,
    pub regs: RegState,
    pub prev_regs: Option<RegState>,
    pub stack: Mem,
    pub prev_stack: Option<Mem>,
    /// Resolved address of the memory view; `mem` starts at or near it.
    pub watch_addr: u64,
    pub mem: Mem,
    pub prev_mem: Option<Mem>,
    pub maps: String,
}

/// First line that marks a definition cell: it is assembled and placed in
/// memory and its labels become visible to later cells, but it is not run.
pub const DEF_MARKER: &str = ";; def";

/// Cell line giving the program a line of stdin: `;; stdin: TEXT` sends
/// TEXT (with `\n`, `\t`, `\0`, `\xNN` escapes) and a newline.
pub const STDIN_DIRECTIVE: &str = ";; stdin:";
/// Cell line closing the program's stdin before the cell runs.
pub const EOF_DIRECTIVE: &str = ";; eof";

/// The stdin bytes and EOF flag from a cell's `;; stdin:` / `;; eof` lines.
pub fn stdin_directives(src: &str) -> Result<(Vec<u8>, bool)> {
    let (mut data, mut eof) = (Vec::new(), false);
    for line in src.lines().map(str::trim) {
        if let Some(text) = line.strip_prefix(STDIN_DIRECTIVE) {
            data.extend(crate::unescape(text.strip_prefix(' ').unwrap_or(text))?);
            data.push(b'\n');
        } else if line.eq_ignore_ascii_case(EOF_DIRECTIVE) {
            eof = true;
        }
    }
    Ok((data, eof))
}

/// Cells start on this alignment in the code region.
const CELL_ALIGN: u64 = 16;

pub fn is_def(src: &str) -> bool {
    src.lines()
        .next()
        .is_some_and(|l| l.trim().eq_ignore_ascii_case(DEF_MARKER))
}

#[derive(Debug, Clone)]
pub enum CellState {
    /// Not executed in the current process (e.g. after a restart).
    Pending,
    Ran(Box<Snapshot>),
    /// Definition cell placed in memory (not executed).
    Defined(Box<Snapshot>),
    /// Source does not assemble in its current position (e.g. it uses a
    /// label from a cell that was deleted).
    AsmError(Vec<AsmError>),
}

#[derive(Debug, Clone)]
pub struct Cell {
    pub src: String,
    /// Where the cell's code lives in the code region.
    pub addr: u64,
    pub code: Vec<u8>,
    /// Where the cell's initialized data (`.data`, `.rodata`) lives.
    pub data_addr: u64,
    pub data: Vec<u8>,
    /// Zeroed bytes reserved after `data` (`.bss`).
    pub bss: u64,
    /// What the program wrote while this cell ran.
    pub output: Output,
    /// System calls intercepted while this cell ran (e.g. `execve`).
    pub syscalls: Vec<SyscallEvent>,
    /// Labels and constants this cell defines.
    pub symbols: Vec<(String, u64)>,
    pub state: CellState,
    /// Execution counter, like Jupyter's `In [n]`.
    pub count: Option<usize>,
}

impl Cell {
    fn new(src: &str) -> Self {
        Self {
            src: src.to_string(),
            addr: 0,
            code: Vec::new(),
            data_addr: 0,
            data: Vec::new(),
            bss: 0,
            output: Output::default(),
            syscalls: Vec::new(),
            symbols: Vec::new(),
            state: CellState::Pending,
            count: None,
        }
    }

    pub fn is_def(&self) -> bool {
        is_def(&self.src)
    }

    pub fn snapshot(&self) -> Option<&Snapshot> {
        match &self.state {
            CellState::Ran(s) | CellState::Defined(s) => Some(s),
            _ => None,
        }
    }
}

#[derive(Debug)]
pub enum Error {
    Asm(Vec<AsmError>),
    Other(anyhow::Error),
}

impl From<anyhow::Error> for Error {
    fn from(e: anyhow::Error) -> Self {
        Self::Other(e)
    }
}

/// Cells are laid out one after another in the code region, so code and
/// data from earlier cells stay in memory, and their labels are passed to
/// later cells: `call strlen` works if an earlier cell defined `strlen:`.
pub struct Notebook {
    pub sess: Session,
    pub cells: Vec<Cell>,
    /// Current state of the live process.
    pub live: Snapshot,
    /// Address shown in the memory view.
    pub watch: Watch,
    /// Symbols defined so far, in the current process.
    pub symbols: BTreeMap<String, u64>,
    /// Where the next cell's code and data go.
    next: u64,
    next_data: u64,
    counter: usize,
    /// Cell whose run is blocked reading stdin.
    pub waiting: Option<usize>,
    /// `;; stdin:` lines for the next cell submitted.
    pub pending_input: Vec<String>,
}

impl Notebook {
    pub fn new(sess: Session) -> Result<Self> {
        let watch = Watch::addr(sess.start());
        let live = capture(&sess, &watch, Outcome::Done, None)?;
        let next = sess.start();
        let next_data = sess.data_range().start;
        Ok(Self {
            sess,
            cells: Vec::new(),
            live,
            watch,
            symbols: BTreeMap::new(),
            next,
            next_data,
            counter: 0,
            waiting: None,
            pending_input: Vec::new(),
        })
    }

    /// Assemble `src` as a new cell after the existing ones and run it (or
    /// just place it, for a definition cell). Input queued with
    /// [`input`](Self::input) is added to it. Returns its index.
    pub fn submit(&mut self, src: &str) -> Result<usize, Error> {
        let src = if self.pending_input.is_empty() {
            src.to_string()
        } else {
            format!("{}\n{src}", self.pending_input.join("\n"))
        };
        let mut cell = Cell::new(&src);
        self.assemble(self.cells.len(), &mut cell)
            .map_err(Error::Asm)?;
        self.check_fits(&cell)?;
        self.pending_input.clear();
        self.cells.push(cell);
        let i = self.cells.len() - 1;
        self.commit(i)?;
        Ok(i)
    }

    /// Replace cell `i` and replay the whole notebook from a fresh process.
    /// If the new source does not assemble, the cell is left unchanged.
    pub fn edit(&mut self, i: usize, src: &str) -> Result<(), Error> {
        let old = std::mem::replace(&mut self.cells[i].src, src.to_string());
        self.replay()?;
        if let CellState::AsmError(errs) = &self.cells[i].state {
            let errs = errs.clone();
            self.cells[i].src = old;
            self.replay()?;
            return Err(Error::Asm(errs));
        }
        Ok(())
    }

    pub fn delete(&mut self, i: usize) -> Result<()> {
        self.cells.remove(i);
        self.replay()
    }

    /// Fresh process; every cell becomes pending.
    pub fn restart(&mut self) -> Result<()> {
        self.sess.restart()?;
        for c in &mut self.cells {
            c.state = CellState::Pending;
        }
        self.symbols.clear();
        self.next = self.sess.start();
        self.next_data = self.sess.data_range().start;
        self.waiting = None;
        self.live = capture(&self.sess, &self.watch, Outcome::Done, None)?;
        Ok(())
    }

    /// Restart and run every cell in order, re-assembling each at its new
    /// position. Cells keep running after one faults or fails to assemble,
    /// just as they would have interactively.
    pub fn replay(&mut self) -> Result<()> {
        self.restart()?;
        for i in 0..self.cells.len() {
            let mut cell = std::mem::replace(&mut self.cells[i], Cell::new(""));
            let res = self.assemble(i, &mut cell);
            self.cells[i] = cell;
            match res {
                Ok(()) => {
                    self.check_fits(&self.cells[i])?;
                    self.commit(i)?;
                }
                Err(errs) => self.cells[i].state = CellState::AsmError(errs),
            }
        }
        Ok(())
    }

    /// Assemble `cell` (to become cell `i`) at the next free address against
    /// the current symbols, plus `cellN` for the start of every placed cell
    /// before it and of itself. User labels named `cellN` win.
    fn assemble(&self, i: usize, cell: &mut Cell) -> Result<(), Vec<AsmError>> {
        let mut names: BTreeMap<String, u64> = self.cells[..i]
            .iter()
            .enumerate()
            .filter(|(_, c)| matches!(c.state, CellState::Ran(_) | CellState::Defined(_)))
            .map(|(j, c)| (self.cell_name(j), c.addr))
            .collect();
        names.insert(self.cell_name(i), self.next);
        names.extend(self.symbols.iter().map(|(n, v)| (n.clone(), *v)));
        let externs: Vec<_> = names.into_iter().collect();
        let layout = Layout {
            code: self.next,
            data: self.next_data,
        };
        let out = self.sess.assemble_at(&cell.src, layout, &externs)?;
        cell.addr = self.next;
        cell.code = out.code;
        cell.data_addr = self.next_data;
        cell.data = out.data;
        cell.bss = out.bss;
        cell.symbols = out.symbols;
        Ok(())
    }

    fn check_fits(&self, cell: &Cell) -> Result<()> {
        let end = cell.addr + (cell.code.len() + self.sess.arch().trap().len()) as u64;
        if end > self.sess.code_end() {
            anyhow::bail!(
                "code region full ({:#x} bytes); delete cells or restart",
                self.sess.code_end() - self.sess.start()
            );
        }
        let data = self.sess.data_range();
        if cell.data_addr + cell.data.len() as u64 + cell.bss > data.end {
            anyhow::bail!(
                "data region full ({:#x} bytes); delete cells or restart",
                data.end - data.start
            );
        }
        Ok(())
    }

    /// Place an assembled cell, publish its symbols, and run it unless it
    /// is a definition cell.
    fn commit(&mut self, i: usize) -> Result<()> {
        let (addr, len) = (self.cells[i].addr, self.cells[i].code.len());
        self.sess.place(addr, &self.cells[i].code)?;
        let trap = self.sess.arch().trap().len() as u64;
        self.next = (addr + len as u64 + trap).next_multiple_of(CELL_ALIGN);
        self.place_data(i)?;
        let c = &self.cells[i];
        self.next_data = (c.data_addr + c.data.len() as u64 + c.bss).next_multiple_of(CELL_ALIGN);
        self.symbols.extend(self.cells[i].symbols.iter().cloned());
        self.counter += 1;
        self.cells[i].count = Some(self.counter);
        self.cells[i].output = Output::default();
        self.cells[i].syscalls = Vec::new();
        self.waiting = None;

        let (data, eof) = stdin_directives(&self.cells[i].src)?;
        if !data.is_empty() {
            self.sess.write_stdin(&data)?;
        }
        if eof {
            self.sess.close_stdin();
        }

        if self.cells[i].is_def() {
            self.live = capture(&self.sess, &self.watch, Outcome::Done, Some(&self.live))?;
            self.cells[i].state = CellState::Defined(Box::new(self.live.clone()));
            return Ok(());
        }
        let outcome = self.sess.exec(addr, addr + len as u64)?;
        self.finish_run(i, outcome)
    }

    /// Record the result of running (or resuming) cell `i`.
    fn finish_run(&mut self, i: usize, outcome: Outcome) -> Result<()> {
        if let Outcome::Exited { .. } = outcome {
            // Fresh process: bring back the code and initial data of
            // every cell so far.
            for j in 0..=i {
                let c = &self.cells[j];
                if matches!(c.state, CellState::AsmError(_)) {
                    continue;
                }
                if !c.code.is_empty() {
                    self.sess.place(c.addr, &c.code)?;
                }
                self.place_data(j)?;
            }
        }
        if outcome == Outcome::WaitingForInput {
            self.waiting = Some(i);
        }
        let out = self.sess.take_output();
        let calls = self.sess.take_syscalls();
        let cell = &mut self.cells[i];
        cell.output.stdout.extend(out.stdout);
        cell.output.stderr.extend(out.stderr);
        cell.syscalls.extend(calls);
        self.live = capture(&self.sess, &self.watch, outcome, Some(&self.live))?;
        self.cells[i].state = CellState::Ran(Box::new(self.live.clone()));
        Ok(())
    }

    /// Send a line to the program's stdin. It is recorded in the source of
    /// the cell that consumes it as `;; stdin: TEXT`, so replays and saved
    /// notebooks reproduce it: the cell waiting for input (which then
    /// resumes), else the next cell submitted. Returns the resumed cell.
    pub fn input(&mut self, text: &str) -> Result<Option<usize>> {
        let mut data = crate::unescape(text)?;
        data.push(b'\n');
        self.feed(format!("{STDIN_DIRECTIVE} {text}"), |sess| {
            sess.write_stdin(&data)
        })
    }

    /// Close the program's stdin (reads return EOF); recorded as `;; eof`.
    pub fn eof(&mut self) -> Result<Option<usize>> {
        self.feed(EOF_DIRECTIVE.to_string(), |sess| {
            sess.close_stdin();
            Ok(())
        })
    }

    fn feed(
        &mut self,
        line: String,
        apply: impl FnOnce(&mut Session) -> Result<()>,
    ) -> Result<Option<usize>> {
        let Some(i) = self.waiting.take() else {
            self.pending_input.push(line);
            return Ok(None);
        };
        if let Err(e) = apply(&mut self.sess) {
            self.waiting = Some(i);
            return Err(e);
        }
        let src = &mut self.cells[i].src;
        src.push('\n');
        src.push_str(&line);
        let c = &self.cells[i];
        let outcome = self.sess.resume(c.addr + c.code.len() as u64)?;
        self.finish_run(i, outcome)?;
        Ok(Some(i))
    }

    fn place_data(&mut self, i: usize) -> Result<()> {
        let c = &self.cells[i];
        if c.data.is_empty() {
            return Ok(());
        }
        let (at, data) = (c.data_addr, c.data.clone());
        self.sess.place_data(at, &data)
    }

    /// The placed cell whose code or data contains `addr`, and the start of
    /// that part. The trap right after the code counts as code, since that
    /// is where a final `call` returns to.
    fn cell_at(&self, addr: u64) -> Option<(usize, u64, bool)> {
        self.cells.iter().enumerate().find_map(|(i, c)| {
            if !matches!(c.state, CellState::Ran(_) | CellState::Defined(_)) {
                return None;
            }
            let data_len = c.data.len() as u64 + c.bss;
            if (c.addr..=c.addr + c.code.len() as u64).contains(&addr) {
                Some((i, c.addr, false))
            } else if data_len > 0 && (c.data_addr..c.data_addr + data_len).contains(&addr) {
                Some((i, c.data_addr, true))
            } else {
                None
            }
        })
    }

    /// Name of cell `i` by its position: `cell1` is the first cell. Usable
    /// as a jump / call target, and used to show addresses in cells that do
    /// not start with a label.
    pub fn cell_name(&self, i: usize) -> String {
        format!("cell{}", i + 1)
    }

    /// The placed cell whose end trap is at `addr` (where execution stops
    /// after running into the end of that cell's code).
    pub fn cell_end(&self, addr: u64) -> Option<usize> {
        self.cells.iter().position(|c| {
            matches!(c.state, CellState::Ran(_) | CellState::Defined(_))
                && c.addr + c.code.len() as u64 == addr
        })
    }

    /// `strlen+0x4` or `buf+0x10` for an address inside a cell's code or
    /// data: relative to the nearest label there, or to the cell itself
    /// (`cell3+0x2`, `cell3.data+0x8`).
    pub fn symbolize(&self, addr: u64) -> Option<String> {
        let (i, base, is_data) = self.cell_at(addr)?;
        let c = &self.cells[i];
        let fallback = || {
            let name = self.cell_name(i);
            (
                if is_data {
                    format!("{name}.data")
                } else {
                    name
                },
                base,
            )
        };
        let (name, at) = c
            .symbols
            .iter()
            .filter(|(_, v)| (base..=addr).contains(v))
            .max_by_key(|(_, v)| *v)
            .map_or_else(fallback, |(n, v)| (n.clone(), *v));
        Some(match addr - at {
            0 => name,
            off => format!("{name}+{off:#x}"),
        })
    }

    /// Labels by address in the code and data regions, for disassembly,
    /// plus a `cellN` entry for cells whose code does not start with one.
    pub fn symbols_by_addr(&self) -> BTreeMap<u64, String> {
        let (code, data) = (
            self.sess.start()..self.sess.code_end(),
            self.sess.data_range(),
        );
        let mut map = BTreeMap::new();
        for (i, c) in self.cells.iter().enumerate() {
            if !matches!(c.state, CellState::Ran(_) | CellState::Defined(_)) {
                continue;
            }
            for (n, v) in &c.symbols {
                if code.contains(v) || data.contains(v) {
                    map.insert(*v, n.clone());
                }
            }
            map.entry(c.addr).or_insert_with(|| self.cell_name(i));
        }
        map
    }

    pub fn set_watch(&mut self, watch: Watch) {
        self.watch = watch;
        let addr = self.watch.resolve(&self.live.regs);
        self.live.watch_addr = addr;
        self.live.mem = read_partial(&self.sess, view_start(addr), WATCH_BYTES);
        self.live.prev_mem = None;
    }

    /// Move the memory view by `delta` bytes.
    pub fn scroll_watch(&mut self, delta: i64) {
        let mut w = self.watch.clone();
        w.offset = w.offset.saturating_add(delta);
        if self
            .watch
            .resolve(&self.live.regs)
            .checked_add_signed(delta)
            .is_some()
        {
            self.set_watch(w);
        }
    }

    pub fn write_mem(&mut self, addr: u64, data: &[u8]) -> Result<()> {
        self.sess.write_mem(addr, data)?;
        self.refresh()
    }

    /// Re-read the live process state, e.g. after writing memory.
    pub fn refresh(&mut self) -> Result<()> {
        let outcome = self.live.outcome.clone();
        self.live = capture(&self.sess, &self.watch, outcome, Some(&self.live))?;
        Ok(())
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        let body: Vec<_> = self.cells.iter().map(|c| c.src.trim_end()).collect();
        let sep = format!("\n{CELL_SEPARATOR}\n");
        std::fs::write(path, body.join(&sep) + "\n")
            .with_context(|| format!("writing {}", path.display()))
    }

    /// Replace all cells with the ones in `path` and run them.
    pub fn load(&mut self, path: &Path) -> Result<()> {
        let text =
            std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        self.cells = split_cells(&text)
            .iter()
            .map(|src| Cell::new(src))
            .collect();
        self.replay()
    }
}

fn split_cells(text: &str) -> Vec<String> {
    let mut cells = vec![String::new()];
    for line in text.lines() {
        if line.trim() == CELL_SEPARATOR {
            cells.push(String::new());
        } else {
            let cur = cells.last_mut().unwrap();
            cur.push_str(line);
            cur.push('\n');
        }
    }
    cells
        .into_iter()
        .map(|c| c.trim_end().to_string())
        .filter(|c| !c.trim().is_empty())
        .collect()
}

fn capture(
    sess: &Session,
    watch: &Watch,
    outcome: Outcome,
    prev: Option<&Snapshot>,
) -> Result<Snapshot> {
    let regs = sess.regs.clone();
    let watch_addr = watch.resolve(&regs);
    let word = sess.arch().word_size() as u64;
    let stack_base = regs.sp.saturating_sub(STACK_WORDS_BELOW * word);
    Ok(Snapshot {
        outcome,
        stack: read_partial(sess, stack_base, STACK_WORDS * word as usize),
        watch_addr,
        mem: read_partial(sess, view_start(watch_addr), WATCH_BYTES),
        maps: sess.maps()?,
        prev_regs: prev.map(|p| p.regs.clone()),
        prev_stack: prev.map(|p| p.stack.clone()),
        prev_mem: prev.map(|p| p.mem.clone()),
        regs,
    })
}

/// The memory view starts on a 16-byte boundary.
fn view_start(addr: u64) -> u64 {
    addr & !0xf
}

/// Read up to `len` bytes: unmapped pages at the start are skipped, and the
/// read stops at the first unmapped page after that.
fn read_partial(sess: &Session, addr: u64, len: usize) -> Mem {
    if let Ok(bytes) = sess.read_mem(addr, len) {
        return Mem { addr, bytes };
    }
    let end = addr.saturating_add(len as u64);
    let (mut at, mut start, mut bytes) = (addr, None, Vec::new());
    while at < end {
        let next = ((at | 0xfff).saturating_add(1)).min(end);
        match sess.read_mem(at, (next - at) as usize) {
            Ok(b) => {
                start.get_or_insert(at);
                bytes.extend(b);
            }
            Err(_) if start.is_some() => break,
            Err(_) => {}
        }
        if next == at {
            break;
        }
        at = next;
    }
    Mem {
        addr: start.unwrap_or(addr),
        bytes,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_cells_on_separator() {
        let text = "mov rax, 1\n;; %%\n\n;; %%\npush rax\npop rbx\n";
        assert_eq!(split_cells(text), ["mov rax, 1", "push rax\npop rbx"]);
    }

    fn regs() -> RegState {
        RegState {
            gp: vec![crate::arch::Reg {
                name: "rsp",
                value: 0x1000,
            }],
            sp: 0x1000,
            pc: 0x400000,
            ..Default::default()
        }
    }

    #[test]
    fn parses_watch_expressions() {
        let r = regs();
        let w = Watch::parse("rsp-0x10", &r).unwrap();
        assert_eq!(w.resolve(&r), 0xff0);
        assert_eq!(w.describe(), "rsp-0x10");
        assert_eq!(Watch::parse("RSP + 8", &r).unwrap().resolve(&r), 0x1008);
        assert_eq!(Watch::parse("pc", &r).unwrap().resolve(&r), 0x400000);
        assert_eq!(Watch::parse("0x2000", &r).unwrap(), Watch::addr(0x2000));
        assert!(Watch::parse("rzz", &r).is_err());
    }

    #[test]
    fn parses_maps() {
        let m = parse_maps(
            "00400000-00404000 r-xp 00001000 00:01 12 /memfd:rusm-tracee (deleted)\n7ffffffde000-7ffffffff000 rw-p 00000000 00:00 0 [stack]\n",
        );
        assert_eq!(m.len(), 2);
        assert_eq!(m[0].lo, 0x400000);
        assert_eq!(m[1].name, "[stack]");
    }
}
