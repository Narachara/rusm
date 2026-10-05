//! TUI state and input handling.

use std::cell::Cell;
use std::path::PathBuf;

use ratatui::crossterm::event::{Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};

use super::editor::Editor;
use crate::notebook::{self, Notebook, Snapshot, Watch, parse_maps};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Focus {
    Editor,
    Cells,
    Memory,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemView {
    Hex,
    Maps,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Level {
    Info,
    Error,
}

pub struct App {
    pub nb: Notebook,
    pub editor: Editor,
    pub focus: Focus,
    /// Selected cell while in `Focus::Cells`.
    pub selected: usize,
    /// Cell being edited in place, if any.
    pub editing: Option<usize>,
    pub status: Option<(Level, String)>,
    pub allregs: bool,
    pub mem_view: MemView,
    pub show_help: bool,
    /// First help line shown while the help is open.
    pub help_scroll: usize,
    /// Help geometry from the last draw: (visible rows, max scroll).
    pub help_layout: Cell<(usize, usize)>,
    pub quit: bool,
    /// Notebook file for `.save` without an argument.
    pub path: Option<PathBuf>,
    history: Vec<String>,
    /// Position while browsing history, and the text that was being typed.
    hist_pos: Option<(usize, String)>,
    /// Goto-address input line while open.
    pub prompt: Option<String>,
    /// Memory pane geometry from the last draw: (rows, bytes per row).
    pub mem_layout: Cell<(usize, usize)>,
}

pub const HELP: &str = "\
Editor
  Enter              run a one-line cell. After a label line (`foo:`)
                     or `;; def`, Enter continues the block on a new
                     line; Enter on an empty line runs the whole block
  Ctrl+R             run cell now (or save edit and replay)
  Ctrl+J, Alt+Enter  new line
  ;; def             as first line: definition cell. Placed in memory
                     and its labels exported, but not run. Labels from
                     earlier cells can be used: call strlen, jmp strlen.loop
  cellN              start of the N-th cell in the list: jmp cell2,
                     call cell2. Running into the end of a cell stops
                     there; use call + ret to come back
  Up/Down            move / browse history on first/last line
  Ctrl+U             clear editor
  Esc                cancel editing an existing cell
Data and bss
  Every cell starts in `section .text`. Switch sections to place
  data in the data region (rw, not executable, `d` in memory view):
  section .data      initialized data: msg: db \"hi\", 10 / n: dq 5
  section .rodata    constants, placed after .data
  section .bss       zeroed space: buf: resb 64 / arr: resq 8
  section .text      back to code
  Address data RIP-relative: lea rsi, [rel msg] / mov rax, [rel n].
  Labels stay visible to later cells. Use Ctrl+J for the extra
  lines, or start with `;; def` to only declare data, e.g.
    ;; def
    section .data
    msg: db \"hello\", 10
    section .bss
    buf: resb 64
Memory (Tab to focus)
  Up/Down, j/k       scroll one row
  PgUp/PgDn          scroll one page
  g                  go to ADDR, REG or REG+OFF (REG follows the register)
  s / p              follow stack pointer / program counter
  c / d              go to the code / data region
  [ / ]              previous / next memory region
  Home               start of the current region
Cells (Tab to focus)
  Up/Down, j/k       select cell and view its state
  e / Enter          edit cell in place (replays notebook)
  y                  copy cell into the editor
  d                  delete cell (replays notebook)
System calls
  Ordinary syscalls (write, openat, ...) run for real; rax holds the
  result. execve is shown with decoded arguments and NOT run (rusm
  can't host a shell); rax gets a simulated result so cells keep working
Global
  F1                 toggle this help
  F2                 toggle all registers (vector / FP)
  F3                 toggle memory hexdump / memory maps
  F5                 restart and replay all cells
  Ctrl+Q, Ctrl+C     quit
Commands (type in editor)
  .watch EXPR        memory view at ADDR, REG or REG+OFF
  .write ADDR HEX    write bytes to memory
  .syms              list labels defined by cells
  .input TEXT        send TEXT + newline to the program's stdin
                     (\\n \\t \\0 \\xNN escapes). Resumes a cell waiting
                     for input, else goes to the next cell. Recorded
                     in the cell as `;; stdin: TEXT` for replays
  .eof               close stdin (recorded as `;; eof`)
  .restart           fresh process, cells become pending
  .replay            restart and rerun all cells
  .clear             delete all cells and restart
  .save [FILE]       save cells to a notebook file
  .load FILE         load a notebook file and run it
  .quit";

impl App {
    pub fn new(nb: Notebook, path: Option<PathBuf>) -> Self {
        Self {
            nb,
            editor: Editor::default(),
            focus: Focus::Editor,
            selected: 0,
            editing: None,
            status: None,
            allregs: false,
            mem_view: MemView::Hex,
            show_help: false,
            help_scroll: 0,
            help_layout: Cell::new((0, 0)),
            quit: false,
            path,
            history: Vec::new(),
            hist_pos: None,
            prompt: None,
            mem_layout: Cell::new((8, 16)),
        }
    }

    /// The snapshot the right-hand panes display: the selected cell's when
    /// browsing cells, otherwise the live process state.
    pub fn view(&self) -> (&Snapshot, Option<usize>) {
        if self.focus == Focus::Cells
            && let Some(s) = self.nb.cells.get(self.selected).and_then(|c| c.snapshot())
        {
            return (s, Some(self.selected));
        }
        (&self.nb.live, None)
    }

    /// Cell whose code the disassembly pane shows.
    pub fn disasm_cell(&self) -> Option<usize> {
        match self.focus {
            Focus::Cells => Some(self.selected).filter(|&i| i < self.nb.cells.len()),
            Focus::Editor | Focus::Memory => self.editing.or(self.nb.cells.len().checked_sub(1)),
        }
    }

    fn info(&mut self, msg: impl Into<String>) {
        self.status = Some((Level::Info, msg.into()));
    }

    fn error(&mut self, msg: impl Into<String>) {
        self.status = Some((Level::Error, msg.into()));
    }

    fn open_help(&mut self) {
        self.show_help = true;
        self.help_scroll = 0;
    }

    /// Scroll keys move the help; any other key closes it.
    fn help_key(&mut self, k: KeyEvent) {
        let (rows, max) = self.help_layout.get();
        let page = rows.saturating_sub(1).max(1);
        let s = self.help_scroll;
        self.help_scroll = match k.code {
            KeyCode::Up | KeyCode::Char('k') => s.saturating_sub(1),
            KeyCode::Down | KeyCode::Char('j') => s + 1,
            KeyCode::PageUp | KeyCode::Char('b') => s.saturating_sub(page),
            KeyCode::PageDown | KeyCode::Char(' ') => s + page,
            KeyCode::Home | KeyCode::Char('g') => 0,
            KeyCode::End | KeyCode::Char('G') => max,
            _ => {
                self.show_help = false;
                return;
            }
        }
        .min(max);
    }

    pub fn handle(&mut self, ev: Event) {
        match ev {
            Event::Key(k) if k.kind != KeyEventKind::Release => self.key(k),
            Event::Paste(s) if self.focus == Focus::Editor => self.editor.insert_str(&s),
            _ => {}
        }
    }

    fn key(&mut self, k: KeyEvent) {
        let ctrl = k.modifiers.contains(KeyModifiers::CONTROL);
        if self.show_help {
            self.help_key(k);
            return;
        }
        if self.prompt.is_some() {
            self.prompt_key(k);
            return;
        }
        match k.code {
            KeyCode::Char('q' | 'c') if ctrl => self.quit = true,
            KeyCode::F(1) => self.open_help(),
            KeyCode::F(2) => self.allregs = !self.allregs,
            KeyCode::F(3) => self.toggle_maps(),
            KeyCode::F(5) => self.replay(),
            KeyCode::Tab => self.cycle_focus(true),
            KeyCode::BackTab => self.cycle_focus(false),
            _ => match self.focus {
                Focus::Editor => self.editor_key(k),
                Focus::Cells => self.cells_key(k),
                Focus::Memory => self.memory_key(k),
            },
        }
    }

    /// Editor -> Cells -> Memory, skipping Cells while there are none.
    fn cycle_focus(&mut self, forward: bool) {
        let order = [Focus::Editor, Focus::Cells, Focus::Memory];
        let mut i = order.iter().position(|&f| f == self.focus).unwrap();
        loop {
            i = if forward { (i + 1) % 3 } else { (i + 2) % 3 };
            if order[i] != Focus::Cells || !self.nb.cells.is_empty() {
                break;
            }
        }
        if order[i] == Focus::Cells {
            self.selected = self.editing.unwrap_or(self.nb.cells.len() - 1);
        }
        if order[i] == Focus::Memory {
            self.mem_view = MemView::Hex;
        }
        self.focus = order[i];
        self.status = None;
    }

    fn toggle_maps(&mut self) {
        self.mem_view = match self.mem_view {
            MemView::Hex => MemView::Maps,
            MemView::Maps => MemView::Hex,
        };
    }

    fn editor_key(&mut self, k: KeyEvent) {
        let ctrl = k.modifiers.contains(KeyModifiers::CONTROL);
        let newline_mod = k
            .modifiers
            .intersects(KeyModifiers::ALT | KeyModifiers::SHIFT);
        let e = &mut self.editor;
        match k.code {
            KeyCode::Enter if ctrl => self.submit(),
            KeyCode::Enter if newline_mod => e.newline(),
            KeyCode::Enter => self.enter(),
            KeyCode::Char('j') if ctrl => e.newline(),
            KeyCode::Char('r') if ctrl => self.submit(),
            KeyCode::Esc => {
                if self.editing.take().is_some() {
                    self.editor.clear();
                    self.info("edit cancelled");
                }
            }
            KeyCode::Char('u') if ctrl => e.clear(),
            KeyCode::Char('a') if ctrl => e.home(),
            KeyCode::Char('e') if ctrl => e.end(),
            KeyCode::Char(c) if !ctrl => e.insert_char(c),
            KeyCode::Backspace => e.backspace(),
            KeyCode::Delete => e.delete(),
            KeyCode::Left => e.left(),
            KeyCode::Right => e.right(),
            KeyCode::Home => e.home(),
            KeyCode::End => e.end(),
            KeyCode::Up if e.on_first_line() => self.history_step(-1),
            KeyCode::Down if e.on_last_line() => self.history_step(1),
            KeyCode::Up => e.up(),
            KeyCode::Down => e.down(),
            _ => {}
        }
    }

    fn memory_key(&mut self, k: KeyEvent) {
        let (rows, per_row) = self.mem_layout.get();
        let (row, page) = (per_row as i64, (rows.max(2) - 1) as i64 * per_row as i64);
        match k.code {
            KeyCode::Up | KeyCode::Char('k') => self.nb.scroll_watch(-row),
            KeyCode::Down | KeyCode::Char('j') => self.nb.scroll_watch(row),
            KeyCode::PageUp => self.nb.scroll_watch(-page),
            KeyCode::PageDown | KeyCode::Char(' ') => self.nb.scroll_watch(page),
            KeyCode::Char('g' | ':') => self.prompt = Some(String::new()),
            KeyCode::Char('s') => self.set_watch("sp"),
            KeyCode::Char('p') => self.set_watch("pc"),
            KeyCode::Char('c') => self.nb.set_watch(Watch::addr(self.nb.sess.start())),
            KeyCode::Char('d') => self
                .nb
                .set_watch(Watch::addr(self.nb.sess.data_range().start)),
            KeyCode::Char('[') => self.region_step(false),
            KeyCode::Char(']') => self.region_step(true),
            KeyCode::Home => {
                if let Some(r) = self.current_region(self.nb.live.watch_addr) {
                    self.nb.set_watch(Watch::addr(r.lo));
                }
            }
            KeyCode::Esc => self.focus = Focus::Editor,
            _ => {}
        }
    }

    fn prompt_key(&mut self, k: KeyEvent) {
        let Some(input) = self.prompt.as_mut() else {
            return;
        };
        match k.code {
            KeyCode::Char(c) => input.push(c),
            KeyCode::Backspace => {
                input.pop();
            }
            KeyCode::Esc => self.prompt = None,
            KeyCode::Enter => {
                let expr = self.prompt.take().unwrap();
                if !expr.trim().is_empty() {
                    self.set_watch(&expr);
                }
            }
            _ => {}
        }
    }

    fn set_watch(&mut self, expr: &str) {
        match Watch::parse(expr, &self.nb.live.regs) {
            Ok(w) => {
                self.nb.set_watch(w);
                self.mem_view = MemView::Hex;
                self.status = None;
            }
            Err(e) => self.error(format!("{e:#}")),
        }
    }

    fn current_region(&self, addr: u64) -> Option<notebook::Region> {
        parse_maps(&self.nb.live.maps)
            .into_iter()
            .find(|r| (r.lo..r.hi).contains(&addr))
    }

    /// Jump to the start of the previous / next mapped region.
    fn region_step(&mut self, forward: bool) {
        let addr = self.nb.live.watch_addr;
        let regions = parse_maps(&self.nb.live.maps);
        let target = if forward {
            regions.iter().find(|r| r.lo > addr)
        } else {
            // Previous region: the last one that ends at or before our region's start.
            let cur_lo = self.current_region(addr).map_or(addr, |r| r.lo);
            regions.iter().rev().find(|r| r.lo < cur_lo)
        };
        match target {
            Some(r) => {
                let name = if r.name.is_empty() {
                    "anonymous"
                } else {
                    r.name.as_str()
                };
                let msg = format!("{:#x}-{:#x} {} {name}", r.lo, r.hi, r.perms);
                self.nb.set_watch(Watch::addr(r.lo));
                self.info(msg);
            }
            None => self.info("no more regions"),
        }
    }

    fn history_step(&mut self, dir: isize) {
        if self.editing.is_some() || self.history.is_empty() {
            return;
        }
        let len = self.history.len();
        let next = match (&self.hist_pos, dir) {
            (None, -1) => Some(len - 1),
            (None, _) => return,
            (Some((0, _)), -1) => Some(0),
            (Some((i, _)), -1) => Some(i - 1),
            (Some((i, _)), _) if i + 1 < len => Some(i + 1),
            (Some(_), _) => None,
        };
        match next {
            Some(i) => {
                let draft = self
                    .hist_pos
                    .take()
                    .map_or_else(|| self.editor.text(), |(_, d)| d);
                self.editor.set_text(&self.history[i]);
                self.hist_pos = Some((i, draft));
            }
            None => {
                let (_, draft) = self.hist_pos.take().unwrap();
                self.editor.set_text(&draft);
            }
        }
    }

    fn cells_key(&mut self, k: KeyEvent) {
        let n = self.nb.cells.len();
        if n == 0 {
            self.focus = Focus::Editor;
            return;
        }
        match k.code {
            KeyCode::Up | KeyCode::Char('k') => self.selected = self.selected.saturating_sub(1),
            KeyCode::Down | KeyCode::Char('j') => self.selected = (self.selected + 1).min(n - 1),
            KeyCode::Home | KeyCode::Char('g') => self.selected = 0,
            KeyCode::End | KeyCode::Char('G') => self.selected = n - 1,
            KeyCode::Enter | KeyCode::Char('e') => {
                self.editing = Some(self.selected);
                self.editor.set_text(&self.nb.cells[self.selected].src);
                self.focus = Focus::Editor;
            }
            KeyCode::Char('y') => {
                self.editing = None;
                self.editor.set_text(&self.nb.cells[self.selected].src);
                self.focus = Focus::Editor;
            }
            KeyCode::Char('d') | KeyCode::Delete => {
                let i = self.selected;
                if let Err(e) = self.nb.delete(i) {
                    self.error(format!("{e:#}"));
                }
                self.editing = match self.editing {
                    Some(j) if j == i => None,
                    Some(j) if j > i => Some(j - 1),
                    other => other,
                };
                if self.nb.cells.is_empty() {
                    self.focus = Focus::Editor;
                } else {
                    self.selected = i.min(self.nb.cells.len() - 1);
                }
                self.info(format!(
                    "deleted cell, replayed {} cells",
                    self.nb.cells.len()
                ));
            }
            KeyCode::Esc => self.focus = Focus::Editor,
            _ => {}
        }
    }

    fn replay(&mut self) {
        match self.nb.replay() {
            Ok(()) => self.info(format!(
                "restarted and replayed {} cells",
                self.nb.cells.len()
            )),
            Err(e) => self.error(format!("{e:#}")),
        }
    }

    /// Whether the editor is collecting a multi-line block, in which case
    /// Enter adds lines and an empty line runs it.
    pub fn in_block(&self) -> bool {
        let lines = self.editor.lines();
        lines.len() > 1 || opens_block(&lines[0])
    }

    /// Python-REPL style Enter: a single line runs at once; a label line
    /// or `;; def` opens a block that runs on an empty line.
    fn enter(&mut self) {
        if !self.in_block() {
            return self.submit();
        }
        let e = &mut self.editor;
        let (row, _) = e.cursor();
        if e.on_last_line() && e.lines().len() > 1 && e.lines()[row].trim().is_empty() {
            // Drop the blank line that ended the block.
            e.backspace();
            self.submit();
        } else {
            e.newline();
        }
    }

    fn submit(&mut self) {
        let text = self.editor.text();
        if text.trim().is_empty() {
            return;
        }
        if let Some(cmd) = as_command(&text) {
            self.command(cmd);
            self.editor.clear();
            return;
        }

        let res = match self.editing {
            Some(i) => self.nb.edit(i, &text).map(|()| i),
            None => self.nb.submit(&text),
        };
        match res {
            Ok(i) => {
                if self.history.last() != Some(&text) {
                    self.history.push(text);
                }
                self.hist_pos = None;
                self.editor.clear();
                self.selected = i;
                self.status = None; // the cell list shows the outcome
                if self.editing.take().is_some() {
                    self.info(format!("cell {} updated, replayed notebook", i + 1));
                }
            }
            Err(notebook::Error::Asm(errs)) => {
                let mut msg = errs
                    .iter()
                    .map(|e| e.to_string())
                    .collect::<Vec<_>>()
                    .join("; ");
                if let Some(cmd) = missing_dot(&text) {
                    msg.push_str(&format!(" (did you mean .{cmd}?)"));
                }
                self.error(msg);
            }
            Err(notebook::Error::Other(e)) => self.error(format!("{e:#}")),
        }
    }

    fn command(&mut self, cmd: &str) {
        let mut args = cmd.split_whitespace();
        let name = args.next().unwrap_or("");
        let res = match name {
            "quit" | "exit" | "q" => {
                self.quit = true;
                Ok(None)
            }
            "help" | "h" => {
                self.open_help();
                Ok(None)
            }
            "restart" => self
                .nb
                .restart()
                .map(|()| Some("restarted; cells are pending (F5 to replay)".into())),
            "replay" => {
                self.replay();
                Ok(None)
            }
            "clear" => {
                self.nb.cells.clear();
                self.editing = None;
                self.nb.restart().map(|()| Some("cleared".into()))
            }
            "input" => {
                // Keep the text as typed (spaces included) after `input `.
                let text = cmd.strip_prefix("input").unwrap_or("");
                let text = text.strip_prefix(' ').unwrap_or(text);
                self.nb.input(text).map(|resumed| match resumed {
                    Some(i) => {
                        self.selected = i;
                        None
                    }
                    None => Some("queued for the next cell".into()),
                })
            }
            "eof" => self.nb.eof().map(|resumed| {
                resumed
                    .is_none()
                    .then(|| "stdin closes before the next cell runs".into())
            }),
            "syms" | "symbols" => {
                let list: Vec<_> = self
                    .nb
                    .symbols
                    .iter()
                    .map(|(n, v)| format!("{n}={v:#x}"))
                    .collect();
                Ok(Some(if list.is_empty() {
                    "no symbols defined".into()
                } else {
                    list.join("  ")
                }))
            }
            "allregs" => {
                self.allregs = !self.allregs;
                Ok(None)
            }
            "maps" => {
                self.toggle_maps();
                Ok(None)
            }
            "watch" | "read" | "x" => {
                let expr = args.collect::<Vec<_>>().join(" ");
                if expr.is_empty() {
                    Err(anyhow::anyhow!("usage: .watch ADDR|REG|REG+OFF"))
                } else {
                    self.focus = Focus::Editor;
                    self.set_watch(&expr);
                    Ok(None)
                }
            }
            "write" => match (args.next(), args.next()) {
                (Some(a), Some(hex)) => self.resolve(a).and_then(|addr| {
                    let data = crate::parse_hex(hex)?;
                    self.nb.write_mem(addr, &data)?;
                    Ok(Some(format!("wrote {} bytes at {addr:#x}", data.len())))
                }),
                _ => Err(anyhow::anyhow!("usage: .write ADDR HEX")),
            },
            "save" => match args.next().map(PathBuf::from).or_else(|| self.path.clone()) {
                Some(p) => self.nb.save(&p).map(|()| {
                    let msg = format!("saved {} cells to {}", self.nb.cells.len(), p.display());
                    self.path = Some(p);
                    Some(msg)
                }),
                None => Err(anyhow::anyhow!("usage: .save FILE")),
            },
            "load" => match args.next().map(PathBuf::from) {
                Some(p) => {
                    self.editing = None;
                    self.nb.load(&p).map(|()| {
                        let msg =
                            format!("loaded {} cells from {}", self.nb.cells.len(), p.display());
                        self.path = Some(p);
                        Some(msg)
                    })
                }
                None => Err(anyhow::anyhow!("usage: .load FILE")),
            },
            other => Err(anyhow::anyhow!("unknown command .{other} (F1 for help)")),
        };
        match res {
            Ok(Some(msg)) => self.info(msg),
            Ok(None) => {}
            Err(e) => self.error(format!("{e:#}")),
        }
    }

    /// An address expression evaluated against the live registers.
    fn resolve(&self, s: &str) -> anyhow::Result<u64> {
        Ok(Watch::parse(s, &self.nb.live.regs)?.resolve(&self.nb.live.regs))
    }
}

const COMMANDS: &[&str] = &[
    "quit", "exit", "q", "help", "h", "restart", "replay", "clear", "syms", "symbols", "allregs",
    "maps", "watch", "read", "x", "write", "save", "load", "input", "eof",
];

/// A one-line `.name args` naming a known command. Anything else starting
/// with a dot (e.g. the local label `.loop:`) is assembly.
fn as_command(text: &str) -> Option<&str> {
    let cmd = text.trim().strip_prefix('.')?;
    let name = cmd.split_whitespace().next()?;
    (!text.trim().contains('\n') && COMMANDS.contains(&name)).then_some(cmd)
}

/// `input hello` that failed to assemble was probably meant as `.input hello`.
fn missing_dot(text: &str) -> Option<&str> {
    let name = text.split_whitespace().next()?;
    (!text.trim().contains('\n') && COMMANDS.contains(&name) && name.len() > 1).then_some(name)
}

/// A line after which Enter continues the cell: a label or `;; def`.
fn opens_block(line: &str) -> bool {
    let line = line.trim();
    notebook::is_def(line) || (line.ends_with(':') && !line.starts_with(';'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_labels_are_not_commands() {
        assert_eq!(as_command(".watch rsp"), Some("watch rsp"));
        assert_eq!(as_command(".loop:"), None);
        assert_eq!(as_command(".loop: inc rax"), None);
        assert_eq!(as_command(".nosuch"), None);
    }

    #[test]
    fn hints_missing_dot() {
        assert_eq!(missing_dot("input hello !"), Some("input"));
        assert_eq!(missing_dot("mov rax, 1"), None);
    }

    #[test]
    fn block_openers() {
        assert!(opens_block("strlen:"));
        assert!(opens_block("  .loop:  "));
        assert!(opens_block(";; def"));
        assert!(!opens_block("mov rax, 1"));
        assert!(!opens_block("; note:"));
    }
}
