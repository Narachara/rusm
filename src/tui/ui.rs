//! Rendering. Pure function of `App`.

use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Position, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span, Text};
use ratatui::widgets::{Block, BorderType, Clear, List, ListItem, ListState, Paragraph};

use super::app::{App, Focus, HELP, Level, MemView};
use crate::arch::RegState;
use crate::display;
use crate::notebook::{CellState, Mem, Region, Snapshot, WatchBase, parse_maps};
use crate::session::{Outcome, SyscallEvent};
use crate::tracee::Output;

const CHANGED: Style = Style::new().fg(Color::Yellow).add_modifier(Modifier::BOLD);
const DIM: Style = Style::new().fg(Color::DarkGray);
const ACCENT: Color = Color::Cyan;

pub fn draw(f: &mut Frame, app: &App) {
    let [main, status] =
        Layout::vertical([Constraint::Min(0), Constraint::Length(1)]).areas(f.area());
    let [left, right] = Layout::horizontal([
        Constraint::Min(40),
        Constraint::Length(right_width(f.area().width)),
    ])
    .areas(main);

    let editor_h = (app.editor.lines().len() as u16 + 2).clamp(3, 12);
    let [cells, editor, disasm] = Layout::vertical([
        Constraint::Min(5),
        Constraint::Length(editor_h),
        Constraint::Length(10),
    ])
    .areas(left);

    let (snap, cell) = app.view();
    let regs_h = regs_height(&snap.regs, app.allregs);
    let [regs, stack, mem] = Layout::vertical([
        Constraint::Length(regs_h),
        Constraint::Min(6),
        Constraint::Length(12),
    ])
    .areas(right);

    draw_cells(f, cells, app);
    draw_editor(f, editor, app);
    draw_disasm(f, disasm, app, snap);

    let when = match cell {
        Some(i) => format!(" after {} [{}] ", app.nb.cell_name(i), cell_label(app, i)),
        None => " live ".into(),
    };
    draw_regs(f, regs, snap, app.allregs, &when);
    draw_stack(f, stack, app, snap, &when);
    match app.mem_view {
        MemView::Hex => draw_mem(f, mem, app, snap, &when),
        MemView::Maps => draw_maps(f, mem, snap),
    }
    draw_status(f, status, app);

    if app.show_help {
        draw_help(f, app);
    }
}

fn block(title: impl Into<Line<'static>>, focused: bool) -> Block<'static> {
    let b = Block::bordered()
        .border_type(BorderType::Rounded)
        .title(title.into());
    if focused {
        b.border_style(Style::new().fg(ACCENT))
            .title_style(Style::new().fg(ACCENT).bold())
    } else {
        b.border_style(DIM)
    }
}

fn cell_label(app: &App, i: usize) -> String {
    app.nb.cells[i].count.map_or(" ".into(), |c| c.to_string())
}

fn draw_cells(f: &mut Frame, area: Rect, app: &App) {
    let focused = app.focus == Focus::Cells;
    // Position names padded to the longest, so the cell sources line up.
    let name_width = app.nb.cell_name(app.nb.cells.len().saturating_sub(1)).len();
    let items: Vec<ListItem> = app
        .nb
        .cells
        .iter()
        .enumerate()
        .map(|(i, c)| {
            let (mark, mark_style) = match &c.state {
                CellState::Pending => ("·", DIM),
                CellState::AsmError(_) => ("✗", Style::new().fg(Color::Red)),
                CellState::Ran(s) if s.outcome == Outcome::Done => {
                    ("✓", Style::new().fg(Color::Green))
                }
                CellState::Ran(s) if s.outcome == Outcome::WaitingForInput => {
                    ("?", Style::new().fg(Color::Yellow).bold())
                }
                CellState::Ran(_) => ("!", Style::new().fg(Color::Red).bold()),
                CellState::Defined(_) => ("◆", Style::new().fg(Color::Blue)),
            };
            let editing = app.editing == Some(i);
            let prompt = format!(
                "{:<name_width$} [{:>2}]",
                app.nb.cell_name(i),
                cell_label(app, i)
            );
            let mut lines = Vec::new();
            for (n, src) in c.src.lines().enumerate() {
                let head = if n == 0 {
                    vec![
                        Span::styled(prompt.clone(), Style::new().fg(ACCENT)),
                        Span::raw(" "),
                        Span::styled(mark, mark_style),
                        Span::raw(if editing { "✎ " } else { "  " }),
                    ]
                } else {
                    vec![Span::raw(" ".repeat(prompt.len() + 4))]
                };
                let mut spans = head;
                // Comments, including `;; def` and `;; stdin:` lines, are dimmed.
                let style = if src.trim_start().starts_with(';') {
                    DIM
                } else {
                    Style::new()
                };
                spans.push(Span::styled(src.to_string(), style));
                lines.push(Line::from(spans));
            }
            let indent = " ".repeat(prompt.len() + 4);
            syscall_lines(&mut lines, &indent, &c.syscalls);
            output_lines(&mut lines, &indent, &c.output);
            let red = Style::new().fg(Color::Red);
            let problem = match &c.state {
                CellState::Ran(s) => match s.outcome {
                    Outcome::StrayTrap { at } => Some((stray_trap_message(app, at), red)),
                    Outcome::WaitingForInput => Some((
                        "waiting for stdin: .input TEXT sends a line, .eof closes stdin".into(),
                        Style::new().fg(Color::Yellow),
                    )),
                    _ => display::outcome(&s.outcome).map(|m| (m, red)),
                },
                CellState::AsmError(errs) => Some((
                    errs.iter()
                        .map(|e| e.to_string())
                        .collect::<Vec<_>>()
                        .join("; "),
                    red,
                )),
                CellState::Pending => None,
                CellState::Defined(_) => {
                    let names: Vec<_> = c.symbols.iter().map(|(n, _)| n.as_str()).collect();
                    let data = c.data.len() as u64 + c.bss;
                    let mut msg =
                        (!names.is_empty()).then(|| format!("defines {}", names.join(", ")));
                    if data > 0 {
                        let d = format!("{data} data bytes at {:#x}", c.data_addr);
                        msg = Some(msg.map_or(d.clone(), |m| format!("{m} · {d}")));
                    }
                    msg.map(|m| (m, Style::new().fg(Color::Blue)))
                }
            };
            if let Some((msg, style)) = problem {
                lines.push(Line::styled(format!("{indent}↳ {msg}"), style));
            }
            ListItem::new(Text::from(lines))
        })
        .collect();

    let title = if app.nb.cells.is_empty() {
        " Cells (empty) ".to_string()
    } else {
        format!(" Cells ({}) ", app.nb.cells.len())
    };
    let list = List::new(items)
        .block(block(title, focused))
        .highlight_style(if focused {
            Style::new().bg(Color::Rgb(40, 44, 52))
        } else {
            Style::new()
        });
    // Outside cell focus, keep the newest cell in view.
    let sel = if focused {
        Some(app.selected)
    } else {
        app.nb.cells.len().checked_sub(1)
    };
    let mut state = ListState::default().with_selected(sel);
    f.render_stateful_widget(list, area, &mut state);
}

fn draw_editor(f: &mut Frame, area: Rect, app: &App) {
    let focused = app.focus == Focus::Editor;
    let title = match app.editing {
        Some(i) => format!(
            " Edit {} [{}] · Ctrl+R save+replay · Esc cancel ",
            app.nb.cell_name(i),
            cell_label(app, i).trim()
        ),
        None if app.nb.waiting.is_some() => {
            " In [ ] · a cell waits for stdin: .input TEXT · .eof ".into()
        }
        None if !app.nb.pending_input.is_empty() => format!(
            " In [ ] · {} stdin line(s) queued for the next cell ",
            app.nb.pending_input.len()
        ),
        None if app.in_block() => {
            " In [ ] · block: Enter new line · empty line or Ctrl+R runs ".into()
        }
        None => " In [ ] · Enter run · Ctrl+J new line ".into(),
    };
    let b = block(title, focused);
    let inner = b.inner(area);
    let (row, col) = app.editor.cursor();
    let scroll = (row as u16 + 1).saturating_sub(inner.height);
    let text: Vec<Line> = app
        .editor
        .lines()
        .iter()
        .map(|l| Line::raw(l.as_str()))
        .collect();
    f.render_widget(Paragraph::new(text).block(b).scroll((scroll, 0)), area);
    if focused && !app.show_help {
        let x = inner.x + (col as u16).min(inner.width.saturating_sub(1));
        f.set_cursor_position(Position::new(x, inner.y + row as u16 - scroll));
    }
}

fn draw_disasm(f: &mut Frame, area: Rect, app: &App, snap: &Snapshot) {
    let Some(mut i) = app.disasm_cell() else {
        f.render_widget(block(" Disassembly ", false), area);
        return;
    };
    let cells = &app.nb.cells;
    let pc = snap.regs.pc;
    let stopped = snap.outcome != Outcome::Done;
    // A fault inside code from another cell (e.g. a called function): show that cell.
    let contains = |c: &crate::notebook::Cell| (c.addr..c.addr + c.code.len() as u64).contains(&pc);
    if stopped
        && !contains(&cells[i])
        && let Some(j) = cells.iter().position(contains)
    {
        i = j;
    }
    let cell = &cells[i];
    let symbols = app.nb.symbols_by_addr();
    let insns = app
        .nb
        .sess
        .arch()
        .disassemble(&cell.code, cell.addr, &symbols);
    let rows = area.height.saturating_sub(2) as usize;
    let mut lines: Vec<Line> = Vec::new();
    for ins in &insns {
        if let Some(label) = symbols.get(&ins.addr) {
            lines.push(Line::styled(
                format!("{label}:"),
                Style::new().fg(Color::Blue).bold(),
            ));
        }
        let at_pc = ins.addr == pc && stopped;
        let bytes: String = ins.bytes.iter().map(|b| format!("{b:02x}")).collect();
        let style = if at_pc {
            Style::new().fg(Color::Red).bold()
        } else {
            Style::new()
        };
        lines.push(Line::from(vec![
            Span::styled(if at_pc { "→ " } else { "  " }, style),
            Span::styled(format!("{:08x}  ", ins.addr), DIM),
            Span::styled(format!("{bytes:<16} "), Style::new().fg(Color::Magenta)),
            Span::styled(ins.text.clone(), style),
        ]));
    }
    // Keep the faulting instruction in view.
    let pc_line = lines
        .iter()
        .position(|l| l.spans.first().is_some_and(|s| s.content == "→ "));
    let scroll = pc_line.map_or(0, |p| (p + 1).saturating_sub(rows)) as u16;
    let title = format!(
        " Disassembly {} [{}] @ {:#x} · {} bytes ",
        app.nb.cell_name(i),
        cell_label(app, i).trim(),
        cell.addr,
        cell.code.len()
    );
    f.render_widget(
        Paragraph::new(lines)
            .block(block(title, false))
            .scroll((scroll, 0)),
        area,
    );
}

fn regs_height(r: &RegState, all: bool) -> u16 {
    let gp = r.gp.len().div_ceil(3) as u16;
    let vec = if all { r.vector.len() as u16 } else { 0 };
    gp + 3 + vec + 2
}

fn changed<T: PartialEq>(prev: Option<T>, cur: T) -> bool {
    prev.is_some_and(|p| p != cur)
}

fn draw_regs(f: &mut Frame, area: Rect, s: &Snapshot, all: bool, when: &str) {
    let r = &s.regs;
    let prev = s.prev_regs.as_ref();
    let mut lines = Vec::new();

    for row in r.gp.chunks(3) {
        let mut spans = Vec::new();
        for g in row {
            let old = prev
                .and_then(|p| p.gp.iter().find(|o| o.name == g.name))
                .map(|o| o.value);
            let style = if changed(old, g.value) {
                CHANGED
            } else {
                Style::new()
            };
            spans.push(Span::styled(
                format!("{:>4} ", g.name),
                Style::new().fg(ACCENT),
            ));
            spans.push(Span::styled(format!("{:016x}", g.value), style));
            spans.push(Span::raw("  "));
        }
        lines.push(Line::from(spans));
    }

    let mut flags = vec![Span::styled(
        format!("{:>4} ", r.flags_name),
        Style::new().fg(ACCENT),
    )];
    flags.push(Span::raw(format!("{:08x}  ", r.flags_raw)));
    for fl in &r.flags {
        let old = prev
            .and_then(|p| p.flags.iter().find(|o| o.name == fl.name))
            .map(|o| o.set);
        // Case shows the state (CF set, cf clear); yellow means the last
        // cell changed it, as for register values.
        let style = if changed(old, fl.set) {
            CHANGED
        } else if fl.set {
            Style::new().bold()
        } else {
            DIM
        };
        let name = if fl.set {
            fl.name.to_uppercase()
        } else {
            fl.name.to_string()
        };
        flags.push(Span::styled(name, style));
        flags.push(Span::raw(" "));
    }
    lines.push(Line::from(flags));

    let short: Vec<_> = r
        .extra
        .iter()
        .filter(|e| !e.name.ends_with("_base"))
        .collect();
    let long: Vec<_> = r
        .extra
        .iter()
        .filter(|e| e.name.ends_with("_base"))
        .collect();
    let mut seg = Vec::new();
    for e in short {
        seg.push(Span::styled(format!("{:>4} ", e.name), DIM));
        seg.push(Span::raw(format!("{:04x} ", e.value)));
    }
    lines.push(Line::from(seg));
    let mut base = Vec::new();
    for e in long {
        seg_push(&mut base, e.name, e.value);
    }
    lines.push(Line::from(base));

    if all {
        for (name, v) in &r.vector {
            let old = prev
                .and_then(|p| p.vector.iter().find(|o| &o.0 == name))
                .map(|o| o.1);
            let style = if changed(old, *v) {
                CHANGED
            } else {
                Style::new()
            };
            lines.push(Line::from(vec![
                Span::styled(format!("{name:>6} "), Style::new().fg(ACCENT)),
                Span::styled(format!("{:016x}", (v >> 64) as u64), style),
                Span::raw(" "),
                Span::styled(format!("{:016x}", *v as u64), style),
            ]));
        }
    }

    f.render_widget(
        Paragraph::new(lines).block(block(format!(" Registers{when}"), false).title_bottom(
            Line::styled(
                " FLAG = set · flag = clear · yellow = changed by the cell ",
                DIM,
            ),
        )),
        area,
    );
}

fn seg_push(spans: &mut Vec<Span<'static>>, name: &str, value: u64) {
    spans.push(Span::styled(format!("{name:>8} "), DIM));
    spans.push(Span::raw(format!("{value:016x}  ")));
}

fn draw_stack(f: &mut Frame, area: Rect, app: &App, s: &Snapshot, when: &str) {
    let word = 8u64;
    let rbp = s.regs.gp.iter().find(|g| g.name == "rbp").map(|g| g.value);
    let rows = area.height.saturating_sub(2) as usize;
    // Start a couple of words below sp when the snapshot has them.
    let first = s.regs.sp.saturating_sub(2 * word).max(s.stack.addr);

    let mut lines = Vec::new();
    for n in 0..rows as u64 {
        let addr = first + n * word;
        let Some(val) = read_word(&s.stack, addr) else {
            break;
        };
        let old = s.prev_stack.as_ref().and_then(|p| read_word(p, addr));
        let marker = if addr == s.regs.sp {
            Span::styled("rsp→ ", Style::new().fg(Color::Green).bold())
        } else if Some(addr) == rbp {
            Span::styled("rbp→ ", Style::new().fg(Color::Blue).bold())
        } else {
            Span::raw("     ")
        };
        let below = addr < s.regs.sp;
        let addr_style = if below { DIM } else { Style::new().fg(ACCENT) };
        let val_style = if changed(old, val) {
            CHANGED
        } else if below {
            DIM
        } else {
            Style::new()
        };
        let mut spans = vec![
            marker,
            Span::styled(format!("{addr:016x}  "), addr_style),
            Span::styled(format!("{val:016x}"), val_style),
        ];
        let hint = annotate(val, s, app);
        if !hint.is_empty() {
            spans.push(Span::styled(format!("  {hint}"), DIM));
        }
        lines.push(Line::from(spans));
    }
    if lines.is_empty() {
        lines.push(Line::styled("stack not readable", DIM));
    }
    f.render_widget(
        Paragraph::new(lines).block(block(format!(" Stack{when}"), false)),
        area,
    );
}

fn read_word(m: &Mem, addr: u64) -> Option<u64> {
    let mut b = [0u8; 8];
    for (i, byte) in b.iter_mut().enumerate() {
        *byte = m.get(addr + i as u64)?;
    }
    Some(u64::from_le_bytes(b))
}

/// Short description of what a stack value points to, via the maps.
fn annotate(val: u64, s: &Snapshot, app: &App) -> String {
    if val == 0 {
        return String::new();
    }
    if let Some(sym) = app.nb.symbolize(val) {
        return format!("→ {sym}");
    }
    parse_maps(&s.maps)
        .iter()
        .find(|r| (r.lo..r.hi).contains(&val))
        .map_or(String::new(), |r| {
            format!("→ {} ({})", region_label(r, app), r.perms)
        })
}

/// Short name for a mapping: stack, heap, vdso, code, ...
fn region_label<'a>(r: &'a Region, app: &App) -> &'a str {
    if r.lo == app.nb.sess.data_range().start {
        return "data";
    }
    match r.name.as_str() {
        "" if r.perms.contains('x') => "code",
        "" => "anon",
        n if n.starts_with('/') => {
            if r.perms.contains('x') {
                "code"
            } else {
                "image"
            }
        }
        n => n.trim_matches(|c| c == '[' || c == ']'),
    }
}

fn draw_mem(f: &mut Frame, area: Rect, app: &App, s: &Snapshot, when: &str) {
    let focused = app.focus == Focus::Memory;
    let rows = area.height.saturating_sub(2) as usize;
    // addr + 3 chars per byte + separator + ascii
    let per_row = if area.width.saturating_sub(2) > 13 + 16 * 4 {
        16
    } else {
        8
    };
    app.mem_layout.set((rows, per_row));

    let top = s.watch_addr & !0xf;
    let mut lines = Vec::new();
    for n in 0..rows as u64 {
        let Some(base) = top.checked_add(n * per_row as u64) else {
            break;
        };
        let mut spans = vec![Span::styled(
            format!("{base:012x} "),
            Style::new().fg(ACCENT),
        )];
        let mut ascii = String::new();
        for i in 0..per_row as u64 {
            let addr = base + i;
            if i == 8 && per_row == 16 {
                spans.push(Span::raw(" "));
            }
            let Some(b) = s.mem.get(addr) else {
                spans.push(Span::styled("?? ", DIM));
                ascii.push(' ');
                continue;
            };
            let old = s.prev_mem.as_ref().and_then(|p| p.get(addr));
            let mut style = if changed(old, b) {
                CHANGED
            } else if b == 0 {
                DIM
            } else {
                Style::new()
            };
            if addr == s.watch_addr {
                style = style.add_modifier(Modifier::REVERSED);
            }
            spans.push(Span::styled(format!("{b:02x}"), style));
            spans.push(Span::raw(" "));
            ascii.push(if b.is_ascii_graphic() || b == b' ' {
                b as char
            } else {
                '.'
            });
        }
        spans.push(Span::styled(ascii, DIM));
        lines.push(Line::from(spans));
    }

    // Only the live view follows the current watch expression.
    let follows = matches!(app.nb.watch.base, WatchBase::Reg(_));
    let what = if when == " live " && follows {
        format!("{} = ", app.nb.watch.describe())
    } else {
        String::new()
    };
    let region = parse_maps(&s.maps)
        .into_iter()
        .find(|r| (r.lo..r.hi).contains(&s.watch_addr))
        .map_or("unmapped".to_string(), |r| {
            format!("{} {}", region_label(&r, app), r.perms)
        });
    let title = format!(" Memory {what}{:#x} [{region}]{when}", s.watch_addr);
    let mut b = block(title, focused);
    if !focused {
        b = b.title_bottom(Line::styled(" Tab here to scroll · g goto · F3 maps ", DIM));
    }
    f.render_widget(Paragraph::new(lines).block(b), area);
}

fn draw_maps(f: &mut Frame, area: Rect, s: &Snapshot) {
    let lines: Vec<Line> = s
        .maps
        .lines()
        .map(|l| {
            let mut p = l.split_whitespace();
            let range = p.next().unwrap_or("");
            let perms = p.next().unwrap_or("");
            let name = p.nth(3).unwrap_or("");
            Line::from(vec![
                Span::styled(format!("{range:<34}"), Style::new().fg(ACCENT)),
                Span::raw(format!("{perms}  ")),
                Span::styled(name.to_string(), DIM),
            ])
        })
        .collect();
    f.render_widget(
        Paragraph::new(lines).block(block(" Memory maps · F3 hexdump ", false)),
        area,
    );
}

fn draw_status(f: &mut Frame, area: Rect, app: &App) {
    if let Some(input) = &app.prompt {
        let label = " goto (ADDR, REG, REG+OFF): ";
        let line = Line::from(vec![
            Span::styled(label, Style::new().fg(ACCENT).bold()),
            Span::raw(input.as_str()),
        ]);
        f.render_widget(Paragraph::new(line), area);
        let x = area.x + (label.chars().count() + input.chars().count()) as u16;
        f.set_cursor_position(Position::new(x.min(area.right().saturating_sub(1)), area.y));
        return;
    }
    let line = match &app.status {
        Some((Level::Error, msg)) => Line::styled(format!(" {msg}"), Style::new().fg(Color::Red)),
        Some((Level::Info, msg)) => Line::styled(format!(" {msg}"), Style::new().fg(Color::Green)),
        None => {
            let hints = match app.focus {
                Focus::Editor => {
                    " Enter run · Ctrl+J new line · Ctrl+R run block · ↑↓ history · Tab cells/memory · F1 help · F2 all regs · F3 maps · F5 replay · Ctrl+Q quit"
                }
                Focus::Cells => {
                    " ↑↓ select (view state) · e edit · y copy · d delete · Tab memory · Esc editor · F1 help · Ctrl+Q quit"
                }
                Focus::Memory => {
                    " ↑↓ row · PgUp/PgDn page · g goto · s/p follow sp/pc · c/d code/data · [ ] regions · Home region start · Esc editor"
                }
            };
            Line::styled(hints, DIM)
        }
    };
    f.render_widget(Paragraph::new(line), area);
}

fn draw_help(f: &mut Frame, app: &App) {
    let area = f.area();
    let w = 80.min(area.width);
    let inner_w = w.saturating_sub(2).max(1) as usize;
    let lines: Vec<String> = HELP.lines().flat_map(|l| wrap(l, inner_w)).collect();
    let h = (lines.len() as u16 + 2).min(area.height);
    let rows = h.saturating_sub(2) as usize;
    let max = lines.len().saturating_sub(rows);
    app.help_layout.set((rows, max));
    let top = app.help_scroll.min(max);

    let popup = Rect::new((area.width - w) / 2, (area.height - h) / 2, w, h);
    f.render_widget(Clear, popup);
    let text: Vec<Line> = lines[top..]
        .iter()
        .take(rows)
        .map(|l| {
            if l.starts_with(' ') {
                Line::raw(l.clone())
            } else {
                Line::styled(l.clone(), Style::new().fg(ACCENT).bold())
            }
        })
        .collect();
    let mut b = block(" rusm help · Esc close ", true);
    if max > 0 {
        b = b.title_bottom(
            Line::from(format!(
                " ↑↓ PgUp/PgDn scroll · {}-{}/{} ",
                top + 1,
                top + rows,
                lines.len()
            ))
            .right_aligned(),
        );
    }
    f.render_widget(Paragraph::new(text).block(b), popup);
}

/// Word-wrap `line` to `width` columns; continuation lines keep the
/// line's indent plus two spaces so headings stay distinguishable.
fn wrap(line: &str, width: usize) -> Vec<String> {
    let indent = line.len() - line.trim_start().len() + 2;
    let mut out = Vec::new();
    let mut rest = line;
    let mut prefix = String::new();
    loop {
        let avail = width.saturating_sub(prefix.len()).max(1);
        if rest.chars().count() <= avail {
            out.push(format!("{prefix}{rest}"));
            return out;
        }
        let cut = rest
            .char_indices()
            .nth(avail)
            .map_or(rest.len(), |(i, _)| i);
        let at = match rest[..cut].rfind(' ') {
            Some(i) if i > 0 => i,
            _ => cut,
        };
        out.push(format!("{prefix}{}", rest[..at].trim_end()));
        rest = rest[at..].trim_start();
        prefix = " ".repeat(indent.min(width / 2));
    }
}

/// Right column: wide enough for a 16-byte hexdump when the terminal allows.
fn right_width(total: u16) -> u16 {
    if total >= 150 { 82 } else { 70 }
}

fn stray_trap_message(app: &App, at: u64) -> String {
    let sym = app.nb.symbolize(at);
    // Exactly on a label the user wrote: a label with no code after it (yet).
    let on_label = sym
        .as_ref()
        .is_some_and(|s| !s.contains('+') && !is_cell_name(s));
    if let Some(i) = app.nb.cell_end(at).filter(|_| !on_label) {
        let name = app.nb.cell_name(i);
        return format!(
            "reached the end of {name}: each cell ends in a trap. To come back, \
             `call {name}` with a `ret` at its end, or push a return address first"
        );
    }
    match sym {
        Some(sym) if on_label => format!(
            "stopped at `{sym}`: there is no code after this label (write the label and its code in one cell)"
        ),
        Some(sym) => {
            format!("stopped at {sym}: reached the end of that code without `ret`, or an int3")
        }
        None => display::outcome(&Outcome::StrayTrap { at }).unwrap_or_default(),
    }
}

/// `cell3`: an automatic cell name rather than a label the user wrote.
fn is_cell_name(s: &str) -> bool {
    s.strip_prefix("cell")
        .is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
}

/// Program output shown under a cell, like a notebook's `Out`.
/// Intercepted system calls shown under a cell: the decoded call, its
/// simulated return, and why it was not run.
fn syscall_lines(lines: &mut Vec<Line<'static>>, indent: &str, calls: &[SyscallEvent]) {
    for ev in calls {
        lines.push(Line::from(vec![
            Span::styled(format!("{indent}↳ "), DIM),
            Span::styled(ev.call.clone(), Style::new().fg(Color::Cyan)),
            Span::styled(format!(" = {}", ev.ret), Style::new().fg(Color::Cyan)),
            Span::styled(format!("  ({})", ev.note), DIM),
        ]));
    }
}

fn output_lines(lines: &mut Vec<Line<'static>>, indent: &str, out: &Output) {
    const MAX: usize = 12;
    let mut shown = 0;
    let mut total = 0;
    for (data, style) in [
        (&out.stdout, Style::new().fg(Color::White)),
        (&out.stderr, Style::new().fg(Color::LightRed)),
    ] {
        let text = String::from_utf8_lossy(data);
        for line in text.lines() {
            total += 1;
            if shown < MAX {
                shown += 1;
                // Keep the list layout intact: no raw control characters.
                let clean: String = line
                    .chars()
                    .map(|c| if c.is_control() { '·' } else { c })
                    .collect();
                lines.push(Line::from(vec![
                    Span::styled(format!("{indent}│ "), DIM),
                    Span::styled(clean, style),
                ]));
            }
        }
    }
    if total > shown {
        lines.push(Line::styled(
            format!("{indent}│ … {} more lines", total - shown),
            DIM,
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrap_keeps_short_lines_and_indents_continuations() {
        assert_eq!(wrap("  short", 20), vec!["  short"]);
        assert_eq!(wrap("", 20), vec![""]);
        assert_eq!(
            wrap("  aaa bbb ccc ddd", 10),
            vec!["  aaa bbb", "    ccc", "    ddd"]
        );
        for l in HELP.lines() {
            assert!(wrap(l, 30).iter().all(|w| w.chars().count() <= 30), "{l}");
        }
    }
}
