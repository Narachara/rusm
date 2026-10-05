use std::io::ErrorKind;
use std::process::Command;

use super::{AsmError, Assembled, Assembler, Layout};

pub struct Nasm {
    pub bits: u32,
}

/// Lines we prepend to the user's source; subtracted from error line numbers.
const HEADER_LINES: usize = 7;

impl Assembler for Nasm {
    fn assemble(
        &self,
        src: &str,
        layout: Layout,
        externs: &[(String, u64)],
    ) -> Result<Assembled, Vec<AsmError>> {
        let src_lines = src.lines().count();
        let mut externs: Vec<&(String, u64)> = externs.iter().collect();
        // A cell may redefine a symbol from an earlier cell. nasm reports that
        // on our appended `equ` line; drop the name and try again.
        loop {
            match self.run(src, layout, &externs) {
                Err(errs) => {
                    let redefined: Vec<_> = errs
                        .iter()
                        .filter(|e| e.line.is_some_and(|l| l > src_lines))
                        .filter_map(|e| redefined_name(&e.msg))
                        .collect();
                    if redefined.is_empty() {
                        return Err(errs
                            .into_iter()
                            .map(|e| blame_externs(e, src_lines))
                            .collect());
                    }
                    externs.retain(|(n, _)| !redefined.contains(&n.as_str()));
                }
                Ok(mut out) => {
                    out.symbols
                        .retain(|(n, _)| !externs.iter().any(|(e, _)| e == n));
                    return Ok(out);
                }
            }
        }
    }
}

impl Nasm {
    fn run(
        &self,
        src: &str,
        layout: Layout,
        externs: &[&(String, u64)],
    ) -> Result<Assembled, Vec<AsmError>> {
        let fail = |msg: String| vec![AsmError { line: None, msg }];

        let dir = tempfile::tempdir().map_err(|e| fail(format!("tempdir: {e}")))?;
        let input = dir.path().join("cell.asm");
        let output = dir.path().join("cell.bin");
        let map = dir.path().join("cell.map");

        // Externs go after the source so cell line numbers stay intact; nasm
        // resolves the forward references. The `$` prefix makes nasm read the
        // name as an identifier even when it is an instruction (`str`, `in`).
        // Code at layout.code; .data, .rodata and .bss one after another at
        // layout.data. In the output file .data/.rodata follow .text.
        let mut source = format!(
            "[bits {bits}]\n\
             section .text vstart={code:#x}\n\
             section .data vstart={data:#x} follows=.text align=1\n\
             section .rodata vfollows=.data follows=.data valign=16 align=1\n\
             section .bss nobits vfollows=.rodata valign=16\n\
             section .text\n\
             [map all {map}]\n{src}\n",
            bits = self.bits,
            code = layout.code,
            data = layout.data,
            map = map.display(),
        );
        for (name, value) in externs {
            source.push_str(&format!("${name} equ {value:#x}\n"));
        }
        std::fs::write(&input, source).map_err(|e| fail(format!("writing source: {e}")))?;

        let out = Command::new("nasm")
            .arg("-f")
            .arg("bin")
            .arg("-o")
            .arg(&output)
            .arg(&input)
            .output()
            .map_err(|e| match e.kind() {
                ErrorKind::NotFound => {
                    fail("nasm not found in PATH (install the `nasm` package)".into())
                }
                _ => fail(format!("running nasm: {e}")),
            })?;

        if !out.status.success() {
            let stderr = String::from_utf8_lossy(&out.stderr);
            let errs: Vec<_> = stderr.lines().filter_map(parse_diag).collect();
            return Err(if errs.is_empty() {
                fail(format!("nasm failed ({}): {}", out.status, stderr.trim()))
            } else {
                errs
            });
        }

        let bin = std::fs::read(&output).map_err(|e| fail(format!("reading nasm output: {e}")))?;
        let map =
            std::fs::read_to_string(&map).map_err(|e| fail(format!("reading nasm map: {e}")))?;
        let (code, data, bss) = split_sections(&bin, &parse_sections(&map), layout.data)?;
        Ok(Assembled {
            code,
            data,
            bss,
            symbols: parse_map(&map),
        })
    }
}

/// Parse `path:LINE: error: msg` into an [`AsmError`] relative to the cell.
fn parse_diag(line: &str) -> Option<AsmError> {
    let (loc, msg) = line.split_once(": error: ")?;
    let lineno = loc
        .rsplit(':')
        .next()
        .and_then(|n| n.parse::<usize>().ok())
        .and_then(|n| n.checked_sub(HEADER_LINES));
    Some(AsmError {
        line: lineno,
        msg: msg.to_string(),
    })
}

/// Errors past the cell's last line come from the appended extern `equ`s;
/// don't report them as a line of the cell.
fn blame_externs(mut e: AsmError, src_lines: usize) -> AsmError {
    if e.line.is_some_and(|l| l > src_lines) {
        e.line = None;
        e.msg = format!("in labels from earlier cells: {}", e.msg);
    }
    e
}

/// `label `foo' inconsistently redefined` -> `foo`
fn redefined_name(msg: &str) -> Option<&str> {
    if !msg.contains("redefined") {
        return None;
    }
    let start = msg.find('`')? + 1;
    let end = start + msg[start..].find('\'')?;
    Some(&msg[start..end])
}

/// One row of the map file's section summary.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Section {
    name: String,
    vstart: u64,
    /// Offset in the output file (progbits only).
    start: u64,
    len: u64,
}

/// Parse `-- Sections (summary)`:
/// `Vstart  Start  Stop  Length  Class  Name` (hex numbers).
fn parse_sections(map: &str) -> Vec<Section> {
    map.lines()
        .skip_while(|l| !l.starts_with("-- Sections (summary)"))
        .skip(1)
        .take_while(|l| !l.starts_with("--"))
        .filter_map(|l| {
            let c: Vec<_> = l.split_whitespace().collect();
            let [vstart, start, _stop, len, _class, name] = c[..] else {
                return None;
            };
            let hex = |s| u64::from_str_radix(s, 16).ok();
            Some(Section {
                name: name.to_string(),
                vstart: hex(vstart)?,
                start: hex(start)?,
                len: hex(len)?,
            })
        })
        .collect()
}

/// Split nasm's flat output into code, initialized data (placed from
/// `data_at`) and the number of zeroed bytes reserved after the data.
fn split_sections(
    bin: &[u8],
    sections: &[Section],
    data_at: u64,
) -> Result<(Vec<u8>, Vec<u8>, u64), Vec<AsmError>> {
    let fail = |msg: String| vec![AsmError { line: None, msg }];
    let bytes = |s: &Section| {
        bin.get(s.start as usize..(s.start + s.len) as usize)
            .ok_or_else(|| fail(format!("section {} is outside nasm's output", s.name)))
    };
    let (mut code, mut data, mut end) = (Vec::new(), Vec::new(), data_at);
    for s in sections.iter().filter(|s| s.len > 0) {
        match s.name.as_str() {
            ".text" => code = bytes(s)?.to_vec(),
            ".data" | ".rodata" => {
                data.resize((s.vstart - data_at) as usize, 0);
                data.extend_from_slice(bytes(s)?);
                end = end.max(s.vstart + s.len);
            }
            ".bss" => end = end.max(s.vstart + s.len),
            other => {
                return Err(fail(format!(
                    "unsupported section {other} (use .text, .data, .rodata or .bss)"
                )));
            }
        }
    }
    let bss = end - data_at - data.len() as u64;
    Ok((code, data, bss))
}

/// Symbols from a nasm map file: section labels (`Real Virtual Name` rows)
/// and constants (`Value Name` rows). Local labels keep their full name.
fn parse_map(text: &str) -> Vec<(String, u64)> {
    let mut syms = Vec::new();
    let mut in_symbols = false;
    for line in text.lines() {
        if line.starts_with("-- Symbols") {
            in_symbols = true;
            continue;
        }
        if !in_symbols || line.starts_with('-') {
            continue;
        }
        let cols: Vec<_> = line.split_whitespace().collect();
        let (value, name) = match cols[..] {
            [v, name] => (v, name),
            [_real, virt, name] => (virt, name),
            _ => continue,
        };
        let Ok(value) = u64::from_str_radix(value, 16) else {
            continue;
        };
        // `strlen.loop` is exported (usable as a full name); bare `.loop`
        // and nasm-internal `..@` labels are not.
        if !name.starts_with('.') {
            syms.push((name.to_string(), value));
        }
    }
    syms
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn diag_line_is_relative_to_cell() {
        let e = parse_diag("/tmp/x/cell.asm:9: error: parser: instruction expected").unwrap();
        assert_eq!(e.line, Some(2));
        assert_eq!(e.msg, "parser: instruction expected");
    }

    #[test]
    fn parses_map_file() {
        let map = "\
-- Symbols --------------------------------------------------------------------

---- No Section ---------------------------------------------------------------

Value     Name
00000005  K


---- Section .text ------------------------------------------------------------

Real              Virtual           Name
          400000            400000  strlen
          400002            400002  strlen.loop
          400006            400006  msg
";
        assert_eq!(
            parse_map(map),
            [
                ("K".to_string(), 5),
                ("strlen".to_string(), 0x400000),
                ("strlen.loop".to_string(), 0x400002),
                ("msg".to_string(), 0x400006)
            ]
        );
    }

    #[test]
    fn splits_sections() {
        let map = "\
-- Sections (summary) ---------------------------------------------------------

Vstart            Start             Stop              Length    Class     Name
          400040                 0                16  00000016  progbits  .text
          600010                16                1F  00000009  progbits  .data
          600020                1F                27  00000008  progbits  .rodata
          600030            600030            600070  00000040  nobits    .bss

-- Sections (detailed) ---------------------------------------------------------
";
        let secs = parse_sections(map);
        assert_eq!(secs.len(), 4);
        let bin: Vec<u8> = (0..0x27).collect();
        let (code, data, bss) = split_sections(&bin, &secs, 0x600010).unwrap();
        assert_eq!(code.len(), 0x16);
        // 9 bytes .data, 7 bytes alignment, 8 bytes .rodata
        assert_eq!(data.len(), 0x18);
        assert_eq!(&data[0x10..], &bin[0x1f..0x27]);
        // 8 bytes padding to the 16-aligned .bss, then 0x40
        assert_eq!(bss, 0x48);
    }

    #[test]
    fn extracts_redefined_name() {
        assert_eq!(
            redefined_name("label `foo' inconsistently redefined"),
            Some("foo")
        );
        assert_eq!(redefined_name("parser: instruction expected"), None);
    }
}
