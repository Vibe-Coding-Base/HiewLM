//! hiewLM headless batch tool (`hiewlmc`) — inspect, disassemble, search, and
//! patch binaries from scripts/CI, reusing the same core/fmt/asm as the TUI.
//! The target file is always treated as passive data — never executed.

use anyhow::{anyhow, bail, Context, Result};
use clap::{Parser, Subcommand};
use hiewlm_asm::Disassembler;
use hiewlm_core::{
    find_all, Arch, EditBuffer, ExecutableModel, FileOffset, FileSource, Pattern, Va,
};
use std::path::{Path, PathBuf};
use std::sync::Arc;

#[derive(Parser)]
#[command(name = "hiewlmc", version, about = "hiewLM batch tool (headless)")]
struct Cli {
    /// Activate container-format plugins: `zip`, `pdf`, or `all`.
    /// Repeat or comma-separate. Plugins are off unless named.
    #[arg(long = "plugin", short = 'P', global = true, value_delimiter = ',')]
    plugins: Vec<String>,

    #[command(subcommand)]
    cmd: Cmd,
}

/// Build the registry of available container plugins and switch on the ones
/// the user asked for. Registration is static: no code is loaded at runtime.
fn registry(enable: &[String]) -> Result<hiewlm_core::ContainerRegistry> {
    let mut reg = hiewlm_core::ContainerRegistry::new();
    reg.register(Box::new(hiewlm_plugin_zip::ZipPlugin));
    reg.register(Box::new(hiewlm_plugin_pdf::PdfPlugin));
    let unknown = reg.enable(enable);
    if !unknown.is_empty() {
        bail!(
            "unknown plugin(s): {}. Available: {}",
            unknown.join(", "),
            reg.names().join(", ")
        );
    }
    Ok(reg)
}

#[derive(Subcommand)]
enum Cmd {
    /// Format, arch, entry point, sections, imports/exports, header fields.
    Info { file: PathBuf },
    /// List the members of a container file (needs `--plugin zip|pdf|all`).
    Container {
        file: PathBuf,
        /// Only print findings (active content, droppers, traversal).
        #[arg(long)]
        findings: bool,
        /// Exit 1 if any member/finding is flagged suspicious.
        #[arg(long)]
        fail_on_suspicious: bool,
    },
    /// One-screen triage verdict: hashes, packer, anomalies, capabilities, IOCs.
    /// Give a directory to rank a whole folder of samples.
    Triage {
        /// File or directory to triage.
        file: PathBuf,
        /// Emit JSON instead of text (one object per file; an array for a folder).
        #[arg(long)]
        json: bool,
        /// Exit 1 when the score reaches this threshold (default 40 with the flag).
        #[arg(long)]
        fail_on_suspicious: bool,
        /// Score threshold for --fail-on-suspicious and folder filtering.
        #[arg(long, default_value_t = 40)]
        min_score: u8,
        /// Cap the bytes scanned for strings (0 = whole file).
        #[arg(long, default_value_t = 64 * 1024 * 1024)]
        max_string_bytes: u64,
        /// Also scan with these YARA rules and fold the result into the verdict.
        #[arg(long)]
        yara: Option<PathBuf>,
    },
    /// Scan with YARA rules (a file, or a folder of .yar/.yara).
    /// Needs a build with `--features yara`.
    Yara {
        file: PathBuf,
        rules: PathBuf,
        /// Exit 1 when any rule matches.
        #[arg(long)]
        fail_on_match: bool,
    },
    /// Recover a repeating XOR key from a region and print the decoded preview.
    Xorkey {
        file: PathBuf,
        /// Start of the region: offset (hex), `.va`, `+n`, `Nt` decimal.
        #[arg(long, default_value = "0")]
        at: String,
        /// Bytes to analyse (0 = to the end of the file).
        #[arg(long, default_value_t = 4096)]
        count: u64,
        /// Longest key length to consider.
        #[arg(long, default_value_t = 32)]
        max_len: usize,
    },
    /// List the container plugins compiled in.
    Plugins,
    /// Hex + ASCII dump.
    Hex {
        file: PathBuf,
        /// Start address: offset (hex), `.va`, `+n`, `Nt` decimal.
        #[arg(long, default_value = "0")]
        at: String,
        #[arg(long, default_value_t = 256)]
        count: u64,
    },
    /// Disassemble instructions.
    Disasm {
        file: PathBuf,
        /// Start address (default: entry point, else 0).
        #[arg(long)]
        at: Option<String>,
        #[arg(long, default_value_t = 32)]
        count: usize,
        /// Override arch: x86, x86-16, x64, arm, arm64, mips, riscv, ppc, sparc.
        #[arg(long)]
        arch: Option<String>,
    },
    /// Find every occurrence of a pattern; prints offsets. Exit 1 if none.
    Search {
        file: PathBuf,
        pattern: String,
        /// Interpret the pattern as hex bytes (e.g. "de ad ?? ef").
        #[arg(long)]
        hex: bool,
    },
    /// Replace every occurrence of `find` with `with` (writes the file).
    Replace {
        file: PathBuf,
        find: String,
        with: String,
        #[arg(long)]
        hex: bool,
        #[arg(long)]
        no_backup: bool,
    },
    /// Overwrite bytes at an address (writes the file).
    Patch {
        file: PathBuf,
        at: String,
        /// Hex bytes to write, e.g. "90 90 c3".
        bytes: String,
        #[arg(long)]
        no_backup: bool,
    },
    /// Assemble x86/x86-64 text and patch it in at an address (writes the file).
    Asm {
        file: PathBuf,
        /// Where to patch: offset (hex), `.va`, or `Nt` decimal.
        at: String,
        /// Instruction text, e.g. "xor eax, eax".
        text: String,
        /// 16, 32 or 64. Default: the file's detected bitness.
        #[arg(long)]
        bits: Option<u8>,
        /// Show the encoding without writing.
        #[arg(long)]
        dry_run: bool,
        #[arg(long)]
        no_backup: bool,
    },
    /// Apply a crypt recipe (xor/add/sub/rol/ror/not/neg) to a byte range.
    Crypt {
        file: PathBuf,
        /// Recipe, e.g. "xor 5a, rol 3".
        recipe: String,
        #[arg(long, default_value = "0")]
        at: String,
        /// Bytes to transform; 0 = to end of file.
        #[arg(long, default_value_t = 0)]
        count: u64,
        /// Print the result without writing.
        #[arg(long)]
        dry_run: bool,
        #[arg(long)]
        no_backup: bool,
    },
    /// CRC32 / MD5 / SHA-256 / BLAKE3 of the file.
    Hash { file: PathBuf },
    /// List printable ASCII strings.
    Strings {
        file: PathBuf,
        #[arg(long, default_value_t = 4)]
        min: usize,
        /// Also list UTF-16LE (wide) strings — where Windows malware keeps its
        /// configuration. On by default; `--no-utf16` turns it off.
        #[arg(long = "no-utf16", action = clap::ArgAction::SetFalse)]
        utf16: bool,
        /// Only strings carrying an indicator (URL, IP, registry, LOLBin, …).
        #[arg(long)]
        ioc: bool,
    },
    /// Shannon entropy of the file and each section.
    Entropy { file: PathBuf },
    /// Detect packers/protectors (signatures + entropy/import heuristics).
    Packer { file: PathBuf },
    /// Run a Rhai script against a file for automated inspection/patching.
    Script {
        file: PathBuf,
        script: PathBuf,
    },
    /// Run a sandboxed WASM plugin (.wasm/.wat) against a file.
    Plugin {
        file: PathBuf,
        wasm: PathBuf,
    },
}

fn main() -> std::process::ExitCode {
    let cli = Cli::parse();
    match run(cli.cmd, &cli.plugins) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("error: {e:#}");
            std::process::ExitCode::from(2)
        }
    }
}

fn run(cmd: Cmd, plugins: &[String]) -> Result<std::process::ExitCode> {
    use std::process::ExitCode;
    let out = match cmd {
        Cmd::Plugins => cmd_plugins()?,
        Cmd::Xorkey { file, at, count, max_len } => cmd_xorkey(&file, &at, count, max_len)?,
        Cmd::Yara { file, rules, fail_on_match } => {
            let (text, matched) = cmd_yara(&file, &rules)?;
            print!("{text}");
            return Ok(if matched && fail_on_match { ExitCode::from(1) } else { ExitCode::SUCCESS });
        }
        Cmd::Triage { file, json, fail_on_suspicious, min_score, max_string_bytes, yara } => {
            let (text, worst) =
                cmd_triage(&file, plugins, json, min_score, max_string_bytes, yara.as_deref())?;
            print!("{text}");
            return Ok(if fail_on_suspicious && worst >= min_score {
                ExitCode::from(1)
            } else {
                ExitCode::SUCCESS
            });
        }
        Cmd::Container { file, findings, fail_on_suspicious } => {
            let (text, suspicious) = cmd_container(&file, plugins, findings)?;
            print!("{text}");
            return Ok(if suspicious && fail_on_suspicious {
                ExitCode::from(1)
            } else {
                ExitCode::SUCCESS
            });
        }
        Cmd::Info { file } => cmd_info(&file, plugins)?,
        Cmd::Hex { file, at, count } => cmd_hex(&file, &at, count)?,
        Cmd::Disasm { file, at, count, arch } => cmd_disasm(&file, at.as_deref(), count, arch.as_deref())?,
        Cmd::Search { file, pattern, hex } => {
            let (text, found) = cmd_search(&file, &pattern, hex)?;
            print!("{text}");
            return Ok(if found { ExitCode::SUCCESS } else { ExitCode::from(1) });
        }
        Cmd::Replace { file, find, with, hex, no_backup } => cmd_replace(&file, &find, &with, hex, !no_backup)?,
        Cmd::Patch { file, at, bytes, no_backup } => cmd_patch(&file, &at, &bytes, !no_backup)?,
        Cmd::Asm { file, at, text, bits, dry_run, no_backup } => {
            cmd_asm(&file, &at, &text, bits, dry_run, !no_backup)?
        }
        Cmd::Crypt { file, recipe, at, count, dry_run, no_backup } => {
            cmd_crypt(&file, &recipe, &at, count, dry_run, !no_backup)?
        }
        Cmd::Hash { file } => cmd_hash(&file)?,
        Cmd::Strings { file, min, utf16, ioc } => cmd_strings(&file, min, utf16, ioc)?,
        Cmd::Entropy { file } => cmd_entropy(&file)?,
        Cmd::Packer { file } => cmd_packer(&file)?,
        Cmd::Script { file, script } => cmd_script(&file, &script)?,
        Cmd::Plugin { file, wasm } => cmd_plugin(&file, &wasm)?,
    };
    print!("{out}");
    Ok(ExitCode::SUCCESS)
}

// ── shared helpers ──────────────────────────────────────────────

fn open(path: &Path) -> Result<(EditBuffer, Option<ExecutableModel>)> {
    // `pid:<N>` opens live process memory (Linux only) — offsets are virtual addrs.
    if let Some(pid) = path.to_string_lossy().strip_prefix("pid:") {
        #[cfg(target_os = "linux")]
        {
            let pid: u32 = pid.parse().context("bad pid")?;
            let src = hiewlm_core::buffer::ProcSource::open(pid)
                .with_context(|| format!("cannot read /proc/{pid}/mem (need ptrace permission)"))?;
            let buf = EditBuffer::new(Arc::new(src));
            let model = hiewlm_fmt::detect(&buf);
            return Ok((buf, model));
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = pid;
            bail!("reading process memory (pid:N) is only supported on Linux");
        }
    }
    let src = FileSource::open(path).with_context(|| format!("cannot open {}", path.display()))?;
    let buf = EditBuffer::new(Arc::new(src));
    let model = hiewlm_fmt::detect(&buf);
    Ok((buf, model))
}

/// Parse a number: hex by default; `0x`/`h` hex, `t` decimal, `0b`/`i` binary, `0o`/`o` octal.
fn parse_num(s: &str) -> Result<u64> {
    let s = s.trim();
    let e = || anyhow!("bad number '{s}'");
    if let Some(r) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        return u64::from_str_radix(r, 16).map_err(|_| e());
    }
    if let Some(r) = s.strip_suffix(['t', 'T']) {
        return r.parse().map_err(|_| e());
    }
    if let Some(r) = s.strip_suffix(['o', 'O']) {
        return u64::from_str_radix(r, 8).map_err(|_| e());
    }
    if let Some(r) = s.strip_suffix(['i', 'I']) {
        return u64::from_str_radix(r, 2).map_err(|_| e());
    }
    let r = s.strip_suffix(['h', 'H']).unwrap_or(s);
    u64::from_str_radix(r, 16).map_err(|_| e())
}

/// Parse an address argument: `.va` → file offset via the model, else an offset.
fn parse_addr(s: &str, model: &Option<ExecutableModel>) -> Result<u64> {
    if let Some(rest) = s.strip_prefix('.') {
        let va = parse_num(rest)?;
        return model
            .as_ref()
            .and_then(|m| m.address_space.offset_of(Va(va)))
            .map(|o| o.get())
            .ok_or_else(|| anyhow!("VA .{rest} is not mapped to a file offset"));
    }
    parse_num(s)
}

fn parse_hex_bytes(input: &str) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    for tok in input.split_whitespace() {
        if tok.len() % 2 != 0 {
            bail!("odd-length hex token '{tok}'");
        }
        for pair in tok.as_bytes().chunks(2) {
            let s = std::str::from_utf8(pair)?;
            out.push(u8::from_str_radix(s, 16).with_context(|| format!("bad hex '{s}'"))?);
        }
    }
    if out.is_empty() {
        bail!("no bytes given");
    }
    Ok(out)
}

fn pattern_of(s: &str, hex: bool) -> Result<Pattern> {
    if hex {
        Pattern::from_hex(s).map_err(|_| anyhow!("invalid hex pattern"))
    } else {
        Ok(Pattern::from_text(s))
    }
}

fn arch_of(name: &str) -> Result<(Arch, u8)> {
    Ok(match name {
        "x86" | "x86-32" | "ia32" => (Arch::X86, 32),
        "x86-16" | "16" => (Arch::X86, 16),
        "x64" | "x86-64" | "amd64" => (Arch::X86_64, 64),
        "arm" => (Arch::Arm, 32),
        "arm64" | "aarch64" => (Arch::Arm64, 64),
        "mips" => (Arch::Mips, 32),
        "mips64" => (Arch::Mips, 64),
        "riscv" | "riscv64" => (Arch::Riscv, 64),
        "riscv32" => (Arch::Riscv, 32),
        "ppc" | "powerpc" => (Arch::Ppc, 32),
        "ppc64" | "powerpc64" => (Arch::Ppc, 64),
        "sparc" => (Arch::Sparc, 32),
        other => bail!("unknown arch '{other}'"),
    })
}

fn read_all(buf: &EditBuffer) -> Vec<u8> {
    let mut v = vec![0u8; buf.len() as usize];
    buf.read_at(FileOffset(0), &mut v);
    v
}

fn backup(path: &Path) -> Result<()> {
    let mut b = path.as_os_str().to_os_string();
    b.push(".bak");
    std::fs::copy(path, PathBuf::from(b))?;
    Ok(())
}

fn entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut freq = [0u64; 256];
    for &b in data {
        freq[b as usize] += 1;
    }
    let total = data.len() as f64;
    let mut h = 0.0;
    for &c in &freq {
        if c > 0 {
            let p = c as f64 / total;
            h -= p * p.log2();
        }
    }
    h
}

// ── commands ────────────────────────────────────────────────────

fn cmd_plugins() -> Result<String> {
    let reg = registry(&[])?;
    let mut s = String::from("container plugins (enable with --plugin <name>, or `all`):\n");
    for (name, desc) in reg.descriptions() {
        s.push_str(&format!("  {name:<6} {desc}\n"));
    }
    Ok(s)
}

fn cmd_container(file: &Path, plugins: &[String], only_findings: bool) -> Result<(String, bool)> {
    if plugins.is_empty() {
        bail!("no plugin activated — pass --plugin zip|pdf|all (see `hiewlmc plugins`)");
    }
    let reg = registry(plugins)?;
    let (buf, _) = open(file)?;
    let data = read_all(&buf);
    let Some((name, c)) = reg.parse(&data) else {
        bail!(
            "no enabled plugin recognizes {} (enabled: {})",
            file.display(),
            plugins.join(", ")
        );
    };

    let mut s = String::new();
    let suspicious = c.suspicious().count() > 0;
    if !only_findings {
        s.push_str(&format!("file      {}\nplugin    {name}\nkind      {}\n", file.display(), c.kind));
        for (k, v) in &c.summary {
            s.push_str(&format!("  {k:<14} {v}\n"));
        }
        s.push_str(&format!("\nmembers ({}):\n", c.members.len()));
        for m in &c.members {
            s.push_str(&format!("  off:{:08X}  {:<40} {}\n", m.offset, m.name, m.detail));
        }
    }
    if !c.findings.is_empty() {
        s.push_str(&format!("\nfindings ({}):\n", c.findings.len()));
        for f in &c.findings {
            let at = f.offset.map(|o| format!(" @{o:08X}")).unwrap_or_default();
            s.push_str(&format!("  [{}]{at} {}\n", f.severity, f.message));
        }
    }
    Ok((s, suspicious))
}

fn cmd_info(file: &Path, plugins: &[String]) -> Result<String> {
    let (buf, model) = open(file)?;
    let mut s = String::new();
    s.push_str(&format!("file      {}\nsize      {}\n", file.display(), buf.len()));
    let Some(m) = model else {
        // Not an executable — an activated container plugin may still know it.
        if !plugins.is_empty() {
            if let Ok((text, _)) = cmd_container(file, plugins, false) {
                return Ok(text);
            }
        }
        s.push_str("format    raw (unrecognized)\n");
        if plugins.is_empty() {
            s.push_str("hint      try --plugin all if this is a container (zip/pdf)\n");
        }
        return Ok(s);
    };
    s.push_str(&format!("format    {}\narch      {} / {}-bit\n", m.format.label(), m.arch.label(), m.bits));
    if let Some(e) = m.entry {
        s.push_str(&format!("entry     .{e:08X}\n"));
    }
    s.push_str(&format!("sections  {}  imports {}  exports {}\n", m.address_space.sections().len(), m.imports.len(), m.exports.len()));
    s.push_str(&format!("packer    {}\n", packer_report(&buf, &Some(m.clone())).summary()));
    for (k, v) in &m.header_fields {
        s.push_str(&format!("  {k:<18} {v}\n"));
    }
    if m.format.is_container() {
        s.push_str("\nmembers:\n");
        for sym in &m.exports {
            s.push_str(&format!("  off:{:08X}  {}\n", sym.va, sym.name));
        }
        return Ok(s);
    }
    s.push_str("\nsections:\n");
    for sec in m.address_space.sections() {
        s.push_str(&format!("  {:<16} off:{:08X} va:.{:08X} size:{:X}\n", sec.name, sec.file_off, sec.va, sec.size));
    }
    Ok(s)
}

fn cmd_hex(file: &Path, at: &str, count: u64) -> Result<String> {
    let (buf, model) = open(file)?;
    let start = parse_addr(at, &model)?;
    let end = (start + count).min(buf.len());
    let mut s = String::new();
    let mut off = start;
    while off < end {
        let row = (end - off).min(16);
        let mut bytes = [0u8; 16];
        buf.read_at(FileOffset(off), &mut bytes[..row as usize]);
        s.push_str(&format!("{off:08X}: "));
        for i in 0..16 {
            if i < row {
                s.push_str(&format!("{:02X} ", bytes[i as usize]));
            } else {
                s.push_str("   ");
            }
        }
        s.push_str(" |");
        for &b in &bytes[..row as usize] {
            s.push(if (0x20..0x7f).contains(&b) { b as char } else { '.' });
        }
        s.push_str("|\n");
        off += row;
    }
    Ok(s)
}

fn cmd_disasm(file: &Path, at: Option<&str>, count: usize, arch: Option<&str>) -> Result<String> {
    let (buf, model) = open(file)?;
    let (a, bits) = match arch {
        Some(name) => arch_of(name)?,
        None => model.as_ref().map(|m| (m.arch, m.bits)).unwrap_or((Arch::X86_64, 64)),
    };
    if !Disassembler::supports(a) {
        bail!("disassembly for {} is not supported yet", a.label());
    }
    let start = match at {
        Some(s) => parse_addr(s, &model)?,
        None => model
            .as_ref()
            .and_then(|m| m.entry)
            .and_then(|va| model.as_ref().and_then(|m| m.address_space.offset_of(Va(va))))
            .map(|o| o.get())
            .unwrap_or(0),
    };
    let va = model
        .as_ref()
        .and_then(|m| m.address_space.va_of(FileOffset(start)))
        .map(|v| v.get())
        .unwrap_or(start);

    let want = (count * 15).min((buf.len().saturating_sub(start)) as usize);
    let mut data = vec![0u8; want];
    buf.read_at(FileOffset(start), &mut data);
    let mut s = String::new();
    for ins in Disassembler::new(a, bits).decode(&data, start, va, count) {
        let hexb: String = ins.bytes.iter().map(|b| format!("{b:02X}")).collect::<Vec<_>>().join("");
        s.push_str(&format!("{:08X}: {:<20} {}\n", ins.va, hexb, ins.text));
    }
    Ok(s)
}

fn cmd_search(file: &Path, pattern: &str, hex: bool) -> Result<(String, bool)> {
    let (buf, _) = open(file)?;
    let pat = pattern_of(pattern, hex)?;
    let hits = find_all(&buf, &pat, FileOffset(0), FileOffset(buf.len()));
    let mut s = String::new();
    for h in &hits {
        s.push_str(&format!("{:08X}\n", h.get()));
    }
    s.push_str(&format!("# {} match(es)\n", hits.len()));
    Ok((s, !hits.is_empty()))
}

fn cmd_replace(file: &Path, find: &str, with: &str, hex: bool, do_backup: bool) -> Result<String> {
    let needle = if hex { parse_hex_bytes(find)? } else { find.as_bytes().to_vec() };
    let repl = if hex { parse_hex_bytes(with)? } else { with.as_bytes().to_vec() };
    if needle.is_empty() {
        bail!("empty search pattern");
    }
    let data = std::fs::read(file)?;
    let (out, count) = replace_all(&data, &needle, &repl);
    if count == 0 {
        return Ok("# 0 replacements (file unchanged)\n".into());
    }
    if do_backup {
        backup(file)?;
    }
    std::fs::write(file, &out)?;
    Ok(format!("# replaced {count} occurrence(s){}\n", if do_backup { ", .bak saved" } else { "" }))
}

fn cmd_patch(file: &Path, at: &str, bytes: &str, do_backup: bool) -> Result<String> {
    let (_buf, model) = open(file)?;
    let off = parse_addr(at, &model)? as usize;
    let patch = parse_hex_bytes(bytes)?;
    let mut data = std::fs::read(file)?;
    if off + patch.len() > data.len() {
        bail!("patch at {off:#x} + {} bytes exceeds file size {}", patch.len(), data.len());
    }
    if do_backup {
        backup(file)?;
    }
    data[off..off + patch.len()].copy_from_slice(&patch);
    std::fs::write(file, &data)?;
    Ok(format!("# wrote {} byte(s) at {off:#x}{}\n", patch.len(), if do_backup { ", .bak saved" } else { "" }))
}

fn cmd_asm(
    file: &Path,
    at: &str,
    text: &str,
    bits: Option<u8>,
    dry_run: bool,
    make_backup: bool,
) -> Result<String> {
    let (buf, model) = open(file)?;
    let off = parse_addr(at, &model)?;
    let bits = bits.or_else(|| model.as_ref().map(|m| m.bits)).unwrap_or(64);
    if !matches!(bits, 16 | 32 | 64) {
        bail!("bits must be 16, 32 or 64");
    }
    // Branches encode relative to the runtime address, not the file offset.
    let rip = model
        .as_ref()
        .and_then(|m| m.address_space.va_of(FileOffset(off)))
        .map(|v| v.get())
        .unwrap_or(off);

    let bytes = hiewlm_asm::assemble(text, bits, rip).map_err(|e| anyhow!("{e}"))?;
    let hex: Vec<String> = bytes.iter().map(|b| format!("{b:02X}")).collect();
    let mut s = format!(
        "{off:08X}: {}   ; {text}  ({}-bit, rip={rip:#x})\n",
        hex.join(" "),
        bits
    );
    if dry_run {
        s.push_str("# dry run, nothing written\n");
        return Ok(s);
    }
    let mut data = read_all(&buf);
    if off as usize + bytes.len() > data.len() {
        bail!("patch would run past end of file");
    }
    if make_backup {
        backup(file)?;
    }
    data[off as usize..off as usize + bytes.len()].copy_from_slice(&bytes);
    std::fs::write(file, &data).with_context(|| format!("writing {}", file.display()))?;
    s.push_str(&format!("# wrote {} byte(s){}\n", bytes.len(), if make_backup { " (.bak saved)" } else { "" }));
    Ok(s)
}

fn cmd_crypt(
    file: &Path,
    recipe: &str,
    at: &str,
    count: u64,
    dry_run: bool,
    make_backup: bool,
) -> Result<String> {
    let r = hiewlm_core::crypt::parse(recipe).map_err(|e| anyhow!("{e}"))?;
    let (buf, model) = open(file)?;
    let start = parse_addr(at, &model)?;
    let mut data = read_all(&buf);
    if start >= data.len() as u64 {
        bail!("start {start:#x} is past end of file");
    }
    let end = if count == 0 { data.len() as u64 } else { (start + count).min(data.len() as u64) };
    let (s, e) = (start as usize, end as usize);

    let before: Vec<u8> = data[s..e.min(s + 16)].to_vec();
    r.apply(&mut data[s..e], 0);
    let after: Vec<u8> = data[s..e.min(s + 16)].to_vec();

    let hex = |v: &[u8]| v.iter().map(|b| format!("{b:02X}")).collect::<Vec<_>>().join(" ");
    let mut out = format!(
        "{recipe}\n  range   {start:08X}..{end:08X} ({} bytes)\n  before  {}\n  after   {}\n",
        e - s,
        hex(&before),
        hex(&after)
    );
    out.push_str(&match r.inverse() {
        Some(_) => "  inverse available (re-apply to restore)\n".to_string(),
        None => "  lossy: and/or cannot be inverted\n".to_string(),
    });
    if dry_run {
        out.push_str("# dry run, nothing written\n");
        return Ok(out);
    }
    if make_backup {
        backup(file)?;
    }
    std::fs::write(file, &data).with_context(|| format!("writing {}", file.display()))?;
    out.push_str(&format!("# wrote {} byte(s){}\n", e - s, if make_backup { " (.bak saved)" } else { "" }));
    Ok(out)
}

fn cmd_hash(file: &Path) -> Result<String> {
    use md5::Digest;
    let (buf, _) = open(file)?;
    let mut crc = crc32fast::Hasher::new();
    let mut md5 = md5::Md5::new();
    let mut sha = sha2::Sha256::new();
    let mut blake = blake3::Hasher::new();
    let mut off = 0u64;
    let mut chunk = vec![0u8; 64 * 1024];
    while off < buf.len() {
        let n = ((buf.len() - off) as usize).min(chunk.len());
        buf.read_at(FileOffset(off), &mut chunk[..n]);
        crc.update(&chunk[..n]);
        md5.update(&chunk[..n]);
        sha.update(&chunk[..n]);
        blake.update(&chunk[..n]);
        off += n as u64;
    }
    let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
    Ok(format!(
        "CRC32   {:08X}\nMD5     {}\nSHA-256 {}\nBLAKE3  {}\n",
        crc.finalize(),
        hex(&md5.finalize()),
        hex(&sha.finalize()),
        blake.finalize().to_hex()
    ))
}

fn cmd_strings(file: &Path, min: usize, utf16: bool, ioc: bool) -> Result<String> {
    let (buf, _) = open(file)?;
    let scan = hiewlm_core::strings::extract_buffer(
        &buf,
        &hiewlm_core::strings::Options {
            min_len: min,
            ascii: true,
            utf16,
            max_results: 0,
            max_bytes: 0,
            only_tagged: ioc,
        },
    );
    let mut s = String::new();
    for f in &scan.strings {
        let tags = if f.kinds.is_empty() { String::new() } else { format!("[{}] ", f.kind_list()) };
        s.push_str(&format!("{:08X} {} {tags}{}\n", f.offset, f.enc.label(), f.text));
    }
    if scan.truncated {
        s.push_str("... (truncated: scan hit its limit)\n");
    }
    Ok(s)
}

fn cmd_xorkey(file: &Path, at: &str, count: u64, max_len: usize) -> Result<String> {
    let (buf, model) = open(file)?;
    let start = parse_addr(at, &model)?;
    let avail = buf.len().saturating_sub(start);
    let len = if count == 0 { avail } else { count.min(avail) };
    if len < 16 {
        bail!("region is too small ({len} bytes) to recover a key from");
    }
    let mut data = vec![0u8; len as usize];
    buf.read_at(FileOffset(start), &mut data);

    let cands = hiewlm_core::xorsearch::infer_repeating_key(&data, max_len, 8);
    if cands.is_empty() {
        return Ok("no repeating XOR key explains this region as plaintext\n".into());
    }
    let mut out = format!("region {start:#x}..{:#x} ({len} bytes)\n", start + len);
    for c in &cands {
        let printable: String = c
            .key
            .iter()
            .map(|&b| if (0x20..0x7f).contains(&b) { b as char } else { '.' })
            .collect();
        out.push_str(&format!(
            "{:>3}B  {:>3.0}%  {:<34} \"{printable}\"\n      {}\n",
            c.key.len(),
            c.score * 100.0,
            c.recipe(),
            c.preview
        ));
    }
    out.push_str(&format!(
        "\nApply with:  hiewlmc crypt {} \"{}\" --at {start:x} --count {len} --dry-run\n",
        file.display(),
        cands[0].recipe()
    ));
    Ok(out)
}

fn cmd_yara(file: &Path, rules: &Path) -> Result<(String, bool)> {
    let (buf, _) = open(file)?;
    let data = read_all(&buf);
    let hits = hiewlm_triage::yara::scan_path(rules, &data).map_err(|e| anyhow!("{e}"))?;
    if hits.is_empty() {
        return Ok((format!("no match in {}\n", file.display()), false));
    }
    let mut out = String::new();
    for h in &hits {
        let tags = if h.tags.is_empty() { String::new() } else { format!(" [{}]", h.tags.join(" ")) };
        out.push_str(&format!("{}{tags}  {} match(es)\n", h.rule, h.matches.len()));
        for (off, len, id) in h.matches.iter().take(64) {
            out.push_str(&format!("    {off:08X}  {len:>5}  {id}\n"));
        }
    }
    Ok((out, true))
}

/// Triage one file, or rank every file in a directory.
fn cmd_triage(
    path: &Path,
    plugins: &[String],
    json: bool,
    min_score: u8,
    max_string_bytes: u64,
    yara: Option<&Path>,
) -> Result<(String, u8)> {
    let opts = hiewlm_triage::Options { max_string_bytes, ..Default::default() };
    if path.is_dir() {
        return triage_dir(path, plugins, json, min_score, &opts, yara);
    }
    let mut report = triage_one(path, plugins, &opts)?;
    apply_yara(&mut report, path, yara)?;
    let text = if json { report.to_json() } else { hiewlm_triage::render::text(&report) };
    let score = report.score;
    Ok((format!("{text}\n"), score))
}

fn triage_one(
    path: &Path,
    plugins: &[String],
    opts: &hiewlm_triage::Options,
) -> Result<hiewlm_triage::TriageReport> {
    let (buf, _) = open(path)?;
    // Container plugins only look at files the executable parsers did not claim.
    let container = if plugins.is_empty() {
        None
    } else {
        let reg = registry(plugins)?;
        let data = read_all(&buf);
        reg.parse(&data).map(|(_, c)| c)
    };
    let name = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    Ok(hiewlm_triage::analyze(&name, &buf, container.as_ref(), opts))
}

/// Fold a YARA scan into an existing report, if rules were given.
fn apply_yara(
    report: &mut hiewlm_triage::TriageReport,
    file: &Path,
    rules: Option<&Path>,
) -> Result<()> {
    let Some(rules) = rules else { return Ok(()) };
    let (buf, _) = open(file)?;
    let data = read_all(&buf);
    let hits = hiewlm_triage::yara::scan_path(rules, &data).map_err(|e| anyhow!("{e}"))?;
    report.set_yara(hits);
    Ok(())
}

/// Rank a folder of samples worst-first — the queue you work through.
fn triage_dir(
    dir: &Path,
    plugins: &[String],
    json: bool,
    min_score: u8,
    opts: &hiewlm_triage::Options,
    yara: Option<&Path>,
) -> Result<(String, u8)> {
    let mut reports = Vec::new();
    let mut entries: Vec<PathBuf> = std::fs::read_dir(dir)
        .with_context(|| format!("cannot read {}", dir.display()))?
        .flatten()
        .filter(|e| e.file_type().map(|t| t.is_file()).unwrap_or(false))
        .map(|e| e.path())
        .collect();
    entries.sort();
    for p in &entries {
        match triage_one(p, plugins, opts) {
            Ok(mut r) => {
                if let Err(e) = apply_yara(&mut r, p, yara) {
                    eprintln!("yara on {}: {e:#}", p.display());
                }
                reports.push(r)
            }
            Err(e) => eprintln!("skipped {}: {e:#}", p.display()),
        }
    }
    reports.sort_by(|a, b| b.score.cmp(&a.score).then(a.name.cmp(&b.name)));
    let worst = reports.first().map(|r| r.score).unwrap_or(0);

    if json {
        let text = serde_json::to_string_pretty(&reports)
            .unwrap_or_else(|e| format!("{{\"error\":\"{e}\"}}"));
        return Ok((format!("{text}\n"), worst));
    }
    let mut out = format!("{:>5} {:<10} {:<40} {:<34} {}\n", "score", "verdict", "file", "sha256", "badges");
    for r in &reports {
        out.push_str(&format!(
            "{:>5} {:<10} {:<40} {:<34} {}\n",
            r.score,
            r.verdict(),
            truncate(&r.name, 40),
            &r.hashes.sha256[..32.min(r.hashes.sha256.len())],
            r.badge_line()
        ));
    }
    let flagged = reports.iter().filter(|r| r.score >= min_score).count();
    out.push_str(&format!("\n{} file(s), {flagged} at or above score {min_score}\n", reports.len()));
    Ok((out, worst))
}

fn truncate(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        s.to_string()
    } else {
        s.chars().take(n.saturating_sub(1)).collect::<String>() + "~"
    }
}

fn cmd_entropy(file: &Path) -> Result<String> {
    let (buf, model) = open(file)?;
    let data = read_all(&buf);
    let mut s = format!("file      {:.3} / 8.0\n", entropy(&data));
    if let Some(m) = model {
        for sec in m.address_space.sections() {
            let a = sec.file_off as usize;
            let b = (a + sec.size as usize).min(data.len());
            let e = if a < b { entropy(&data[a..b]) } else { 0.0 };
            s.push_str(&format!("  {:<16} {e:.3}\n", sec.name));
        }
    }
    Ok(s)
}

/// Build a packer report from a buffer + model (entry bytes + section entropy).
fn packer_report(
    buf: &EditBuffer,
    model: &Option<ExecutableModel>,
) -> hiewlm_core::packer::PackerReport {
    let Some(m) = model else {
        return hiewlm_core::packer::PackerReport::default();
    };
    let data = read_all(buf);
    let entry_off = m
        .entry
        .and_then(|va| m.address_space.offset_of(Va(va)))
        .map(|o| o.get() as usize)
        .unwrap_or(0);
    let entry: Vec<u8> = data.get(entry_off..(entry_off + 32).min(data.len())).unwrap_or(&[]).to_vec();
    let sections: Vec<hiewlm_core::packer::SectionInfo> = m
        .address_space
        .sections()
        .iter()
        .map(|s| {
            let a = s.file_off as usize;
            let b = (a + s.size as usize).min(data.len());
            hiewlm_core::packer::SectionInfo {
                name: s.name.clone(),
                entropy: if a < b { entropy(&data[a..b]) as f32 } else { 0.0 },
            }
        })
        .collect();
    hiewlm_core::packer::detect(&entry, &sections, m.imports.len())
}

fn cmd_packer(file: &Path) -> Result<String> {
    let (buf, model) = open(file)?;
    let r = packer_report(&buf, &model);
    let mut s = format!("packer    {}\n", r.summary());
    for ind in &r.indicators {
        s.push_str(&format!("  - {ind}\n"));
    }
    Ok(s)
}

fn read_le(data: &[u8], off: usize, n: usize) -> u64 {
    let mut v = 0u64;
    for i in 0..n {
        v |= (*data.get(off + i).unwrap_or(&0) as u64) << (8 * i);
    }
    v
}

fn find_in(data: &[u8], needle: &[u8]) -> i64 {
    if needle.is_empty() || data.len() < needle.len() {
        return -1;
    }
    (0..=data.len() - needle.len())
        .find(|&i| &data[i..i + needle.len()] == needle)
        .map(|i| i as i64)
        .unwrap_or(-1)
}

/// Run a Rhai script with a small file-patching API:
/// `len()`, `byte(i)`, `u16/u32/u64(i)`, `poke(i,v)`, `find_text(s)`,
/// `find_hex(s)`, `save()`, `log(msg)`.
fn cmd_script(file: &Path, script: &Path) -> Result<String> {
    use std::cell::RefCell;
    use std::rc::Rc;

    struct St {
        data: Vec<u8>,
        path: PathBuf,
        saved: bool,
        log: String,
    }
    let st = Rc::new(RefCell::new(St {
        data: std::fs::read(file)?,
        path: file.to_path_buf(),
        saved: false,
        log: String::new(),
    }));
    let src = std::fs::read_to_string(script)
        .with_context(|| format!("cannot read script {}", script.display()))?;

    let mut engine = rhai::Engine::new();
    engine.set_max_operations(50_000_000);

    macro_rules! reg {
        ($name:literal, $s:ident, $body:expr) => {{
            let $s = st.clone();
            engine.register_fn($name, $body);
        }};
    }
    reg!("len", s, move || s.borrow().data.len() as i64);
    reg!("byte", s, move |i: i64| s.borrow().data.get(i as usize).map(|&b| b as i64).unwrap_or(-1));
    reg!("u16", s, move |i: i64| read_le(&s.borrow().data, i as usize, 2) as i64);
    reg!("u32", s, move |i: i64| read_le(&s.borrow().data, i as usize, 4) as i64);
    reg!("u64", s, move |i: i64| read_le(&s.borrow().data, i as usize, 8) as i64);
    reg!("poke", s, move |i: i64, v: i64| {
        if let Some(x) = s.borrow_mut().data.get_mut(i as usize) {
            *x = v as u8;
        }
    });
    reg!("find_text", s, move |p: &str| find_in(&s.borrow().data, p.as_bytes()));
    reg!("find_hex", s, move |p: &str| {
        let bytes = parse_hex_bytes(p).unwrap_or_default();
        find_in(&s.borrow().data, &bytes)
    });
    reg!("log", s, move |m: &str| {
        let mut b = s.borrow_mut();
        b.log.push_str(m);
        b.log.push('\n');
    });
    reg!("save", s, move || {
        let mut b = s.borrow_mut();
        let _ = backup(&b.path);
        let path = b.path.clone();
        let data = b.data.clone();
        let _ = std::fs::write(path, data);
        b.saved = true;
    });

    engine.run(&src).map_err(|e| anyhow!("script error: {e}"))?;
    let b = st.borrow();
    let mut out = b.log.clone();
    out.push_str(&format!("# script done{}\n", if b.saved { " (file saved, .bak kept)" } else { "" }));
    Ok(out)
}

fn cmd_plugin(file: &Path, wasm: &Path) -> Result<String> {
    let module = std::fs::read(wasm).with_context(|| format!("cannot read {}", wasm.display()))?;
    let data = std::fs::read(file)?;
    let out = hiewlm_plugin::run(&module, data)?;
    let mut s = out.log.join("\n");
    if !s.is_empty() {
        s.push('\n');
    }
    if out.modified {
        backup(file)?;
        std::fs::write(file, &out.data)?;
        s.push_str("# plugin modified the file (.bak saved)\n");
    } else {
        s.push_str("# plugin ran (no changes)\n");
    }
    Ok(s)
}

fn replace_all(data: &[u8], needle: &[u8], repl: &[u8]) -> (Vec<u8>, usize) {
    let mut out = Vec::with_capacity(data.len());
    let mut i = 0;
    let mut count = 0;
    while i < data.len() {
        if i + needle.len() <= data.len() && &data[i..i + needle.len()] == needle {
            out.extend_from_slice(repl);
            i += needle.len();
            count += 1;
        } else {
            out.push(data[i]);
            i += 1;
        }
    }
    (out, count)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn number_and_address_parsing() {
        assert_eq!(parse_num("10").unwrap(), 0x10);
        assert_eq!(parse_num("0x20").unwrap(), 0x20);
        assert_eq!(parse_num("16t").unwrap(), 16);
        assert_eq!(parse_addr("40", &None).unwrap(), 0x40);
        assert!(parse_addr(".401000", &None).is_err()); // no model → unmapped
    }

    #[test]
    fn hex_bytes_and_replace() {
        assert_eq!(parse_hex_bytes("90 c3").unwrap(), vec![0x90, 0xc3]);
        assert!(parse_hex_bytes("9").is_err());
        let (out, n) = replace_all(b"aXbXc", b"X", b"YY");
        assert_eq!(n, 2);
        assert_eq!(out, b"aYYbYYc");
    }

    #[test]
    fn hash_and_strings_on_temp() {
        let p = std::env::temp_dir().join("hiewlmc_test.bin");
        std::fs::write(&p, b"\x00Hello, world\x00").unwrap();
        let h = cmd_hash(&p).unwrap();
        assert!(h.contains("SHA-256"));
        let s = cmd_strings(&p, 4, true, false).unwrap();
        assert!(s.contains("Hello, world"));
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn patch_roundtrip() {
        let p = std::env::temp_dir().join("hiewlmc_patch.bin");
        std::fs::write(&p, b"AAAA").unwrap();
        cmd_patch(&p, "1", "42", false).unwrap();
        assert_eq!(std::fs::read(&p).unwrap(), b"ABAA");
        std::fs::remove_file(&p).ok();
    }
}
