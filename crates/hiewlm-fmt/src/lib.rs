//! Executable-format detection. Reads the buffer and parses headers only — it
//! never executes or maps the target (design §22.1). Returns a unified
//! [`ExecutableModel`] with arch/bits, entry point, and a file-offset ↔ VA map.

pub mod elf_extra;
pub mod macho_extra;
pub mod pe_extra;

pub use elf_extra::{parse as elf_details, ElfDetails};
pub use macho_extra::{parse as macho_details, MachoDetails};
pub use pe_extra::{parse as pe_details, PeDetails};

use hiewlm_core::{
    AddressSpace, Arch, EditBuffer, ExecutableModel, FileOffset, Format, Resource, SectionMap, Sym,
};

/// Files larger than this are treated as raw (parsing needs the whole slice, and
/// ELF section headers usually sit at the end).
const MAX_PARSE: u64 = 256 * 1024 * 1024;

/// Detect and parse the executable format of `buf`, or `None` if unrecognized or
/// too large.
pub fn detect(buf: &EditBuffer) -> Option<ExecutableModel> {
    if buf.is_empty() || buf.len() > MAX_PARSE {
        return None;
    }
    let mut bytes = vec![0u8; buf.len() as usize];
    buf.read_at(FileOffset(0), &mut bytes);
    parse_bytes(&bytes)
}

fn parse_bytes(bytes: &[u8]) -> Option<ExecutableModel> {
    use goblin::Object;
    if let Ok(obj) = Object::parse(bytes) {
        match obj {
            Object::Elf(elf) => return Some(from_elf(&elf)),
            Object::PE(pe) => return Some(from_pe(&pe, bytes)),
            Object::Mach(goblin::mach::Mach::Binary(macho)) => return Some(from_macho(&macho, 0)),
            Object::Mach(goblin::mach::Mach::Fat(multi)) => {
                // Universal binary: parse the first Mach-O slice; its offsets are
                // relative to the slice, so add the slice's offset in the file.
                if let Ok(arches) = multi.arches() {
                    for (i, fa) in arches.iter().enumerate() {
                        if let Ok(goblin::mach::SingleArch::MachO(macho)) = multi.get(i) {
                            return Some(from_macho(&macho, fa.offset as u64));
                        }
                    }
                }
            }
            Object::Archive(ar) => {
                let members: Vec<Sym> = ar
                    .members()
                    .iter()
                    .map(|name| {
                        let (off, size) = ar
                            .get(name)
                            .map(|m| (m.header_offset, m.size()))
                            .unwrap_or((0, 0));
                        // va carries the member header offset for F12 to jump.
                        Sym {
                            name: format!("{name}  ({size} bytes)"),
                            va: off,
                        }
                    })
                    .collect();
                return Some(ExecutableModel {
                    format: Format::Archive,
                    arch: Arch::Unknown,
                    bits: 0,
                    address_space: AddressSpace::flat(),
                    entry: None,
                    imports: Vec::new(),
                    header_fields: vec![("Members".into(), members.len().to_string())],
                    exports: members,
                    resources: Vec::new(),
                });
            }
            Object::COFF(coff) => return Some(from_coff(&coff)),
            _ => {}
        }
    }
    detect_legacy(bytes)
}

fn machine_arch(machine: u16) -> Arch {
    match machine {
        0x014c => Arch::X86,
        0x8664 => Arch::X86_64,
        0x01c0 | 0x01c4 => Arch::Arm,
        0xaa64 => Arch::Arm64,
        _ => Arch::Unknown,
    }
}

fn from_coff(coff: &goblin::pe::Coff) -> ExecutableModel {
    let arch = machine_arch(coff.header.machine);
    let bits = if arch == Arch::X86_64 || arch == Arch::Arm64 {
        64
    } else {
        32
    };
    let mut sections = Vec::new();
    for s in &coff.sections {
        sections.push(SectionMap {
            file_off: s.pointer_to_raw_data as u64,
            va: s.virtual_address as u64,
            size: s.size_of_raw_data as u64,
            name: s.name().unwrap_or("").to_string(),
        });
    }
    let header_fields = vec![
        (
            "Machine".into(),
            format!("{:#06x} ({})", coff.header.machine, arch.label()),
        ),
        (
            "Sections".into(),
            coff.header.number_of_sections.to_string(),
        ),
        (
            "TimeDateStamp".into(),
            fmt_timestamp(coff.header.time_date_stamp),
        ),
        (
            "Symbols".into(),
            coff.header.number_of_symbol_table.to_string(),
        ),
    ];
    ExecutableModel {
        format: Format::Coff,
        arch,
        bits,
        address_space: AddressSpace::new(0, sections),
        entry: None,
        imports: Vec::new(),
        exports: Vec::new(),
        header_fields,
        resources: Vec::new(),
    }
}

/// DOS/OS-2/EFI headers goblin doesn't cover: identified by magic. Sections aren't
/// parsed yet — this reports the format and key header fields.
fn detect_legacy(bytes: &[u8]) -> Option<ExecutableModel> {
    let minimal =
        |format: Format, arch: Arch, bits: u8, fields: Vec<(String, String)>| ExecutableModel {
            format,
            arch,
            bits,
            address_space: AddressSpace::flat(),
            entry: None,
            imports: Vec::new(),
            exports: Vec::new(),
            header_fields: fields,
            resources: Vec::new(),
        };

    // TE (Terse Executable, EFI): "VZ" magic, Machine at offset 2.
    if bytes.len() >= 4 && &bytes[0..2] == b"VZ" {
        let machine = u16::from_le_bytes([bytes[2], bytes[3]]);
        let arch = machine_arch(machine);
        return Some(minimal(
            Format::Te,
            arch,
            if arch == Arch::X86_64 || arch == Arch::Arm64 {
                64
            } else {
                32
            },
            vec![
                ("Signature".into(), "VZ (TE)".into()),
                (
                    "Machine".into(),
                    format!("{machine:#06x} ({})", arch.label()),
                ),
            ],
        ));
    }

    // NLM (NetWare Loadable Module): a fixed 24-byte signature, then a header
    // of 32-bit little-endian offsets. NetWare was x86-only.
    const NLM_SIG: &[u8] = b"NetWare Loadable Module\x1a";
    if bytes.len() >= 130 && bytes.starts_with(NLM_SIG) {
        let u32_at = |o: usize| -> u32 {
            bytes
                .get(o..o + 4)
                .map_or(0, |b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
        };
        // moduleName is a Pascal string: one length byte, then the characters.
        let name_len = bytes.get(28).copied().unwrap_or(0).min(13) as usize;
        let name = bytes
            .get(29..29 + name_len)
            .map(|b| String::from_utf8_lossy(b).into_owned())
            .unwrap_or_default();

        let code_off = u32_at(42) as u64;
        let code_size = u32_at(46) as u64;
        let data_off = u32_at(50) as u64;
        let data_size = u32_at(54) as u64;
        let code_start = u32_at(110) as u64;

        let module_type = match u32_at(122) {
            0 => "0 (generic .NLM)",
            1 => "1 (LAN driver)",
            2 => "2 (disk driver)",
            3 => "3 (namespace)",
            4 => "4 (utility)",
            5 => "5 (Mac namespace)",
            6 => "6 (NLM utility)",
            7 => "7 (OS)",
            8 => "8 (paged high OS)",
            n => {
                return Some(minimal(
                    Format::Nlm,
                    Arch::X86,
                    32,
                    vec![
                        ("Signature".into(), "NetWare Loadable Module".into()),
                        ("Module".into(), name),
                        ("Module type".into(), n.to_string()),
                    ],
                ))
            }
        };

        // Map the code image so offsets and disassembly line up.
        let mut sections = Vec::new();
        if code_size > 0 {
            sections.push(SectionMap {
                file_off: code_off,
                va: code_off,
                size: code_size,
                name: "code".into(),
            });
        }
        if data_size > 0 {
            sections.push(SectionMap {
                file_off: data_off,
                va: data_off,
                size: data_size,
                name: "data".into(),
            });
        }

        return Some(ExecutableModel {
            format: Format::Nlm,
            arch: Arch::X86,
            bits: 32,
            address_space: if sections.is_empty() {
                AddressSpace::flat()
            } else {
                AddressSpace::new(0, sections)
            },
            entry: (code_size > 0).then_some(code_off + code_start),
            imports: Vec::new(),
            exports: Vec::new(),
            header_fields: vec![
                ("Signature".into(), "NetWare Loadable Module".into()),
                ("Module".into(), name),
                ("Version".into(), u32_at(24).to_string()),
                ("Module type".into(), module_type.into()),
                (
                    "Code image".into(),
                    format!("{code_off:#x} ({code_size} bytes)"),
                ),
                (
                    "Data image".into(),
                    format!("{data_off:#x} ({data_size} bytes)"),
                ),
                ("BSS size".into(), u32_at(58).to_string()),
                ("Code start".into(), format!("{code_start:#x}")),
                ("Exit proc".into(), format!("{:#x}", u32_at(114))),
                ("Check-unload proc".into(), format!("{:#x}", u32_at(118))),
                ("Publics".into(), u32_at(98).to_string()),
                ("External refs".into(), u32_at(90).to_string()),
                ("Relocations".into(), u32_at(82).to_string()),
                ("Dependencies".into(), u32_at(74).to_string()),
                ("Flags".into(), format!("{:#010x}", u32_at(126))),
            ],
            resources: Vec::new(),
        });
    }

    // MZ stub + a new-executable header (NE/LE/LX; PE is handled by goblin).
    if bytes.len() >= 0x40 && &bytes[0..2] == b"MZ" {
        let e_lfanew = u32::from_le_bytes(bytes[0x3c..0x40].try_into().ok()?) as usize;
        if e_lfanew + 2 <= bytes.len() {
            let sig = &bytes[e_lfanew..e_lfanew + 2];
            let (format, bits) = match sig {
                b"NE" => (Format::Ne, 16),
                b"LE" => (Format::Le, 32),
                b"LX" => (Format::Lx, 32),
                _ => return None,
            };
            return Some(minimal(
                format,
                Arch::Unknown,
                bits,
                vec![
                    (
                        "Signature".into(),
                        String::from_utf8_lossy(sig).into_owned(),
                    ),
                    ("New header @".into(), format!("{e_lfanew:#x}")),
                ],
            ));
        }
    }
    None
}

fn from_elf(elf: &goblin::elf::Elf) -> ExecutableModel {
    use goblin::elf::header;
    use goblin::elf::section_header::SHT_NOBITS;

    let bits = if elf.is_64 { 64 } else { 32 };
    let arch = match elf.header.e_machine {
        header::EM_386 => Arch::X86,
        header::EM_X86_64 => Arch::X86_64,
        header::EM_ARM => Arch::Arm,
        header::EM_AARCH64 => Arch::Arm64,
        header::EM_MIPS => Arch::Mips,
        header::EM_RISCV => Arch::Riscv,
        header::EM_PPC | header::EM_PPC64 => Arch::Ppc,
        header::EM_SPARC | header::EM_SPARCV9 => Arch::Sparc,
        _ => Arch::Unknown,
    };

    let mut sections = Vec::new();
    for sh in &elf.section_headers {
        if sh.sh_addr != 0 && sh.sh_size != 0 && sh.sh_type != SHT_NOBITS {
            let name = elf.shdr_strtab.get_at(sh.sh_name).unwrap_or("").to_string();
            sections.push(SectionMap {
                file_off: sh.sh_offset,
                va: sh.sh_addr,
                size: sh.sh_size,
                name,
            });
        }
    }
    let mut imports = Vec::new();
    let mut exports = Vec::new();
    for sym in elf.dynsyms.iter() {
        let Some(name) = elf.dynstrtab.get_at(sym.st_name) else {
            continue;
        };
        if name.is_empty() {
            continue;
        }
        if sym.st_shndx == 0 {
            imports.push(Sym {
                name: name.to_string(),
                va: 0,
            });
        } else if sym.st_bind() == goblin::elf::sym::STB_GLOBAL {
            exports.push(Sym {
                name: name.to_string(),
                va: sym.st_value,
            });
        }
    }

    let h = &elf.header;
    let header_fields = vec![
        (
            "Class".into(),
            if elf.is_64 {
                "ELF64".into()
            } else {
                "ELF32".into()
            },
        ),
        (
            "Endian".into(),
            if elf.little_endian {
                "little".into()
            } else {
                "big".into()
            },
        ),
        ("Type".into(), format!("{:#06x}", h.e_type)),
        (
            "Machine".into(),
            format!("{:#06x} ({})", h.e_machine, arch.label()),
        ),
        ("Entry".into(), format!("{:#018x}", h.e_entry)),
        (
            "PH off/num".into(),
            format!("{:#x} / {}", h.e_phoff, h.e_phnum),
        ),
        (
            "SH off/num".into(),
            format!("{:#x} / {}", h.e_shoff, h.e_shnum),
        ),
        ("Flags".into(), format!("{:#010x}", h.e_flags)),
    ];

    let image_base = sections.iter().map(|s| s.va).min().unwrap_or(0);
    ExecutableModel {
        format: Format::Elf,
        arch,
        bits,
        address_space: AddressSpace::new(image_base, sections),
        entry: Some(elf.entry),
        imports,
        exports,
        header_fields,
        resources: Vec::new(),
    }
}

/// Parse the .NET (CLR) metadata: COR20 header + metadata root/streams. Returns
/// header fields to append; empty when the PE is not a .NET assembly.
fn parse_dotnet(pe: &goblin::pe::PE, bytes: &[u8]) -> Vec<(String, String)> {
    let Some(opt) = pe.header.optional_header.as_ref() else {
        return Vec::new();
    };
    let dd = opt.data_directories.get_clr_runtime_header();
    let Some(cor) = dd.filter(|d| d.virtual_address != 0) else {
        return Vec::new();
    };
    let Some(cor_off) = rva_to_off(&pe.sections, cor.virtual_address) else {
        return Vec::new();
    };
    let cor = cor_off as usize;
    if cor + 24 > bytes.len() {
        return Vec::new();
    }
    let mut fields = vec![(".NET".into(), "yes (managed)".into())];
    fields.push((
        "CLR runtime".into(),
        format!("{}.{}", rd_u16(bytes, cor + 4), rd_u16(bytes, cor + 6)),
    ));
    let md_rva = rd_u32(bytes, cor + 8);
    fields.push((
        "CLR flags".into(),
        format!("{:#010x}", rd_u32(bytes, cor + 16)),
    ));
    fields.push((
        "EntryPoint token".into(),
        format!("{:#010x}", rd_u32(bytes, cor + 20)),
    ));

    // Metadata root (BSJB).
    if let Some(md_off) = rva_to_off(&pe.sections, md_rva) {
        let md = md_off as usize;
        if md + 20 <= bytes.len() && rd_u32(bytes, md) == 0x424A_5342 {
            let ver_len = rd_u32(bytes, md + 12) as usize;
            let vend = (md + 16 + ver_len).min(bytes.len());
            let ver: String = bytes[md + 16..vend]
                .iter()
                .take_while(|&&b| b != 0)
                .map(|&b| b as char)
                .collect();
            fields.push(("Metadata version".into(), ver));
            // After the version: Flags(u16), NumberOfStreams(u16), then headers.
            let flags_off = align4(md + 16 + ver_len);
            let n_streams = rd_u16(bytes, flags_off + 2).min(16);
            let mut o = flags_off + 4;
            let mut names = Vec::new();
            for _ in 0..n_streams {
                if o + 8 > bytes.len() {
                    break;
                }
                let (name, no) = read_ascii(bytes, o + 8);
                names.push(name);
                o = align4(no);
            }
            if !names.is_empty() {
                fields.push(("CLR streams".into(), names.join(" ")));
            }
        }
    }
    fields
}

/// Read a NUL-terminated ASCII string; returns (string, offset past the NUL).
fn read_ascii(b: &[u8], off: usize) -> (String, usize) {
    let mut s = String::new();
    let mut o = off;
    for _ in 0..256 {
        let c = *b.get(o).unwrap_or(&0);
        o += 1;
        if c == 0 {
            break;
        }
        s.push(c as char);
    }
    (s, o)
}

fn from_pe(pe: &goblin::pe::PE, bytes: &[u8]) -> ExecutableModel {
    let bits = if pe.is_64 { 64 } else { 32 };
    let arch = machine_arch(pe.header.coff_header.machine);
    let image_base = pe.image_base as u64;

    let mut sections = Vec::new();
    for s in &pe.sections {
        sections.push(SectionMap {
            file_off: s.pointer_to_raw_data as u64,
            va: image_base + s.virtual_address as u64,
            size: s.virtual_size as u64,
            name: s.name().unwrap_or("").to_string(),
        });
    }
    let imports = pe
        .imports
        .iter()
        .map(|i| Sym {
            name: format!("{}!{}", i.dll, i.name),
            va: image_base + i.rva as u64,
        })
        .collect();
    let exports = pe
        .exports
        .iter()
        .filter_map(|e| {
            e.name.map(|n| Sym {
                name: n.to_string(),
                va: image_base + e.rva as u64,
            })
        })
        .collect();

    let coff = &pe.header.coff_header;
    let mut header_fields = vec![
        (
            "Machine".into(),
            format!("{:#06x} ({})", coff.machine, arch.label()),
        ),
        ("Sections".into(), coff.number_of_sections.to_string()),
        ("TimeDateStamp".into(), fmt_timestamp(coff.time_date_stamp)),
        (
            "Characteristics".into(),
            format!(
                "{:#06x} [{}]",
                coff.characteristics,
                pe_characteristics(coff.characteristics)
            ),
        ),
        ("ImageBase".into(), format!("{image_base:#018x}")),
        ("Entry (RVA)".into(), format!("{:#x}", pe.entry)),
    ];
    if let Some(o) = pe.header.optional_header.as_ref() {
        let s = &o.standard_fields;
        let w = &o.windows_fields;
        let magic = if s.magic == 0x20b { "PE32+" } else { "PE32" };
        header_fields.extend([
            ("Magic".into(), format!("{:#06x} ({magic})", s.magic)),
            (
                "LinkerVersion".into(),
                format!("{}.{}", s.major_linker_version, s.minor_linker_version),
            ),
            ("SizeOfCode".into(), format!("{:#x}", s.size_of_code)),
            (
                "SectionAlignment".into(),
                format!("{:#x}", w.section_alignment),
            ),
            ("FileAlignment".into(), format!("{:#x}", w.file_alignment)),
            (
                "OSVersion".into(),
                format!(
                    "{}.{}",
                    w.major_operating_system_version, w.minor_operating_system_version
                ),
            ),
            (
                "SubsystemVersion".into(),
                format!(
                    "{}.{}",
                    w.major_subsystem_version, w.minor_subsystem_version
                ),
            ),
            (
                "Subsystem".into(),
                format!("{} ({})", w.subsystem, subsystem_name(w.subsystem)),
            ),
            (
                "DllCharacteristics".into(),
                format!(
                    "{:#06x} [{}]",
                    w.dll_characteristics,
                    dll_characteristics(w.dll_characteristics)
                ),
            ),
            ("SizeOfImage".into(), format!("{:#x}", w.size_of_image)),
            ("SizeOfHeaders".into(), format!("{:#x}", w.size_of_headers)),
            ("CheckSum".into(), format!("{:#010x}", w.check_sum)),
            (
                "DataDirectories".into(),
                w.number_of_rva_and_sizes.to_string(),
            ),
        ]);
    }

    let resources = parse_pe_resources(pe, bytes);

    // Rich header (comp-id tool fingerprint).
    let e_lfanew = rd_u32(bytes, 0x3c) as usize;
    if let Some((n, key)) = parse_rich(bytes, e_lfanew) {
        header_fields.push((
            "RichHeader".into(),
            format!("{n} comp entries (xor key {key:#010x})"),
        ));
    }
    // VERSION resource strings (ProductName, FileVersion, CompanyName, …).
    if let Some(v) = resources.iter().find(|r| r.type_name == "VERSION") {
        for (k, val) in parse_version_info(bytes, v.file_off, v.size) {
            header_fields.push((format!("Ver.{k}"), val));
        }
    }
    // .NET managed metadata, if present.
    header_fields.extend(parse_dotnet(pe, bytes));

    ExecutableModel {
        format: Format::Pe,
        arch,
        bits,
        address_space: AddressSpace::new(image_base, sections),
        entry: Some(image_base + pe.entry as u64),
        imports,
        exports,
        header_fields,
        resources,
    }
}

/// Format a PE TimeDateStamp (unix seconds) as hex + a UTC date, or "(not set)"
/// when zero (common for .NET / reproducible builds).
fn fmt_timestamp(ts: u32) -> String {
    if ts == 0 {
        return "0x00000000 (not set)".into();
    }
    format!("{ts:#010x} ({})", hiewlm_core::format_unix(ts as i64))
}

fn subsystem_name(s: u16) -> &'static str {
    match s {
        1 => "native",
        2 => "GUI",
        3 => "console",
        5 => "OS/2",
        7 => "POSIX",
        9 => "WinCE GUI",
        10 => "EFI app",
        11 => "EFI boot driver",
        12 => "EFI runtime driver",
        14 => "Xbox",
        _ => "?",
    }
}

fn flags_join(value: u16, table: &[(u16, &str)]) -> String {
    let names: Vec<&str> = table
        .iter()
        .filter(|(bit, _)| value & bit != 0)
        .map(|(_, n)| *n)
        .collect();
    if names.is_empty() {
        "-".into()
    } else {
        names.join(" ")
    }
}

fn pe_characteristics(c: u16) -> String {
    flags_join(
        c,
        &[
            (0x0001, "RELOCS_STRIPPED"),
            (0x0002, "EXECUTABLE"),
            (0x0020, "LARGE_ADDRESS_AWARE"),
            (0x0100, "32BIT"),
            (0x0200, "DEBUG_STRIPPED"),
            (0x2000, "DLL"),
            (0x1000, "SYSTEM"),
        ],
    )
}

fn dll_characteristics(c: u16) -> String {
    flags_join(
        c,
        &[
            (0x0020, "HIGH_ENTROPY_VA"),
            (0x0040, "DYNAMIC_BASE(ASLR)"),
            (0x0080, "FORCE_INTEGRITY"),
            (0x0100, "NX_COMPAT(DEP)"),
            (0x0200, "NO_ISOLATION"),
            (0x0400, "NO_SEH"),
            (0x0800, "NO_BIND"),
            (0x1000, "APPCONTAINER"),
            (0x2000, "WDM_DRIVER"),
            (0x4000, "GUARD_CF"),
            (0x8000, "TERMINAL_SERVER_AWARE"),
        ],
    )
}

fn rva_to_off(sections: &[goblin::pe::section_table::SectionTable], rva: u32) -> Option<u64> {
    for s in sections {
        let start = s.virtual_address;
        let end = start + s.virtual_size.max(s.size_of_raw_data);
        if rva >= start && rva < end {
            return Some((s.pointer_to_raw_data + (rva - start)) as u64);
        }
    }
    None
}

fn rt_name(id: u32) -> String {
    let n = match id {
        1 => "CURSOR",
        2 => "BITMAP",
        3 => "ICON",
        4 => "MENU",
        5 => "DIALOG",
        6 => "STRING",
        7 => "FONTDIR",
        8 => "FONT",
        9 => "ACCELERATOR",
        10 => "RCDATA",
        11 => "MESSAGETABLE",
        12 => "GROUP_CURSOR",
        14 => "GROUP_ICON",
        16 => "VERSION",
        24 => "MANIFEST",
        _ => return format!("type {id}"),
    };
    n.to_string()
}

fn rd_u16(b: &[u8], off: usize) -> u16 {
    b.get(off..off + 2)
        .map(|s| u16::from_le_bytes([s[0], s[1]]))
        .unwrap_or(0)
}
fn rd_u32(b: &[u8], off: usize) -> u32 {
    b.get(off..off + 4)
        .map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
        .unwrap_or(0)
}

/// Read the entries `(id_or_name_field, offset_field)` of a resource directory at
/// absolute file offset `dir_off`.
fn res_dir_entries(bytes: &[u8], dir_off: usize) -> Vec<(u32, u32)> {
    let named = rd_u16(bytes, dir_off + 12) as usize;
    let ids = rd_u16(bytes, dir_off + 14) as usize;
    let count = (named + ids).min(4096);
    let mut out = Vec::with_capacity(count);
    for i in 0..count {
        let e = dir_off + 16 + i * 8;
        if e + 8 > bytes.len() {
            break;
        }
        out.push((rd_u32(bytes, e), rd_u32(bytes, e + 4)));
    }
    out
}

/// A resource name/id: high bit set → UTF-16 string at `base + off`, else numeric.
fn res_label(bytes: &[u8], base: usize, field: u32) -> String {
    if field & 0x8000_0000 != 0 {
        let off = base + (field & 0x7fff_ffff) as usize;
        let len = rd_u16(bytes, off) as usize;
        let mut s = String::new();
        for i in 0..len.min(128) {
            let c = rd_u16(bytes, off + 2 + i * 2);
            s.push(char::from_u32(c as u32).unwrap_or('.'));
        }
        s
    } else {
        (field & 0x7fff_ffff).to_string()
    }
}

fn align4(o: usize) -> usize {
    (o + 3) & !3
}

/// Read a NUL-terminated UTF-16LE string; returns (string, offset past the NUL).
fn read_wstr(b: &[u8], off: usize) -> (String, usize) {
    let mut s = String::new();
    let mut o = off;
    for _ in 0..512 {
        let c = rd_u16(b, o);
        o += 2;
        if c == 0 {
            break;
        }
        s.push(char::from_u32(c as u32).unwrap_or('.'));
    }
    (s, o)
}

/// Decode a VS_VERSIONINFO resource into its StringFileInfo key/value pairs
/// (ProductName, FileVersion, CompanyName, …).
fn parse_version_info(b: &[u8], base: u64, size: u64) -> Vec<(String, String)> {
    let base = base as usize;
    let end = (base + size as usize).min(b.len());
    if base + 6 > end {
        return Vec::new();
    }
    let root_len = rd_u16(b, base) as usize;
    let value_len = rd_u16(b, base + 2) as usize; // wValueLength (VS_FIXEDFILEINFO size)
    let (_key, ko) = read_wstr(b, base + 6); // "VS_VERSION_INFO"
    let mut o = align4(ko) + value_len; // skip VS_FIXEDFILEINFO
    o = align4(o);
    let root_end = (base + root_len).min(end);

    let mut out = Vec::new();
    let mut guard = 0;
    while o + 6 <= root_end && guard < 64 {
        guard += 1;
        let child_len = rd_u16(b, o) as usize;
        if child_len == 0 {
            break;
        }
        let child_start = o;
        let (child_key, ko) = read_wstr(b, o + 6);
        if child_key == "StringFileInfo" {
            let mut po = align4(ko);
            let sfi_end = (child_start + child_len).min(root_end);
            let mut g2 = 0;
            while po + 6 <= sfi_end && g2 < 64 {
                g2 += 1;
                let st_len = rd_u16(b, po) as usize;
                if st_len == 0 {
                    break;
                }
                let st_start = po;
                let (_lang, lo) = read_wstr(b, po + 6);
                let mut so = align4(lo);
                let st_end = (st_start + st_len).min(sfi_end);
                let mut g3 = 0;
                while so + 6 <= st_end && g3 < 256 {
                    g3 += 1;
                    let s_len = rd_u16(b, so) as usize;
                    if s_len == 0 {
                        break;
                    }
                    let s_start = so;
                    let (name, no) = read_wstr(b, so + 6);
                    let (value, _) = read_wstr(b, align4(no));
                    if !name.is_empty() && !value.is_empty() {
                        out.push((name, value));
                    }
                    so = align4(s_start + s_len);
                }
                po = align4(st_start + st_len);
            }
        }
        o = align4(child_start + child_len);
    }
    out
}

/// Decode the MS "Rich" header (between the DOS stub and PE header): returns the
/// number of comp-id entries and the XOR key.
fn parse_rich(b: &[u8], e_lfanew: usize) -> Option<(usize, u32)> {
    let limit = e_lfanew.min(b.len());
    let mut rich_pos = None;
    let mut i = 0x40;
    while i + 4 <= limit {
        if &b[i..i + 4] == b"Rich" {
            rich_pos = Some(i);
            break;
        }
        i += 1;
    }
    let rp = rich_pos?;
    let key = rd_u32(b, rp + 4);
    let mut dwords = Vec::new();
    let mut k = rp;
    while k >= 4 && dwords.len() < 4096 {
        k -= 4;
        let dw = rd_u32(b, k) ^ key;
        if dw == 0x536E_6144 {
            // "DanS"
            dwords.reverse();
            // 3 padding dwords, then (compid, count) pairs.
            let payload = dwords.iter().skip_while(|&&d| d == 0).count();
            return Some((payload / 2, key));
        }
        dwords.push(dw);
    }
    None
}

/// Walk the 3-level PE resource tree (type → name → language) into flat leaves.
fn parse_pe_resources(pe: &goblin::pe::PE, bytes: &[u8]) -> Vec<Resource> {
    let Some(opt) = pe.header.optional_header.as_ref() else {
        return Vec::new();
    };
    let Some(rdir) = opt.data_directories.get_resource_table() else {
        return Vec::new();
    };
    if rdir.virtual_address == 0 {
        return Vec::new();
    }
    let Some(base64) = rva_to_off(&pe.sections, rdir.virtual_address) else {
        return Vec::new();
    };
    let base = base64 as usize;
    if base + 16 > bytes.len() {
        return Vec::new();
    }

    let mut out = Vec::new();
    for (type_field, type_off) in res_dir_entries(bytes, base) {
        if type_field & 0x8000_0000 == 0 && type_off & 0x8000_0000 == 0 {
            continue; // expected a subdirectory
        }
        let type_name = if type_field & 0x8000_0000 != 0 {
            res_label(bytes, base, type_field)
        } else {
            rt_name(type_field)
        };
        let name_dir = base + (type_off & 0x7fff_ffff) as usize;
        for (name_field, name_off) in res_dir_entries(bytes, name_dir) {
            let name = res_label(bytes, base, name_field);
            let lang_dir = base + (name_off & 0x7fff_ffff) as usize;
            for (lang_field, data_off) in res_dir_entries(bytes, lang_dir) {
                let data_entry = base + (data_off & 0x7fff_ffff) as usize;
                let data_rva = rd_u32(bytes, data_entry);
                let size = rd_u32(bytes, data_entry + 4) as u64;
                if let Some(file_off) = rva_to_off(&pe.sections, data_rva) {
                    out.push(Resource {
                        type_name: type_name.clone(),
                        name: name.clone(),
                        lang: lang_field & 0x7fff_ffff,
                        file_off,
                        size,
                    });
                }
                if out.len() >= 8192 {
                    return out;
                }
            }
        }
    }
    out
}

fn macho_ver32(v: u32) -> String {
    format!("{}.{}.{}", v >> 16, (v >> 8) & 0xff, v & 0xff)
}

fn macho_src_ver(v: u64) -> String {
    format!(
        "{}.{}.{}.{}.{}",
        v >> 40,
        (v >> 30) & 0x3ff,
        (v >> 20) & 0x3ff,
        (v >> 10) & 0x3ff,
        v & 0x3ff
    )
}

fn macho_platform(p: u32) -> String {
    let n = match p {
        1 => "macOS",
        2 => "iOS",
        3 => "tvOS",
        4 => "watchOS",
        5 => "bridgeOS",
        6 => "Mac Catalyst",
        7 => "iOS simulator",
        _ => return format!("platform {p}"),
    };
    n.to_string()
}

fn macho_uuid(u: &[u8; 16]) -> String {
    let h: String = u.iter().map(|b| format!("{b:02X}")).collect();
    format!(
        "{}-{}-{}-{}-{}",
        &h[0..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..32]
    )
}

fn from_macho(m: &goblin::mach::MachO, base_off: u64) -> ExecutableModel {
    use goblin::mach::cputype;

    let bits = if m.is_64 { 64 } else { 32 };
    let arch = match m.header.cputype {
        cputype::CPU_TYPE_X86 => Arch::X86,
        cputype::CPU_TYPE_X86_64 => Arch::X86_64,
        cputype::CPU_TYPE_ARM => Arch::Arm,
        cputype::CPU_TYPE_ARM64 => Arch::Arm64,
        _ => Arch::Unknown,
    };

    let mut sections = Vec::new();
    for seg in &m.segments {
        if let Ok(sects) = seg.sections() {
            for (sect, _data) in sects {
                sections.push(SectionMap {
                    file_off: base_off + sect.offset as u64,
                    va: sect.addr,
                    size: sect.size,
                    name: sect.name().unwrap_or("").to_string(),
                });
            }
        }
    }
    // Prefer the symbol table for imports: undefined external symbols. This works
    // even on binaries using chained fixups, which goblin's imports() misses.
    let mut imports: Vec<Sym> = Vec::new();
    let mut exports: Vec<Sym> = Vec::new();
    for entry in m.symbols() {
        let Ok((name, nlist)) = entry else { continue };
        if name.is_empty() || nlist.is_stab() {
            continue;
        }
        if nlist.is_undefined() {
            imports.push(Sym {
                name: name.to_string(),
                va: 0,
            });
        } else if nlist.is_global() {
            exports.push(Sym {
                name: name.to_string(),
                va: nlist.n_value,
            });
        }
    }
    // Fall back to the export trie if the symbol table gave nothing.
    if exports.is_empty() {
        if let Ok(list) = m.exports() {
            exports = list
                .iter()
                .map(|e| Sym {
                    name: e.name.clone(),
                    va: e.offset,
                })
                .collect();
        }
    }

    let h = &m.header;
    let mut header_fields = vec![
        ("Magic".into(), format!("{:#010x}", h.magic)),
        (
            "CPU type".into(),
            format!("{:#x} ({})", h.cputype, arch.label()),
        ),
        ("CPU subtype".into(), format!("{:#x}", h.cpusubtype)),
        ("File type".into(), format!("{:#x}", h.filetype)),
        ("Load commands".into(), h.ncmds.to_string()),
        ("Flags".into(), format!("{:#010x}", h.flags)),
        ("Entry".into(), format!("{:#018x}", m.entry)),
    ];
    // Mach-O has no compile timestamp; expose the build/version metadata instead.
    for lc in &m.load_commands {
        use goblin::mach::load_command::CommandVariant;
        match &lc.command {
            CommandVariant::BuildVersion(b) => {
                header_fields.push(("Platform".into(), macho_platform(b.platform)));
                header_fields.push(("MinOS".into(), macho_ver32(b.minos)));
                header_fields.push(("SDK".into(), macho_ver32(b.sdk)));
            }
            CommandVariant::VersionMinMacosx(v)
            | CommandVariant::VersionMinIphoneos(v)
            | CommandVariant::VersionMinTvos(v)
            | CommandVariant::VersionMinWatchos(v) => {
                header_fields.push(("MinOS".into(), macho_ver32(v.version)));
                header_fields.push(("SDK".into(), macho_ver32(v.sdk)));
            }
            CommandVariant::SourceVersion(s) => {
                header_fields.push(("SourceVersion".into(), macho_src_ver(s.version)));
            }
            CommandVariant::Uuid(u) => {
                header_fields.push(("UUID".into(), macho_uuid(&u.uuid)));
            }
            _ => {}
        }
    }

    let image_base = sections.iter().map(|s| s.va).min().unwrap_or(0);
    ExecutableModel {
        format: Format::MachO,
        arch,
        bits,
        address_space: AddressSpace::new(image_base, sections),
        entry: Some(m.entry),
        imports,
        exports,
        header_fields,
        resources: Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hiewlm_core::{FileSource, MemSource};
    use std::sync::Arc;

    #[test]
    fn random_bytes_not_detected() {
        let buf = EditBuffer::new(Arc::new(MemSource::new(vec![0u8; 128])));
        assert!(detect(&buf).is_none());
    }

    #[test]
    fn empty_not_detected() {
        let buf = EditBuffer::new(Arc::new(MemSource::new(Vec::new())));
        assert!(detect(&buf).is_none());
    }

    #[test]
    fn resource_dir_primitives() {
        assert_eq!(rt_name(3), "ICON");
        assert_eq!(rt_name(16), "VERSION");
        // A directory with one id-entry (id=5, offset=0x1234).
        let mut b = vec![0u8; 16 + 8];
        b[14] = 1; // number_of_id_entries = 1
        b[16..20].copy_from_slice(&5u32.to_le_bytes());
        b[20..24].copy_from_slice(&0x1234u32.to_le_bytes());
        assert_eq!(res_dir_entries(&b, 0), vec![(5, 0x1234)]);
    }

    #[test]
    fn nlm_header_is_parsed() {
        let mut b = b"NetWare Loadable Module\x1a".to_vec();
        assert_eq!(b.len(), 24);
        b.extend_from_slice(&1u32.to_le_bytes()); // version
        b.push(5); // moduleName length
        b.extend_from_slice(b"HELLO");
        b.resize(42, 0);
        b.extend_from_slice(&0x200u32.to_le_bytes()); // codeImageOffset
        b.extend_from_slice(&0x100u32.to_le_bytes()); // codeImageSize
        b.extend_from_slice(&0x300u32.to_le_bytes()); // dataImageOffset
        b.extend_from_slice(&0x080u32.to_le_bytes()); // dataImageSize
        b.resize(110, 0);
        b.extend_from_slice(&0x10u32.to_le_bytes()); // codeStartOffset
        b.resize(122, 0);
        b.extend_from_slice(&1u32.to_le_bytes()); // moduleType = LAN driver
        b.extend_from_slice(&0u32.to_le_bytes()); // flags
        b.resize(0x400, 0);

        let m = detect_legacy(&b).expect("NLM detected");
        assert_eq!(m.format, Format::Nlm);
        assert_eq!(m.arch, Arch::X86);
        assert_eq!(m.bits, 32);
        assert_eq!(m.entry, Some(0x210)); // codeImageOffset + codeStartOffset
        let f = |k: &str| {
            m.header_fields
                .iter()
                .find(|(n, _)| n == k)
                .map(|(_, v)| v.clone())
        };
        assert_eq!(f("Module").as_deref(), Some("HELLO"));
        assert!(f("Module type").unwrap().contains("LAN driver"));
        // The code image is mapped so disassembly and offsets line up.
        assert!(m.address_space.sections().iter().any(|s| s.name == "code"));
    }

    #[test]
    fn nlm_signature_must_match_exactly() {
        let mut b = b"NetWare Loadable Modula\x1a".to_vec(); // typo'd magic
        b.resize(200, 0);
        assert!(detect_legacy(&b).is_none());
    }

    #[test]
    fn timestamp_decoding() {
        assert!(fmt_timestamp(0).contains("not set"));
        assert!(fmt_timestamp(1).contains("1970-01-01"));
        assert!(fmt_timestamp(1_700_000_000).contains("2023-11-14"));
    }

    #[test]
    fn pe_flag_decoders() {
        assert!(dll_characteristics(0x0140).contains("DYNAMIC_BASE"));
        assert!(dll_characteristics(0x0140).contains("NX_COMPAT"));
        assert!(pe_characteristics(0x2002).contains("DLL"));
        assert_eq!(subsystem_name(3), "console");
    }

    #[test]
    fn detects_ne_by_magic() {
        let mut v = vec![0u8; 0x42];
        v[0] = b'M';
        v[1] = b'Z';
        v[0x3c..0x40].copy_from_slice(&0x40u32.to_le_bytes());
        v[0x40] = b'N';
        v[0x41] = b'E';
        let buf = EditBuffer::new(Arc::new(MemSource::new(v)));
        let m = detect(&buf).expect("NE detected");
        assert_eq!(m.format, hiewlm_core::Format::Ne);
    }

    #[test]
    fn detects_a_real_binary_without_panicking() {
        // A thin ELF/PE/Mach-O should be recognized; universal (fat) Mach-O is not
        // handled yet, so accept either outcome — the point is it must not panic.
        for p in ["/bin/ls", "/usr/bin/true", "/bin/cat"] {
            if let Ok(src) = FileSource::open(p) {
                let buf = EditBuffer::new(Arc::new(src));
                let _ = detect(&buf);
                return;
            }
        }
    }
}
