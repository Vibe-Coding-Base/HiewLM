<h1 align="center">hiewLM</h1>

<p align="center">
  <strong>A keyboard-driven binary viewer and malware triage tool, in the spirit of HIEW.</strong><br>
  Cross-platform, single binary, and safe to point at malware: the target file is
  data, never code.
</p>

<p align="center">
  <img alt="Rust 1.75+" src="https://img.shields.io/badge/rust-1.75%2B-orange">
  <img alt="License" src="https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue">
  <img alt="Platforms" src="https://img.shields.io/badge/platforms-Windows%20%C2%B7%20macOS%20%C2%B7%20Linux-lightgrey">
</p>

<!-- Once this is on GitHub, replace OWNER/REPO and paste these back above:
  <a href="https://github.com/OWNER/REPO/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/OWNER/REPO/actions/workflows/ci.yml/badge.svg"></a>
  <a href="https://github.com/OWNER/REPO/actions/workflows/release.yml"><img alt="Build" src="https://github.com/OWNER/REPO/actions/workflows/release.yml/badge.svg"></a>
A workflow badge only renders for a repository that exists and has run that
workflow at least once; pointing one at a guessed URL shows a broken image. -->

---

## What it is

**HIEW's essentials, on Linux and macOS.** That is the whole reason this exists,
and the whole reason for the name: HIEW is a DOS/Windows program, and an analyst
who works on Linux or a Mac has to give up the tool or give up the platform.
hiewLM is HIEW's way of working — the function-key bar, the key rhythm, hex and
disassembly and structure in one keyboard-driven window — running natively on
**L**inux and **m**acOS as well as Windows.

On top of that it answers the question a malware analyst actually starts with —
*is this file worth my next hour, and why?*

## Why

Hex editors show you bytes. Triage tools give you a verdict you cannot verify.
hiewLM does both in one window: every finding carries the offset it came from,
and `Enter` takes you there.

- **Triage in one keystroke.** Hashes a feed will recognise (including ssdeep and
  imphash), packer and builder identification, structural anomalies, capabilities
  read off the import table, indicators, and an entropy map — one screen, filterable.
- **Documents get the same treatment as executables.** OLE2, OOXML, RTF, PDF and
  ZIP have a structure view with navigable offsets, decompressed VBA macro source,
  and the findings that decide whether a document is a lure.
- **Safe by construction.** A `no_exec` test in CI fails the build if any code
  path gains the ability to load or run target-file content. `unsafe` is denied
  workspace-wide. Nothing is dlopened, no linked resource is fetched, no macro runs.
- **HIEW-faithful.** The function-key bar, the key rhythm, the classic theme — and
  every action also has a plain-letter alias, because most terminals never deliver
  F1–F12.
- **Detection rules are data.** APIs, packers, indicators and document signatures
  live in text files you can extend without a compiler.

## Install

Prebuilt binaries for Linux, macOS (Intel and Apple silicon) and Windows are
attached to every release, with SHA-256 sums; builds of the latest `main` are
available as workflow artifacts. To build from source you need a recent stable
Rust:

```sh
git clone https://github.com/hiewLM/hiewLM
cd hiewLM
cargo build --release                      # hiewlm (viewer) + hiewlmc (CLI)
```

Nothing heavy is enabled by default. Add what you need:

```sh
cargo build --release --features full      # YARA + Rhai scripting + WASM plugins
FEATURES=full ./scripts/build-release.sh   # same, into dist/hiewlm-<os>-<arch>
```

| Build | `hiewlm` | `hiewlmc` |
|---|---:|---:|
| default | 9.5 MB | 8.8 MB |
| `--features full` | 24 MB | 30 MB |

## Quick start

```sh
hiewlm sample.exe            # open the viewer; press 2 for triage, 1 for help
hiewlm ~/samples/            # a folder opens as a queue, ranked worst-first
hiewlmc triage sample.exe    # the same verdict, headless
```

The keys worth knowing on day one:

| Key | |
|---|---|
| `2` | triage screen — verdict, hashes, anomalies, capabilities, indicators |
| `Enter` | cycle Hex → Code → Text → Doc |
| `s` | strings (ASCII + UTF-16), tagged; type `url` or `lolbin` to filter |
| `8` | header: sections, imports tagged by behaviour, exports, resources |
| `Alt+X` | find plaintext hidden behind a single-byte key, and read it decoded |
| `Y` | copy a hash, a block or the whole report to the system clipboard |
| `:` | command palette — every command by name |
| `1` / `V` | help / about |

The sample is **read-only until you unlock it** with `Ctrl+W` (or `--rw`).
Evidence should not change because of a stray keystroke.

## Documentation

- **[Usage guide](docs/USAGE.md)** — every key, every command, and the workflows
  they add up to.
- **[Developer guide](docs/DEVELOPMENT.md)** — architecture, how to add a format,
  a rule or a view, and the decisions behind the shape of the code.
- **[Design document](docs/DESIGN.md)** — the long-form design, including the
  security model.

## Security model

hiewLM is built to be pointed at hostile files.

- The target file is **passive data**. There is no code path that loads or
  executes its content, and `crates/hiewlm-core/tests/no_exec.rs` scans the source
  to keep it that way — `Command::new`, `dlopen`, `LoadLibrary` and friends fail
  the build.
- `unsafe_code = "deny"` workspace-wide; the single exception (memory-mapping a
  file) carries a local allow and a SAFETY note.
- Container and document parsers see `&[u8]` and return descriptions. Nothing is
  decompressed beyond a bounded prefix, no action is followed, no remote template
  or URL is ever fetched.
- Optional WASM plugins run in a fuel-bounded wasmtime sandbox with no filesystem
  or network access.

## Acknowledgements

**hiewLM exists because HIEW does.** Eugene Suslikov's
[HIEW](https://hiew.ru) has been the reference for what a binary viewer should
feel like for over thirty years: everything under the fingers, nothing in the
way, and a program that never gets between you and the bytes. A generation of
reverse engineers learned to read binaries in it, and this project is an attempt
to carry that experience to the platforms HIEW does not run on — not to replace
it, and not to compete with it. Thank you.

Where hiewLM departs from HIEW it does so on purpose and says why
([DESIGN.md](docs/DESIGN.md) §23.4). Where it can follow HIEW, it does.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Adding a packer signature or an API rule
is a one-line edit to a data file — that path is meant to be easy.

## License

Dual-licensed under [MIT](LICENSE-MIT) or [Apache 2.0](LICENSE-APACHE), at your
option.
