#!/bin/sh
# Usage: sh scripts/gen-wiki.sh <repo-root> <out-dir>
# The GitHub Action wiki-sync.yml runs this on every docs change; docs/ is the
# single source, the wiki is a build artifact. Edit docs, not the wiki.
# Sinh trang wiki từ docs/ - docs/ là nguồn gốc duy nhất, wiki là bản dựng.
# Ảnh trong docs dùng đường dẫn tương đối ../assets/...; wiki cần raw URL tuyệt đối.
set -e
ROOT="$1"; OUT="$2"
RAW="https://raw.githubusercontent.com/Vibe-Coding-Base/HiewLM/main/assets/screenshots/"
mkdir -p "$OUT"

# Usage: nội dung docs/USAGE.md; đổi link nội bộ + đường dẫn ảnh.
sed -e 's#](DEVELOPMENT.md)#](Developer guide)#g' \
    -e 's#\[USAGE\.md\]#[Usage]#g' \
    -e "s#\.\./assets/screenshots/#$RAW#g" \
    "$ROOT/docs/USAGE.md" > "$OUT/Usage.md"

# Development
sed -e 's#\[USAGE\.md\](USAGE.md)#[Usage](Usage)#g' \
    -e 's#](USAGE.md)#](Usage)#g' \
    -e "s#\.\./assets/screenshots/#$RAW#g" \
    "$ROOT/docs/DEVELOPMENT.md" > "$OUT/Development.md"

# Home: landing rút từ README (giữ What/Why), kèm ảnh hero.
cat > "$OUT/Home.md" <<MD
# hiewLM

**HIEW's essentials, on Linux and macOS.** A keyboard-driven binary viewer and
malware triage tool, in the spirit of HIEW - cross-platform, a single binary,
and safe to point at malware: the target file is data, never code.

hiewLM answers the question a malware analyst starts with - *is this file worth
my next hour, and why?* - and carries HIEW's way of working to the platforms
HIEW does not run on.

![Triage screen](${RAW}triage.png)

## Pages

- **[Usage](Usage)** - every key, every command, the workflows they add up to.
- **[Developer guide](Development)** - architecture, how to add a format, a rule
  or a view, and the decisions behind the code.

## What it does

- **Triage in one keystroke** - hashes, packer/builder identification, structural
  anomalies, capabilities from imports, indicators, an entropy map: one screen.
- **Documents and images** - OLE2/OOXML/RTF/PDF/ZIP structure and findings, plus
  JPEG/PNG/TIFF metadata (EXIF/XMP, GPS) with identity fields flagged.
- **Plugins menu and a metadata scrub** - \`P\` gathers the tools for the open
  file; for a document or image it writes a copy with identity metadata removed.
- **Safe by construction** - a \`no_exec\` CI test fails the build if any path can
  load or run target content; \`unsafe\` is denied workspace-wide.
- **Detection rules are data** - APIs, packers, indicators and document
  signatures live in text files you can extend without a compiler.

![Folder triage queue](${RAW}folder-triage.png)

The source, releases and issue tracker live in the
[repository](https://github.com/Vibe-Coding-Base/HiewLM).
MD

cat > "$OUT/_Sidebar.md" <<'MD'
### hiewLM

- [Home](Home)
- [Usage](Usage)
- [Developer guide](Development)
- [Repository](https://github.com/Vibe-Coding-Base/HiewLM)
- [Releases](https://github.com/Vibe-Coding-Base/HiewLM/releases)
MD

cat > "$OUT/_Footer.md" <<'MD'
Generated from [docs/](https://github.com/Vibe-Coding-Base/HiewLM/tree/main/docs) - edit the docs, not the wiki.
MD
