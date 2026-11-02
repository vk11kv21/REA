# rea — reverse-engineer anything, starting with triage

[![ci](https://github.com/vk11kv21/REA/actions/workflows/ci.yml/badge.svg)](https://github.com/vk11kv21/REA/actions/workflows/ci.yml)
[![license: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![node >= 18](https://img.shields.io/badge/node-%3E%3D18-brightgreen.svg)](package.json)

A small, dependency-free command line toolkit for the first hour of a reverse
engineering job: **work out what a file is, what it is made of, and what to look
at next.**

`rea` does the boring, deterministic part — identification, hashing, strings,
entropy, PE/ELF headers, archive layouts — and writes it up as markdown you can
hand to a reviewer or an AI agent. It does not pretend to decompile a binary for
you, and it never phones home.

```
$ rea info notepad.exe
C:\Windows\System32\notepad.exe
size     352 KB (360,448 bytes)
format   Windows PE / DOS executable [pe]
entropy  6.483 bits/byte — normal for compiled code
sha256   468ffe129c395abf6b21a09efdf261910a95fb98aa982ead73caa7b2b684577e
  next: rea pe <file>
```

## Why

Every analysis starts the same way: figure out the format, hash it, pull the
strings, look for compression, check the imports, write down what you found.
That work is repeatable, so it should be one command, offline, with no
`pip install`, no virtualenv and no 400 MB of dependencies.

## Install

Requires **Node.js 18 or newer**. There are no dependencies.

```sh
git clone https://github.com/vk11kv21/REA.git
cd REA
npm link          # puts `rea` on your PATH
```

Or run it straight from the checkout without linking:

```sh
node bin/rea.js help
```

On Windows, if `npm` is blocked by the PowerShell execution policy, use
`npm.cmd link` or call the binary directly with `node`.

## Quick start

```sh
rea init case-acme            # scaffold notes/, samples/, findings/, reports/
rea scan samples/             # what have I got? what looks interesting?
rea info samples/app.exe
rea strings samples/app.exe --grep http --limit 50
rea entropy samples/app.exe
rea pe samples/app.exe
rea report samples/ --out reports/acme.md
```

## Commands

| Command   | What it does                                                      |
| --------- | ----------------------------------------------------------------- |
| `info`    | Format by magic bytes, size, MD5/SHA-256, overall entropy         |
| `strings` | ASCII and UTF-16LE extraction with filtering, dedupe and export   |
| `entropy` | Per-block entropy map plus high-entropy runs (packed/encrypted)   |
| `pe`      | PE headers, sections, permissions, imports, exports, PDB, overlay |
| `elf`     | ELF headers, sections, PIE/NX/RELRO hardening summary              |
| `archive` | ZIP/APK/JAR contents, APK ABIs and DEX files, gzip inner format   |
| `scan`    | Directory triage: classify, hash, flag suspicious files           |
| `report`  | Markdown triage report with inventory, details and next steps     |
| `init`    | Case workspace scaffold (config, notes, findings, reports)        |

Every command supports `--json` for scripting, `--no-color`, and
`rea help <command>` for its own options.

### info

```sh
rea info samples/app.exe samples/notes.txt
rea info samples/app.exe --no-hash --json
```

Format detection covers PE, ELF, Mach-O, WebAssembly, DEX, Java class, ZIP,
gzip, 7z, bzip2, xz, zstd, RAR, tar, cab, cpio, SquashFS, CramFS, UBI, U-Boot
images, Android boot images, ISO, PDF, OLE2, SQLite, PNG/JPEG/GIF, RIFF, MP4,
Ogg and MP3 — plus plain text.

### strings

```sh
rea strings samples/app.exe                        # first 40 strings, both encodings
rea strings samples/app.exe --min 8 --limit 200
rea strings samples/app.exe --grep "https?://" --regex
rea strings samples/app.exe --unique --out strings.txt
```

UTF-16 is scanned at both byte alignments, so strings written by Windows
compilers are found even when they do not start on an even offset.

### entropy

```sh
rea entropy samples/packed.exe
```

```
size     1.2 MB (1,234,567 bytes)
overall  7.946 bits/byte
blocks   4,823 × 256 bytes
zeroed   12 blocks (0%)
high     1 run(s) ≥ 7.2 bits/byte

  0.0 ████████████████████████████████████████████████████████████████ 8.0

high-entropy runs ───────────────────────────────────
start       end         length  entropy
0x00000400  0x0012d400  1.2 MB  7.947
```

A large run above ~7.2 bits/byte is compressed or encrypted data: a packer, an
embedded archive, or an encrypted payload. Use `--block` and `--threshold` to
tune the sensitivity.

### pe

```sh
rea pe samples/app.exe --imports 40
```

Reports architecture, build timestamp, entry point, subsystem, DLL
characteristics (ASLR, DEP, CFG), section permissions and entropy, imported
libraries with function names, exports, the CodeView PDB path if it leaked, and
any overlay data appended after the last section. It ends with observations that
matter for triage — high-entropy sections, writable+executable sections, a
missing import table, a managed .NET header.

### elf

```sh
rea elf ./busybox
```

Adds a hardening summary (PIE, NX stack, RELRO) to the header and section
listing, which is usually the fastest way to tell a normal build from a
deliberately weakened one.

### archive

```sh
rea archive app.apk
rea archive app.apk --grep lib/ --all
rea archive payload.gz
```

For APKs it calls out DEX files, supported ABIs and whether a v1 signature is
present. For other ZIP containers it summarises content by extension and lists
the largest entries.

### scan

```sh
rea scan samples/ --top 25
rea scan samples/ --min-size 1024 --hidden --json
```

Walks a folder, classifies every file, hashes it and flags:

- high entropy (packed or encrypted content)
- executables and binaries whose format does not match their extension
- double extensions (`invoice.pdf.exe`)
- duplicate files (same SHA-256)
- base64-looking filenames

### report

```sh
rea report samples/ --title "Acme client" --out reports/acme.md
```

Produces a markdown report with an inventory table, per-file detail for PE/ELF/
ZIP artifacts, an observations list and a findings checklist you can fill in as
you work.

## Using the JSON output with agents

Every command returns structured JSON with `--json`, which makes `rea` a good
tool for an agent loop: the model decides what to look at next, and the tool
gives it stable, hashable facts instead of scraping column-formatted text.

```sh
rea scan samples/ --json > scan.json
rea strings samples/app.exe --grep "api" --json > strings.json
```

## Typical workflow

1. **`init`** a case folder so notes and evidence have a home.
2. **`scan`** the samples you were given; note the flagged files.
3. **`info`** the primary target and record its SHA-256 in the notes.
4. **`strings`** for URLs, paths, registry keys, error messages and versions.
5. **`entropy`** to find packed or encrypted regions before wasting time.
6. **`pe` / `elf`** for entry points, imports and hardening.
7. **`archive`** for mobile apps and installers.
8. **`report`** to capture what you know and what to do next.

## What it deliberately does not do

- No disassembly or decompilation. Use Ghidra, IDA, Binary Ninja or radare2 for
  that; `rea pe` tells you where to point them.
- No unpacking, emulation or dynamic analysis.
- No network access, ever.
- No YARA matching or malware verdicts. It reports facts, not conclusions.

## Safety and legality

Only analyse software you own or have explicit permission to examine. Respect
licences, terms of service and the law where you are. Publishing hashes and
observations is not the same as redistributing a binary — keep samples out of
git, which is why `rea init` ignores `samples/`.

## Development

```sh
npm test          # node --test, no dependencies
node bin/rea.js help
```

Layout:

```
bin/rea.js        entry point
src/cli.js        command router and help
src/commands/     one file per command
src/lib/          parsers and helpers (pe, elf, zip, entropy, strings, walk)
test/             unit tests for parsers plus CLI integration tests
```

Parsers are written against the file formats directly and refuse malformed
input with a clear message rather than throwing a stack trace at the user.

## License

MIT — see [LICENSE](LICENSE).
