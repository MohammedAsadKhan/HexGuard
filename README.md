# HexGuard 🛡️

![Python](https://img.shields.io/badge/Python-3.10%2B-blue?style=flat-square&logo=python)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)
![Status](https://img.shields.io/badge/Status-Active-brightgreen?style=flat-square)
![Use Case](https://img.shields.io/badge/Use%20Case-CTF%20%7C%20Malware%20Triage-red?style=flat-square)

**HexGuard** is a lightweight, zero-dependency Python tool for identifying the true type of any file by reading its **magic bytes** — the raw binary signature embedded in every file's header. It ignores extensions entirely, cross-references detected types against a database of 169+ known signatures, and flags disguised or mismatched files with a severity rating.

Built for CTF forensics, malware triage, and automated upload validation pipelines.

---

## Why HexGuard?

File extensions are cosmetic. Any attacker can rename `malware.exe` to `vacation_photo.jpg` and most filters won't catch it. Operating systems, email clients, and basic upload validators all rely on the extension — not the actual content — to decide how to handle a file.

HexGuard skips the extension entirely and reads the file at the binary level, where the truth is.

> "A file's extension is a suggestion. Its magic bytes are a confession."

This tool was originally developed after repeatedly hitting "file upload" and "forensics" challenges in CTFs where the solve required recognizing a disguised ELF binary or a ZIP archive masquerading as a PNG. Manual hex editing works once. HexGuard works every time.

---

## Features

| Feature | Description |
|---|---|
| **Magic Byte Detection** | Reads file headers and matches against 169+ known binary signatures |
| **Extension Cross-Check** | Compares detected type to the claimed extension; flags mismatches |
| **Severity Ratings** | Four-level verdict system: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW` |
| **245 Extension Mappings** | Covers images, archives, executables, documents, media, crypto keys, disk images, and more |
| **145 High-Risk Patterns** | Known attacker disguise combos (e.g. PE in `.jpg`, ELF in `.txt`, OLE macro in `.png`) |
| **Batch / Directory Scan** | Scan individual files or entire directories, recursively |
| **Risk-Only Filter** | `--risk-only` flag to surface only suspicious files in large scans |
| **JSON Output** | Machine-readable output for SIEM/pipeline integration |
| **Zero Dependencies** | Pure Python 3 stdlib — no pip installs required |

---

## How It Works

Every file format reserves its first few bytes for a unique identifier, known as a **magic number** or **file signature**. These bytes are set by the format specification and cannot be faked without breaking the file itself.

HexGuard reads the first 512 bytes of a file and checks for matches at each known offset:

```
File: invoice.pdf
  → Read header: 4D 5A 90 00 03 00 00 00 ...
  → Match found at offset 0: 4D 5A → Windows PE/DOS Executable
  → Extension .pdf expected: PDF Document
  → MISMATCH detected
  → Risk lookup: PE Executable in .pdf → CRITICAL
```

### Signature matching example

A legitimate PNG will always begin with:
```
89 50 4E 47 0D 0A 1A 0A
```

A Windows executable will always begin with:
```
4D 5A  (ASCII: "MZ")
```

If a file is named `invoice.pdf` but its first two bytes are `4D 5A`, HexGuard catches it immediately — regardless of anything else about the file.

---

## Threat Coverage

HexGuard is specifically tuned to catch the most common attacker evasion patterns seen in CTFs, phishing campaigns, and malware delivery chains:

| Attack Pattern | Example | HexGuard Verdict |
|---|---|---|
| Executable as image | `malware.exe` → `photo.jpg` | `CRITICAL` |
| Macro document as image | `trojan.doc` → `logo.png` | `CRITICAL` |
| Exploit PDF as image | `payload.pdf` → `invoice.jpg` | `HIGH` |
| ZIP polyglot as image | `exploit.zip` → `banner.png` | `HIGH` |
| Android DEX as audio | `backdoor.dex` → `track.mp3` | `HIGH` |
| Linux ELF as text | `rootkit.elf` → `readme.txt` | `HIGH` |
| SSH key as image | `id_rsa` → `photo.jpg` | `HIGH` |
| PCAP as document | `capture.pcap` → `report.docx` | `HIGH` |
| SQLite DB as image | `data.db` → `avatar.jpg` | `HIGH` |
| Web shell PHP as image | `shell.php` → `upload.gif` | `CRITICAL` |

---

## Getting Started

### Prerequisites

- Python 3.10 or later (uses the `X | Y` type union syntax)
- No external libraries required

### Installation

```bash
git clone https://github.com/MohammedAsadKhan/HexGuard.git
cd HexGuard
```

### Project Structure

```
HexGuard/
├── hexguard.py          # Entry point / CLI (replaces cli.py)
├── file_identifier.py   # Core detection engine
├── magic_bytes_db.py    # Signature database (169 sigs, 145 risk pairs)
└── README.md
```

---

## Usage

### Scan a single file

```bash
python hexguard.py suspicious_file.jpg
```

### Scan a directory

```bash
python hexguard.py /path/to/uploads/
```

### Recursive scan

```bash
python hexguard.py /path/to/uploads/ --recursive
```

### Show only suspicious files

```bash
python hexguard.py /path/to/uploads/ --recursive --risk-only
```

### Verbose output (hex dump + all matches)

```bash
python hexguard.py suspicious_file.jpg --verbose
```

### JSON output (for pipelines / SIEMs)

```bash
python hexguard.py /path/to/uploads/ --recursive --json > results.json
```

### Full options

```
usage: hexguard.py <target> [options]

positional arguments:
  target              File or directory to analyze

options:
  -r, --recursive     Scan directory recursively
  -v, --verbose       Show hex dump and all signature matches
  -j, --json          Output results as JSON
  -s, --summary       Show summary table only
      --risk-only     Show only MISMATCH / HIGH / CRITICAL files
```

---

## Sample Output

### Clean file

```
──────────────────────────────────────────────────────────────
File:     real_photo.jpg
Path:     /uploads/real_photo.jpg
Size:     2.4 MB
Detected: JPEG/JFIF Image  [Image]
          MIME: image/jpeg
Extension:.jpg
Verdict:  CLEAN
──────────────────────────────────────────────────────────────
```

### Disguised executable (CRITICAL)

```
──────────────────────────────────────────────────────────────
File:     totally_a_photo.jpg
Path:     /uploads/totally_a_photo.jpg
Size:     56.0 B
Detected: Windows PE/DOS Executable  [Executable]
          MIME: application/x-msdownload
Extension:.jpg
Verdict:  CRITICAL
Alert:    ⚠️  CRITICAL: Executable disguised as JPEG — classic malware dropper tactic
──────────────────────────────────────────────────────────────
```

### Scan summary

```
══════════════════════════════════════════════════════════════
SCAN SUMMARY — 142 file(s)
══════════════════════════════════════════════════════════════
  CRITICAL      3
  HIGH          7
  MEDIUM        2
  CLEAN       130
══════════════════════════════════════════════════════════════
```

---

## Signature Database

The signature database (`magic_bytes_db.py`) is sourced from:

- [Wikipedia — List of file signatures](https://en.wikipedia.org/wiki/List_of_file_signatures)
- Gary Kessler's File Signatures Table
- libmagic / `file(1)` Magdir source
- Community CTF writeups and malware analysis blogs

Current coverage:

| Metric | Count |
|---|---|
| Unique signatures | 169 |
| File extensions mapped | 245 |
| High-risk disguise pairs | 145 |
| Categories covered | 27 |

**Categories include:** Images, Audio, Video, Documents, Archives, Executables, Disk Images, Databases, Network Captures, Crypto/Keys, Fonts, Scientific Data, Game ROMs, Medical (DICOM), and more.

---

## Integration Example

HexGuard's `--json` flag makes it easy to integrate into automated pipelines:

```python
import subprocess
import json

result = subprocess.run(
    ["python", "hexguard.py", "/tmp/upload.jpg", "--json"],
    capture_output=True, text=True
)
findings = json.loads(result.stdout)

for f in findings:
    if f["verdict"] in ("CRITICAL", "HIGH"):
        quarantine(f["file"])
        alert_team(f["mismatch_report"]["risk_note"])
```

### Exit codes

| Code | Meaning |
|---|---|
| `0` | All files clean |
| `1` | One or more mismatches or high-risk files detected |

This makes HexGuard suitable as a gate in CI/CD pipelines or file upload validators.

---

## Limitations

- **Magic bytes only:** HexGuard analyzes file headers. A sufficiently crafted polyglot file (valid as two formats simultaneously) may not be flagged.
- **No content scanning:** HexGuard does not inspect file contents beyond the header — it does not detect encrypted payloads, steganography, or obfuscated scripts within otherwise legitimate containers.
- **Signature coverage:** Rare or proprietary formats may not be in the database. Contributions welcome.
- **Not a replacement for AV:** HexGuard is a first-pass triage tool, not a full antivirus solution.

---

## Roadmap

- [ ] Shannon entropy analysis to detect packed/encrypted payloads
- [ ] YARA rule integration for content-level pattern matching
- [ ] VirusTotal hash lookup (API key optional)
- [ ] Recursive archive scanning (ZIP-in-ZIP, nested containers)
- [ ] Web UI / drag-and-drop interface
- [ ] Plugin system for custom signature sets
- [ ] `--watch` mode for real-time directory monitoring

---

## Contributing

Contributions are welcome — especially new signatures, additional high-risk pairs, and real-world evasion patterns discovered in CTFs or malware samples.

1. Fork the repository
2. Add your signature to `magic_bytes_db.py` following the existing format
3. Include a source reference (Wikipedia, RFC, format spec, or writeup)
4. Open a pull request with a brief description of what it catches

---

## License

MIT License — see `LICENSE` for details.

---

*Developed as a utility for CTF forensics and automated threat detection.*  
*Maintained by Mohammed Asad Khan.*
