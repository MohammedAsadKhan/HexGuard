# HexGuard 🛡️

![Python](https://img.shields.io/badge/Python-3.10%2B-blue?style=flat-square&logo=python)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)
![Status](https://img.shields.io/badge/Status-Active-brightgreen?style=flat-square)
![Use Case](https://img.shields.io/badge/Use%20Case-CTF%20%7C%20Malware%20Triage-red?style=flat-square)

HexGuard is a lightweight, zero-dependency Python tool that identifies the true type of any file by reading its **magic bytes** - the raw binary signature embedded in every file's header. It ignores extensions entirely, checks against a database of 169+ known signatures, and flags disguised or mismatched files with a severity rating.

Built for CTF forensics, malware triage, and automated upload validation.

## Why HexGuard?

File extensions are cosmetic. Any attacker can rename `malware.exe` to `vacation_photo.jpg` and most filters won't catch it. Operating systems, email clients, and basic upload validators all rely on the extension - not the actual content - to decide how to handle a file.

HexGuard skips the extension entirely and reads the file at the binary level, where the truth is.

> "A file's extension is a suggestion. Its magic bytes are a confession."

I originally built this after hitting the same wall over and over in CTF forensics challenges - the solve was always recognizing a disguised ELF binary or a ZIP masquerading as a PNG. Manual hex editing works once. HexGuard works every time.

## Features

| Feature | Description |
|---|---|
| **Magic Byte Detection** | Reads file headers and matches against 169+ known binary signatures |
| **Extension Cross-Check** | Compares the detected type to the claimed extension and flags mismatches |
| **Severity Ratings** | Four-level verdict system: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW` |
| **245 Extension Mappings** | Covers images, archives, executables, documents, media, crypto keys, disk images, and more |
| **145 High-Risk Patterns** | Known attacker disguise combos (e.g. PE in `.jpg`, ELF in `.txt`, OLE macro in `.png`) |
| **Batch / Directory Scan** | Scan individual files or entire directories, recursively |
| **Risk-Only Filter** | `--risk-only` flag to surface only suspicious files in large scans |
| **JSON Output** | Machine-readable output for SIEM/pipeline integration |
| **Zero Dependencies** | Pure Python 3 stdlib - no pip installs required |

## How It Works

Every file format reserves its first few bytes for a unique identifier called a **magic number** or **file signature**. These bytes are defined by the format spec and can't be faked without breaking the file.

HexGuard reads the first 512 bytes of a file and checks for matches at each known offset:

```
File: invoice.pdf
  -> Read header: 4D 5A 90 00 03 00 00 00 ...
  -> Match found at offset 0: 4D 5A -> Windows PE/DOS Executable
  -> Extension .pdf expected: PDF Document
  -> MISMATCH detected
  -> Risk lookup: PE Executable in .pdf -> CRITICAL
```

A legitimate PNG will always begin with:
```
89 50 4E 47 0D 0A 1A 0A
```

A Windows executable will always begin with:
```
4D 5A  (ASCII: "MZ")
```

If a file is named `invoice.pdf` but its first two bytes are `4D 5A`, HexGuard catches it immediately regardless of anything else about the file.

## Threat Coverage

HexGuard is tuned to catch the most common evasion patterns seen in CTFs, phishing campaigns, and malware delivery:

| Attack Pattern | Example | Verdict |
|---|---|---|
| Executable as image | `malware.exe` -> `photo.jpg` | `CRITICAL` |
| Macro document as image | `trojan.doc` -> `logo.png` | `CRITICAL` |
| Web shell as image | `shell.php` -> `upload.gif` | `CRITICAL` |
| Exploit PDF as image | `payload.pdf` -> `invoice.jpg` | `HIGH` |
| ZIP polyglot as image | `exploit.zip` -> `banner.png` | `HIGH` |
| Android DEX as audio | `backdoor.dex` -> `track.mp3` | `HIGH` |
| Linux ELF as text | `rootkit.elf` -> `readme.txt` | `HIGH` |
| SSH key as image | `id_rsa` -> `photo.jpg` | `HIGH` |
| PCAP as document | `capture.pcap` -> `report.docx` | `HIGH` |
| SQLite DB as image | `data.db` -> `avatar.jpg` | `HIGH` |

## Getting Started

**Prerequisites:** Python 3.10 or later. No external libraries needed.

```bash
git clone https://github.com/MohammedAsadKhan/HexGuard.git
cd HexGuard
```

**Project structure:**
```
HexGuard/
├── hexguard.py          # Entry point / CLI
├── file_identifier.py   # Core detection engine
├── magic_bytes_db.py    # Signature database (169 sigs, 145 risk pairs)
└── README.md
```

## Usage

```bash
# Scan a single file
python hexguard.py suspicious_file.jpg

# Scan a directory
python hexguard.py /path/to/uploads/

# Recursive scan
python hexguard.py /path/to/uploads/ --recursive

# Show only suspicious files
python hexguard.py /path/to/uploads/ --recursive --risk-only

# Verbose output with hex dump
python hexguard.py suspicious_file.jpg --verbose

# JSON output for pipelines
python hexguard.py /path/to/uploads/ --recursive --json > results.json
```

**All options:**
```
positional arguments:
  target              File or directory to analyze

options:
  -r, --recursive     Scan directory recursively
  -v, --verbose       Show hex dump and all signature matches
  -j, --json          Output results as JSON
  -s, --summary       Show summary table only
      --risk-only     Show only MISMATCH / HIGH / CRITICAL files
```

## Sample Output

Clean file:
```
--------------------------------------------------------------
File:     real_photo.jpg
Path:     /uploads/real_photo.jpg
Size:     2.4 MB
Detected: JPEG/JFIF Image  [Image]
          MIME: image/jpeg
Extension:.jpg
Verdict:  CLEAN
--------------------------------------------------------------
```

Disguised executable:
```
--------------------------------------------------------------
File:     totally_a_photo.jpg
Path:     /uploads/totally_a_photo.jpg
Size:     56.0 B
Detected: Windows PE/DOS Executable  [Executable]
          MIME: application/x-msdownload
Extension:.jpg
Verdict:  CRITICAL
Alert:    CRITICAL: Executable disguised as JPEG - classic malware dropper tactic
--------------------------------------------------------------
```

Scan summary:
```
==============================================================
SCAN SUMMARY - 142 file(s)
==============================================================
  CRITICAL      3
  HIGH          7
  MEDIUM        2
  CLEAN       130
==============================================================
```

## Signature Database

The database in `magic_bytes_db.py` is built from:

- [Wikipedia - List of file signatures](https://en.wikipedia.org/wiki/List_of_file_signatures)
- Gary Kessler's File Signatures Table
- libmagic / `file(1)` Magdir source
- CTF writeups and malware analysis blogs

Current coverage:

| Metric | Count |
|---|---|
| Unique signatures | 169 |
| File extensions mapped | 245 |
| High-risk disguise pairs | 145 |
| Categories covered | 27 |

Categories include images, audio, video, documents, archives, executables, disk images, databases, network captures, crypto/keys, fonts, scientific data, game ROMs, medical (DICOM), and more.

## Pipeline Integration

The `--json` flag makes it easy to drop HexGuard into automated workflows:

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

Exit codes: `0` means all clean, `1` means at least one suspicious file was found. Useful as a gate in CI/CD pipelines or upload validators.

## Limitations

Worth being upfront about what this tool is and isn't:

- HexGuard only looks at the file header. A well-crafted polyglot file (valid as two formats at once) could slip through.
- It doesn't scan file contents beyond the header, so it won't catch encrypted payloads, steganography, or obfuscated scripts hiding inside otherwise legitimate containers.
- Rare or proprietary formats might not be in the database yet.
- This is a first-pass triage tool, not a replacement for antivirus.

## Contributing

If you come across a signature or evasion pattern that isn't covered, feel free to open a PR. Add your entry to `magic_bytes_db.py` following the existing format and include a source (Wikipedia, RFC, format spec, or a writeup). New high-risk disguise pairs are especially useful.

## License

MIT License - see `LICENSE` for details.

*Developed as a utility for CTF forensics and automated threat detection.*
*Maintained by Mohammed Asad Khan.*
