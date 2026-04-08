# HexGuard 🛡️

![Python](https://img.shields.io/badge/Python-3.10%2B-blue?style=flat-square&logo=python)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)
![Status](https://img.shields.io/badge/Status-Active-brightgreen?style=flat-square)
![Use Case](https://img.shields.io/badge/Use%20Case-CTF%20%7C%20File%20Carving%20%7C%20Malware%20Triage-red?style=flat-square)

HexGuard is a lightweight, zero-dependency Python tool that identifies the true type of any file by reading its **magic bytes** - the raw binary signature embedded in every file's header. It ignores extensions entirely, checks against a database of 169+ known signatures, flags disguised or mismatched files with a severity rating, and tells you **exactly how to fix the header** in a hex editor.

Built for CTF forensics, file carving, malware triage, and automated upload validation.

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
| **Deep Inspection** | Scans the full file body for missing EOF markers, foreign signatures, and embedded payloads |
| **Header Swap Detection** | Identifies files where the header has been replaced with a different format's magic bytes |
| **Hex Editor Fix Guide** | Tells you the exact bytes to overwrite at offset 0x00 and what extension to save as |
| **Severity Ratings** | Four-level verdict system: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW` |
| **245 Extension Mappings** | Covers images, archives, executables, documents, media, crypto keys, disk images, and more |
| **145 High-Risk Patterns** | Known attacker disguise combos (e.g. PE in `.jpg`, ELF in `.txt`, OLE macro in `.png`) |
| **Batch / Directory Scan** | Scan individual files or entire directories, recursively |
| **Risk-Only Filter** | `--risk-only` flag to surface only suspicious files in large scans |
| **JSON Output** | Machine-readable output for SIEM/pipeline integration |
| **Zero Dependencies** | Pure Python 3 stdlib - no pip installs required |

## How It Works

Every file format reserves its first few bytes for a unique identifier called a **magic number** or **file signature**. These bytes are defined by the format spec and can't be faked without breaking the file.

HexGuard runs two passes on every file:

**Pass 1 - Header check:** Reads the first 512 bytes and matches against the signature database.

```
File: invoice.pdf
  -> Read header: 4D 5A 90 00 03 00 00 00 ...
  -> Match found at offset 0: 4D 5A -> Windows PE/DOS Executable
  -> Extension .pdf expected: PDF Document
  -> MISMATCH detected
  -> Risk lookup: PE Executable in .pdf -> CRITICAL
```

**Pass 2 - Deep inspection:** Reads the full file body and checks for missing EOF markers, foreign format signatures embedded in the body, and known alarm signatures (executables, archives, etc.) hiding inside other formats.

```
File: flag.jpeg
  -> Header: FF D8 FF E0 (JPEG) - matches extension .jpeg -> initially CLEAN
  -> Deep inspect: no JPEG FFD9 end marker found
  -> Deep inspect: PNG IHDR chunk at offset 12, PNG IEND chunk at offset 7083
  -> CRITICAL: PNG disguised as JPEG
  -> Fix: replace bytes at 0x00 with 89 50 4E 47 0D 0A 1A 0A, rename to .png
```

## Threat Coverage

HexGuard is tuned to catch the most common evasion patterns seen in CTFs, phishing campaigns, and malware delivery:

| Attack Pattern | Example | Verdict |
|---|---|---|
| Executable as image | `malware.exe` → `photo.jpg` | `CRITICAL` |
| Macro document as image | `trojan.doc` → `logo.png` | `CRITICAL` |
| PNG body with JPEG header | `flag.png` → `flag.jpeg` | `CRITICAL` |
| JPEG body with PNG header | `flag.jpg` → `flag.png` | `CRITICAL` |
| PNG body with Word header | `image.png` → `document.doc` | `CRITICAL` |
| PDF disguised as image | `payload.pdf` → `invoice.jpg` | `CRITICAL` |
| ZIP polyglot as image | `exploit.zip` → `banner.png` | `CRITICAL` |
| Web shell as image | `shell.php` → `upload.gif` | `CRITICAL` |
| Linux ELF as text | `rootkit.elf` → `readme.txt` | `HIGH` |
| SSH key as image | `id_rsa` → `photo.jpg` | `HIGH` |
| PCAP as document | `capture.pcap` → `report.docx` | `HIGH` |
| SQLite DB as image | `data.db` → `avatar.jpg` | `HIGH` |
| Android DEX as audio | `backdoor.dex` → `track.mp3` | `HIGH` |

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
├── file_identifier.py   # Core detection engine + deep inspector
├── magic_bytes_db.py    # Signature database (169 sigs, 145 risk pairs)
└── README.md
```

## Usage

```bash
# Scan a single file
python3 hexguard.py suspicious_file.jpg

# Scan a directory
python3 hexguard.py /path/to/uploads/

# Recursive scan
python3 hexguard.py /path/to/uploads/ --recursive

# Show only suspicious files
python3 hexguard.py /path/to/uploads/ --recursive --risk-only

# Verbose output with hex dump
python3 hexguard.py suspicious_file.jpg --verbose

# JSON output for pipelines
python3 hexguard.py /path/to/uploads/ --recursive --json > results.json
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

**Clean file:**
```
──────────────────────────────────────────────────────────────
File:     real_photo.jpg
Path:     /uploads/real_photo.jpg
Size:     2.4 MB
Detected: JPEG/JFIF Image  [Image]
          MIME: image/jpeg
Extension:.jpg
Verdict:  CLEAN
Reason:   The file header contains the magic bytes for 'JPEG/JFIF Image'
          and the extension '.jpg' is a valid match for that format.
          No evasion detected.
──────────────────────────────────────────────────────────────
```

**PNG disguised as JPEG (header swap):**
```
──────────────────────────────────────────────────────────────
File:     flag__1_.jpeg
Path:     flag__1_.jpeg
Size:     6.9 KB
Detected: JPEG/JFIF Image  [Image]
          MIME: image/jpeg
Extension:.jpeg
Verdict:  CRITICAL
Reason:   The file header contains the magic bytes for 'JPEG/JFIF Image'
          and the extension '.jpeg' is a valid match for that format.
          [Deep Inspect] Missing JPEG EOI end marker - file may have a
          swapped/fake header. | Found PNG IHDR chunk at offset 12 inside
          a JPEG file. | Found PNG IEND chunk at offset 7083.

⚠  Deep Inspection Findings:
   • Missing JPEG EOI end marker - file may have a swapped/fake header.
   • Found PNG IHDR chunk at offset 12 inside a JPEG file - possible polyglot or header-swap.
   • Found PNG IEND chunk at offset 7083 inside a JPEG file - possible polyglot or header-swap.

🔍 Fix: Open in a hex editor and correct the header
   Detected swap: PNG image disguised as JPEG
   The file header says 'JPEG/JFIF Image' but the body is actually PNG.

     Current header (fake): FF D8 FF E0 00 10 4A 46 ...
     Replace with   (real):  89 50 4E 47 0D 0A 1A 0A

   Steps:
     1. Open the file in a hex editor (e.g. HxD, wxHexEditor, Bless)
     2. Go to offset 0x00 (the very start)
     3. Overwrite the first bytes with: 89 50 4E 47 0D 0A 1A 0A
     4. Save and rename the file with extension: .png
──────────────────────────────────────────────────────────────
```

**PNG image disguised as a Word document:**
```
──────────────────────────────────────────────────────────────
File:     disguised_image.doc
Path:     disguised_image.doc
Size:     1.5 KB
Detected: MS Office Legacy (DOC/XLS/PPT/MSG)  [Document]
          MIME: application/msword
Extension:.doc
Verdict:  CRITICAL
Reason:   The file header contains the magic bytes for 'MS Office Legacy'
          and the extension '.doc' is a valid match for that format.
          [Deep Inspect] Found PNG signature at offset 24 inside a
          MS Office file - possible polyglot or header-swap.

⚠  Deep Inspection Findings:
   • Found PNG signature at offset 24 inside a MS Office file - possible polyglot or header-swap.
   • Embedded PNG image signature at offset 24.

🔍 Fix: Open in a hex editor and correct the header
   Detected swap: PNG disguised as MS Office document
   The file header says 'MS Office Legacy (DOC/XLS/PPT/MSG)' but the body is actually PNG image.

     Current header (fake): D0 CF 11 E0 A1 B1 1A E1 ...
     Replace with   (real):  89 50 4E 47 0D 0A 1A 0A

   Steps:
     1. Open the file in a hex editor (e.g. HxD, wxHexEditor, Bless)
     2. Go to offset 0x00 (the very start)
     3. Overwrite the first bytes with: 89 50 4E 47 0D 0A 1A 0A
     4. Save and rename the file with extension: .png
──────────────────────────────────────────────────────────────
```

**Scan summary:**
```
==============================================================
SCAN SUMMARY - 12 file(s)
==============================================================
  CRITICAL      4
  HIGH          2
  MEDIUM        1
  CLEAN         5
==============================================================
```

## Header Swap Coverage

HexGuard detects swaps in every direction across all major format families:

| Swap Direction | Detected |
|---|---|
| Any image ↔ Any image | JPEG↔PNG, JPEG↔GIF, JPEG↔BMP, JPEG↔TIFF, PNG↔GIF, PNG↔BMP, and more |
| Image → Executable | JPEG/PNG/GIF hiding PE/EXE or ELF binary |
| Image → Archive | JPEG/PNG hiding ZIP, PDF, or MS Office OLE |
| Document ↔ Document | PDF↔JPEG/PNG/ZIP/OLE, MS Office↔JPEG/PNG/ZIP/EXE |
| Executable → Anything | PE/EXE or ELF hiding inside any image or archive |

For every detected swap, HexGuard outputs the exact hex bytes to paste at offset `0x00` in a hex editor and the correct extension to rename the file to. No guesswork.

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
| Header swap fix entries | 50+ |
| Categories covered | 27 |

Categories include images, audio, video, documents, archives, executables, disk images, databases, network captures, crypto/keys, fonts, scientific data, game ROMs, medical (DICOM), and more.

## Pipeline Integration

The `--json` flag makes it easy to drop HexGuard into automated workflows:

```python
import subprocess
import json

result = subprocess.run(
    ["python3", "hexguard.py", "/tmp/upload.jpg", "--json"],
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

- Deep inspection catches header swaps and embedded signatures, but a well-crafted polyglot (valid in two formats simultaneously) may still pass depending on construction.
- It does not decrypt encrypted payloads or detect steganography hidden inside pixel data.
- Rare or proprietary formats may not be in the database yet.
- This is a first-pass triage and file carving tool, not a replacement for antivirus.

## Contributing

If you come across a signature, evasion pattern, or header swap combo that isn't covered, feel free to open a PR. Add signatures to `magic_bytes_db.py` and swap entries to the `_HEADER_SWAP_FIXES` table in `file_identifier.py`, following the existing format. Include a source (Wikipedia, RFC, format spec, or a CTF writeup). New high-risk disguise pairs are especially useful.

## License

MIT License - see [`LICENSE`](LICENSE) for details.

*Developed as a utility for CTF forensics, file carving, and automated threat detection.*  
*Maintained by Mohammed Asad Khan.*
