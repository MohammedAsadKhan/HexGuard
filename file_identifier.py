"""
File Type Identifier - Core Engine
Reads file header magic bytes, detects type, cross-checks extension,
and flags mismatches / disguised files using the expanded signature database.
"""

import os
from pathlib import Path
from datetime import datetime
from magic_bytes_db import SIGNATURES, EXTENSION_TYPE_MAP, lookup_risk

# Bytes to read from each file header (covers all known offsets in our DB)
HEADER_READ_SIZE = 512


# -----------------------------------------------------------------------------
# Core Detection
# -----------------------------------------------------------------------------

def read_header(file_path: str, size: int = HEADER_READ_SIZE) -> bytes | None:
    try:
        with open(file_path, "rb") as f:
            return f.read(size)
    except (IOError, PermissionError):
        return None


def detect_type(header: bytes) -> list[dict]:
    """
    Match header bytes against all known signatures (at their correct offsets).
    Returns all matches sorted by signature length descending (longer = more specific).
    """
    matches = []
    seen = set()
    for offset, sig, label, mime, category, exts in SIGNATURES:
        if offset + len(sig) > len(header):
            continue
        window = header[offset: offset + len(sig)]
        if window == sig and label not in seen:
            seen.add(label)
            matches.append({
                "label":      label,
                "mime_type":  mime,
                "category":   category,
                "signature":  sig.hex(),
                "offset":     offset,
                "sig_len":    len(sig),
                "valid_exts": list(exts),
            })
    # Longer / more specific signatures rank higher
    matches.sort(key=lambda m: m["sig_len"], reverse=True)
    return matches


def check_mismatch(file_path: str, matches: list[dict]) -> dict:
    """
    Compare the file's extension against detected types.
    Returns a full mismatch report dict.
    """
    ext = Path(file_path).suffix.lower()

    if not ext:
        return {
            "has_extension":  False,
            "extension":      None,
            "expected_types": [],
            "detected_labels":[],
            "mismatch":       False,
            "risk_level":     "UNKNOWN",
            "risk_note":      "No extension - cannot cross-check.",
        }

    expected_types  = EXTENSION_TYPE_MAP.get(ext, [])
    detected_labels = [m["label"] for m in matches]

    # A match exists if any detected type is in the expected list
    match_found = any(d in expected_types for d in detected_labels)
    mismatch    = bool(matches) and not match_found and bool(expected_types)

    risk_level = "OK"
    risk_note  = ""

    if mismatch:
        risk_level = "MISMATCH"
        risk_note  = (
            f"File claims to be '{ext.upper()}' but header says: "
            f"{', '.join(detected_labels[:3])}"
        )
        # Check against high-risk pairs (substring match)
        for d_label in detected_labels:
            result = lookup_risk(d_label, ext)
            if result:
                level, msg = result
                risk_order = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
                if risk_order.get(level, 0) > risk_order.get(risk_level.replace("MISMATCH", "LOW"), 0):
                    risk_level = level
                    risk_note  = f"[{level}] {msg}"

    return {
        "has_extension":  True,
        "extension":      ext,
        "expected_types": expected_types,
        "detected_labels":detected_labels,
        "mismatch":       mismatch,
        "risk_level":     risk_level,
        "risk_note":      risk_note,
    }


def get_file_metadata(file_path: str) -> dict:
    try:
        stat = os.stat(file_path)
        return {
            "size_bytes": stat.st_size,
            "size_human": _human_size(stat.st_size),
            "modified":   datetime.fromtimestamp(stat.st_mtime).isoformat(),
            "created":    datetime.fromtimestamp(stat.st_ctime).isoformat(),
        }
    except Exception:
        return {}


def _human_size(size: int) -> str:
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if size < 1024:
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} PB"


# -----------------------------------------------------------------------------
# Reason generator
# Produces a plain-English explanation for every possible verdict.
# -----------------------------------------------------------------------------

def _build_reason(verdict: str, matches: list[dict], mr: dict, file_path: str) -> str:
    ext = Path(file_path).suffix.lower() or "(none)"

    if verdict == "ERROR":
        return "Could not read the file."

    if verdict == "UNKNOWN":
        return (
            "No matching signature was found in the database. "
            "The file may be plain text, a config file, an unsupported format, "
            "or the header may be corrupt or empty."
        )

    if verdict == "CLEAN":
        pt = matches[0]
        return (
            f"The file header contains the magic bytes for '{pt['label']}' "
            f"and the extension '{ext}' is a valid match for that format. "
            f"No evasion detected."
        )

    # MISMATCH / LOW / MEDIUM / HIGH / CRITICAL
    risk_note = mr.get("risk_note", "")
    detected  = ", ".join(mr.get("detected_labels", [])[:3])

    severity_context = {
        "LOW":      "Low-severity mismatch. Could be a renamed or miscategorised file.",
        "MEDIUM":   "Moderate-severity mismatch. The file type is suspicious for this extension.",
        "HIGH":     "High-severity mismatch. This combination is commonly used to bypass filters.",
        "CRITICAL": "Critical mismatch. This is a well-known attacker technique for delivering malicious payloads.",
        "MISMATCH": "The detected file type does not match the extension.",
    }

    context = severity_context.get(verdict, "")
    return (
        f"Header identifies this as: {detected}. "
        f"Extension '{ext}' does not match that type. "
        f"{context} {risk_note}".strip()
    )


# -----------------------------------------------------------------------------
# Main Analysis
# -----------------------------------------------------------------------------

def analyze_file(file_path: str) -> dict:
    result = {
        "file":                file_path,
        "filename":            Path(file_path).name,
        "timestamp":           datetime.now().isoformat(),
        "status":              "ok",
        "error":               None,
        "metadata":            {},
        "header_hex":          "",
        "detected_types":      [],
        "primary_type":        None,
        "mismatch_report":     {},
        "deep_inspect_report": {},
        "verdict":             "CLEAN",
        "reason":              "",
        "binwalk_suggested":   False,
    }

    if not os.path.isfile(file_path):
        result.update(status="error", error="File not found", verdict="ERROR",
                      reason="File not found on disk.")
        return result

    result["metadata"] = get_file_metadata(file_path)

    header = read_header(file_path)
    if header is None:
        result.update(status="error", error="Cannot read file (permission denied)",
                      verdict="ERROR", reason="Permission denied when reading the file.")
        return result

    result["header_hex"] = header[:32].hex(" ").upper()

    matches = detect_type(header)
    result["detected_types"] = matches
    result["primary_type"]   = matches[0] if matches else None

    mr = check_mismatch(file_path, matches)
    result["mismatch_report"] = mr

    rl = mr["risk_level"]
    if rl in ("CRITICAL", "HIGH", "MEDIUM", "LOW") and mr["mismatch"]:
        result["verdict"] = rl
    elif mr["mismatch"]:
        result["verdict"] = "MISMATCH"
    elif not matches:
        result["verdict"] = "UNKNOWN"
    else:
        result["verdict"] = "CLEAN"

    result["reason"] = _build_reason(result["verdict"], matches, mr, file_path)

    # --- Deep inspection (runs on all files with a known primary type) ---
    if matches:
        di = deep_inspect(file_path, matches[0]["label"])
        result["deep_inspect_report"] = di
        if di["suspicious"]:
            sev       = di["severity"]
            sev_order = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
            cur_order = sev_order.get(result["verdict"], 0)
            new_order = sev_order.get(sev, 0)
            # Only upgrade verdict, never downgrade
            if new_order > cur_order:
                result["verdict"] = sev
            result["binwalk_suggested"] = True
            # Append deep-inspect findings to reason
            findings_text = " | ".join(di["findings"])
            result["reason"] += f"\n  [Deep Inspect] {findings_text}"

    return result


# -----------------------------------------------------------------------------
# Deep Inspection
# Catches header-swapped polyglots and hidden embedded files that pass the
# basic magic byte check — e.g. a PNG body with a JPEG header bolted on.
# Runs only on files that initially appear CLEAN.
# -----------------------------------------------------------------------------

# Known end-of-file markers: (format_label_substring, marker_bytes, description)
_EOF_MARKERS = [
    ("JPEG",  b"\xff\xd9",                     "JPEG EOI"),
    ("PDF",   b"%%EOF",                         "PDF EOF"),
    ("GIF",   b"\x00\x3b",                      "GIF trailer"),
    ("ZIP",   b"PK\x05\x06",                    "ZIP end-of-central-directory"),
]

# Signatures that should NOT appear inside a file of another type
# (primary_label_substring, forbidden_sig, forbidden_sig_name)
_FOREIGN_SIGS = [
    ("JPEG",  b"\x89PNG\r\n\x1a\n",            "PNG signature"),
    ("JPEG",  b"IHDR",                          "PNG IHDR chunk"),
    ("JPEG",  b"IEND",                          "PNG IEND chunk"),
    ("JPEG",  b"\x1a\x45\xdf\xa3",             "MKV/WebM signature"),
    ("PNG",   b"\xff\xd8\xff",                  "JPEG SOI"),
    ("PNG",   b"MZ",                            "PE/EXE signature"),
    ("PNG",   b"\x7fELF",                       "ELF signature"),
    ("GIF",   b"\xff\xd8\xff",                  "JPEG SOI"),
    ("GIF",   b"\x89PNG",                       "PNG signature"),
    ("PDF",   b"MZ",                            "PE/EXE signature"),
    ("PDF",   b"\x7fELF",                       "ELF signature"),
]

# Signatures whose presence anywhere in the file body is always suspicious
_EMBEDDED_ALARM_SIGS = [
    (b"MZ",               "Windows PE/EXE",   "CRITICAL"),
    (b"\x7fELF",          "Linux ELF binary", "CRITICAL"),
    (b"PK\x03\x04",       "ZIP archive",      "HIGH"),
    (b"\x1f\x8b\x08",     "GZIP stream",      "HIGH"),
    (b"7z\xbc\xaf'",      "7-Zip archive",    "HIGH"),
    (b"Rar!\x1a\x07",     "RAR archive",      "HIGH"),
    (b"\x89PNG\r\n\x1a\n","PNG image",        "MEDIUM"),
    (b"%PDF-",            "PDF document",     "MEDIUM"),
    (b"\xff\xd8\xff",     "JPEG image",       "MEDIUM"),
]

def deep_inspect(file_path: str, primary_label: str) -> dict:
    """
    Reads the full file and checks for:
      1. Missing expected EOF marker (header-swap / truncation)
      2. Foreign format signatures inside the body
      3. Embedded alarm signatures mid-file (appended/prepended payloads)

    Returns a dict:
      {
        "suspicious": bool,
        "severity":   "CRITICAL"|"HIGH"|"MEDIUM"|"LOW"|"",
        "findings":   [str, ...]          # human-readable findings list
      }
    """
    try:
        with open(file_path, "rb") as f:
            body = f.read()
    except (IOError, PermissionError):
        return {"suspicious": False, "severity": "", "findings": []}

    findings  = []
    top_sev   = ""
    sev_order = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}

    def _upgrade(sev: str):
        nonlocal top_sev
        if sev_order.get(sev, 0) > sev_order.get(top_sev, 0):
            top_sev = sev

    label_up = primary_label.upper()

    # 1 — Check for missing EOF marker
    for fmt_sub, marker, marker_name in _EOF_MARKERS:
        if fmt_sub.upper() in label_up:
            if marker not in body:
                findings.append(
                    f"Missing {marker_name} end marker — file may have a swapped/fake header."
                )
                _upgrade("HIGH")

    # 2 — Check for foreign signatures in the body (skip first 16 bytes = header area)
    for fmt_sub, sig, sig_name in _FOREIGN_SIGS:
        if fmt_sub.upper() in label_up:
            idx = body.find(sig, 16)
            if idx != -1:
                findings.append(
                    f"Found {sig_name} at offset {idx} inside a {fmt_sub} file — "
                    f"possible polyglot or header-swap."
                )
                _upgrade("CRITICAL")

    # 3 — Embedded alarm signatures anywhere past the header (offset > 32)
    for sig, sig_name, sev in _EMBEDDED_ALARM_SIGS:
        # Skip if this sig matches the file's own primary type
        if sig_name.split()[0].upper() in label_up:
            continue
        idx = body.find(sig, 32)
        if idx != -1:
            findings.append(
                f"Embedded {sig_name} signature at offset {idx}."
            )
            _upgrade(sev)

    return {
        "suspicious": bool(findings),
        "severity":   top_sev,
        "findings":   findings,
    }


def analyze_directory(dir_path: str, recursive: bool = False) -> list[dict]:
    results = []
    p = Path(dir_path)
    if not p.is_dir():
        return [{"error": f"Not a directory: {dir_path}"}]
    glob = p.rglob("*") if recursive else p.glob("*")
    for f in glob:
        if f.is_file():
            results.append(analyze_file(str(f)))
    return results


# -----------------------------------------------------------------------------
# Pretty-print helpers
# -----------------------------------------------------------------------------

VERDICT_COLORS = {
    "CLEAN":    "\033[92m",   # green
    "UNKNOWN":  "\033[93m",   # yellow
    "LOW":      "\033[93m",   # yellow
    "MEDIUM":   "\033[33m",   # orange
    "MISMATCH": "\033[91m",   # red
    "HIGH":     "\033[91m",   # red
    "CRITICAL": "\033[95m",   # magenta
    "ERROR":    "\033[90m",   # grey
}
RESET = "\033[0m"
BOLD  = "\033[1m"


def print_result(result: dict, verbose: bool = False):
    v     = result["verdict"]
    color = VERDICT_COLORS.get(v, "")

    print(f"\n{'─'*62}")
    print(f"{BOLD}File:{RESET}     {result['filename']}")
    print(f"{BOLD}Path:{RESET}     {result['file']}")

    meta = result.get("metadata", {})
    if meta.get("size_human"):
        print(f"{BOLD}Size:{RESET}     {meta['size_human']}")

    if result["status"] == "error":
        print(f"{BOLD}Verdict:{RESET}  {color}{BOLD}{v}{RESET}")
        print(f"{BOLD}Reason:{RESET}   {result.get('reason', '')}")
        print(f"{'─'*62}")
        return

    pt = result["primary_type"]
    if pt:
        print(f"{BOLD}Detected:{RESET} {pt['label']}  [{pt['category']}]")
        print(f"          MIME: {pt['mime_type']}")
        if verbose and len(result["detected_types"]) > 1:
            print(f"          Also matches:")
            for m in result["detected_types"][1:4]:
                print(f"            - {m['label']}")
    else:
        print(f"{BOLD}Detected:{RESET} {color}UNKNOWN - no matching signature found{RESET}")

    mr  = result.get("mismatch_report", {})
    ext = mr.get("extension", "-")
    print(f"{BOLD}Extension:{RESET}{ext}")
    print(f"{BOLD}Verdict:{RESET}  {color}{BOLD}{v}{RESET}")
    print(f"{BOLD}Reason:{RESET}   {result.get('reason', '')}")

    if verbose:
        print(f"\n{BOLD}Header (hex, first 32 bytes):{RESET}")
        print(f"  {result['header_hex']}")
        expected = mr.get("expected_types", [])
        if expected:
            print(f"\n{BOLD}Expected type(s) for {ext}:{RESET}")
            for t in expected[:5]:
                print(f"  - {t}")

    # Deep inspect findings
    di = result.get("deep_inspect_report", {})
    if di.get("suspicious"):
        YELLOW = "\033[93m"
        print(f"\n{YELLOW}{BOLD}⚠  Deep Inspection Findings:{RESET}")
        for finding in di.get("findings", []):
            print(f"   • {finding}")

    # Binwalk suggestion
    if result.get("binwalk_suggested"):
        CYAN = "\033[96m"
        fname = result["filename"]
        print(f"\n{CYAN}{BOLD}🔍 Recommended:{RESET}{CYAN} Run binwalk for further analysis:{RESET}")
        print(f"   {CYAN}binwalk -e \"{fname}\"{RESET}")
        print(f"   {CYAN}binwalk --dd='.*' \"{fname}\"   (extract all embedded files){RESET}")

    print(f"{'─'*62}")


def print_summary(results: list[dict]):
    total  = len(results)
    order  = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "MISMATCH", "UNKNOWN", "CLEAN", "ERROR"]
    counts: dict[str, int] = {k: 0 for k in order}
    for r in results:
        v = r.get("verdict", "ERROR")
        counts[v] = counts.get(v, 0) + 1

    print(f"\n{'='*62}")
    print(f"{BOLD}SCAN SUMMARY - {total} file(s){RESET}")
    print(f"{'='*62}")
    for verdict in order:
        n = counts.get(verdict, 0)
        if n:
            c = VERDICT_COLORS.get(verdict, "")
            print(f"  {c}{verdict:<12}{RESET} {n}")
    print(f"{'='*62}\n")
