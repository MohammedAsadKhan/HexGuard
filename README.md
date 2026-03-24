# HexGuard: Binary File Identifier

**HexGuard** is a lightweight Python-based defensive tool designed to identify the true identity of a file by analyzing its **magic bytes** (file signatures). 

I developed this tool after repeatedly encountering "file upload" and "forensics" challenges in various CTFs where attackers disguised malicious executables as harmless images. While manual hex editing works, HexGuard automates this process for active defense and rapid triage.

---

## ### Why HexGuard?
In both CTFs and real-world malware analysis, file extensions can be misleading. An adversary might rename `malware.exe` to `vacation_photos.jpg` to bypass basic security filters or trick a user. HexGuard ignores the extension and looks directly at the file header to verify the file’s integrity.



## ### Core Features
* **Header Analysis:** Reads the initial bytes of a file to determine its true format.
* **Extension Validation:** Compares the detected file type against the provided extension and flags mismatches.
* **CTF Optimized:** Built to quickly identify common obscured file types (ELF, PE, JPG, PNG, PDF, etc.).
* **Active Defense Ready:** Can be integrated into automated pipelines to identify and log suspicious file uploads.

## ### How It Works
The tool reads the binary data at the start of a file and compares it against a dictionary of known signatures. 

For example, a **PNG** file will always begin with the hex sequence:  
`89 50 4E 47 0D 0A 1A 0A`

If a file is named `invoice.pdf` but starts with `4D 5A` (the magic bytes for a Windows Executable), HexGuard will immediately flag it as an evasion attempt.

## ### Getting Started

### **Prerequisites**
* Python 3.x

### **Installation**
```bash
git clone [https://github.com/MohammedAsadKhan/HexGuard.git](https://github.com/MohammedAsadKhan/HexGuard.git)
cd HexGuard
```

### **Usage**
```bash
python hexguard.py <filename>
```

---
*Developed as a utility for CTF forensics and automated threat detection.*
```
