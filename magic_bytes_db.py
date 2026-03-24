"""
Magic Bytes Signature Database — Expanded Edition
Sources:
  - Wikipedia: List of file signatures (https://en.wikipedia.org/wiki/List_of_file_signatures)
  - Gary Kessler's File Signatures Table (filesig.search.org / garykessler.net)
  - libmagic / file(1) Magdir (github.com/file/file)
  - GitHub: Ilias1988/Magic-Bytes-List

Format per entry:
    (offset, bytes_pattern, label, mime_type, category, extensions_tuple)

offset         : byte offset in file where the signature starts
bytes_pattern  : raw bytes to match
label          : human-readable file type name
mime_type      : IANA / common MIME type
category       : broad category for grouping/display
extensions     : tuple of lowercase dot-prefixed extensions that legitimately match
"""

SIGNATURES = [

    # ── Images ──────────────────────────────────────────────────────────────
    (0,  b'\xFF\xD8\xFF\xDB',                "JPEG Image (raw)",           "image/jpeg",             "Image",        (".jpg", ".jpeg")),
    (0,  b'\xFF\xD8\xFF\xE0',                "JPEG/JFIF Image",            "image/jpeg",             "Image",        (".jpg", ".jpeg", ".jfif")),
    (0,  b'\xFF\xD8\xFF\xE1',                "JPEG/Exif Image",            "image/jpeg",             "Image",        (".jpg", ".jpeg")),
    (0,  b'\xFF\xD8\xFF\xEE',               "JPEG Image",                 "image/jpeg",             "Image",        (".jpg", ".jpeg")),
    (0,  b'\x89PNG\r\n\x1a\n',              "PNG Image",                  "image/png",              "Image",        (".png",)),
    (0,  b'GIF87a',                          "GIF Image (87a)",            "image/gif",              "Image",        (".gif",)),
    (0,  b'GIF89a',                          "GIF Image (89a)",            "image/gif",              "Image",        (".gif",)),
    (0,  b'BM',                              "BMP Image",                  "image/bmp",              "Image",        (".bmp", ".dib")),
    (0,  b'II*\x00',                         "TIFF Image (LE)",            "image/tiff",             "Image",        (".tif", ".tiff")),
    (0,  b'MM\x00*',                         "TIFF Image (BE)",            "image/tiff",             "Image",        (".tif", ".tiff")),
    (0,  b'II+\x00',                         "BigTIFF Image (LE)",         "image/tiff",             "Image",        (".tif", ".tiff")),
    (0,  b'MM\x00+',                         "BigTIFF Image (BE)",         "image/tiff",             "Image",        (".tif", ".tiff")),
    (0,  b'II*\x00\x10\x00\x00\x00CR',      "Canon CR2 RAW Image",        "image/x-canon-cr2",      "Image",        (".cr2",)),
    (0,  b'\x00\x00\x01\x00',               "ICO Image",                  "image/x-icon",           "Image",        (".ico",)),
    (0,  b'icns',                            "Apple ICNS Image",           "image/x-icns",           "Image",        (".icns",)),
    (0,  b'8BPS',                            "Photoshop PSD",              "image/vnd.adobe.photoshop","Image",      (".psd",)),
    (0,  b'qoif',                            "QOI Image",                  "image/x-qoi",            "Image",        (".qoi",)),
    (0,  b'FLIF',                            "FLIF Lossless Image",        "image/x-flif",           "Image",        (".flif",)),
    (0,  b'BPG\xFB',                         "BPG Image",                  "image/bpg",              "Image",        (".bpg",)),
    (0,  b'v/1\x01',                         "OpenEXR Image",              "image/x-exr",            "Image",        (".exr",)),
    (0,  b'SDPX',                            "DPX Image (BE)",             "image/x-dpx",            "Image",        (".dpx",)),
    (0,  b'XPDS',                            "DPX Image (LE)",             "image/x-dpx",            "Image",        (".dpx",)),
    (0,  b'\x80*_\xD7',                      "Kodak Cineon Image",         "image/x-cineon",         "Image",        (".cin",)),
    (0,  b'\x00\x00\x00\x0CjP  \r\n\x87\n', "JPEG 2000 Image",            "image/jp2",              "Image",        (".jp2", ".j2k", ".jpf", ".jpx", ".jpm", ".j2c", ".jpc", ".mj2")),
    (4,  b'ftypheic',                        "HEIC/HEIF Image",            "image/heic",             "Image",        (".heic", ".heif")),
    (0,  b'NURUIMG',                         "NURU ASCII Image",           "image/x-nuru",           "Image",        (".nui",)),
    (0,  b'AT&TFORM',                        "DjVu Document",              "image/vnd.djvu",         "Document",     (".djvu", ".djv")),

    # ── Audio ────────────────────────────────────────────────────────────────
    (0,  b'ID3',                             "MP3 Audio (ID3v2)",          "audio/mpeg",             "Audio",        (".mp3",)),
    (0,  b'\xFF\xFB',                        "MP3 Audio",                  "audio/mpeg",             "Audio",        (".mp3",)),
    (0,  b'\xFF\xF3',                        "MP3 Audio",                  "audio/mpeg",             "Audio",        (".mp3",)),
    (0,  b'\xFF\xF2',                        "MP3 Audio",                  "audio/mpeg",             "Audio",        (".mp3",)),
    (0,  b'fLaC',                            "FLAC Audio",                 "audio/flac",             "Audio",        (".flac",)),
    (0,  b'OggS',                            "OGG Container",              "audio/ogg",              "Audio",        (".ogg", ".oga", ".ogv")),
    (0,  b'MAC ',                            "Monkey's Audio (APE)",       "audio/ape",              "Audio",        (".ape",)),
    (0,  b'wvpk',                            "WavPack Audio",              "audio/x-wavpack",        "Audio",        (".wv",)),
    (0,  b'MThd',                            "MIDI Audio",                 "audio/midi",             "Audio",        (".mid", ".midi")),
    (0,  b'Creative Voice File',             "Creative Voice Audio",       "audio/x-voc",            "Audio",        (".voc",)),
    (0,  b'\x02dss',                         "DSS Audio v2",               "audio/dss",              "Audio",        (".dss",)),
    (0,  b'\x03dss',                         "DSS Audio v3",               "audio/dss",              "Audio",        (".dss",)),
    (0,  b'RIFF',                            "RIFF Container (WAV/AVI)",   "application/octet-stream","Container",   (".wav", ".avi", ".rmi")),

    # ── Video ─────────────────────────────────────────────────────────────────
    (4,  b'ftyp',                            "MP4/MOV/M4x Video",          "video/mp4",              "Video",        (".mp4", ".mov", ".m4v", ".m4a", ".m4p", ".m4b", ".f4v")),
    (4,  b'ftyp3g',                          "3GPP Media",                 "video/3gpp",             "Video",        (".3gp", ".3g2")),
    (0,  b'\x1A\x45\xDF\xA3',               "MKV/WebM Video",             "video/x-matroska",       "Video",        (".mkv", ".mka", ".mks", ".mk3d", ".webm")),
    (0,  b'FLV\x01',                         "Flash Video (FLV)",          "video/x-flv",            "Video",        (".flv",)),
    (0,  b'\x00\x00\x01\xB3',               "MPEG Video",                 "video/mpeg",             "Video",        (".mpeg", ".mpg")),
    (0,  b'\x00\x00\x01\xBA',               "MPEG-PS Video",              "video/mpeg",             "Video",        (".mpeg", ".mpg", ".vob")),
    (0,  b'MLVI',                            "Magic Lantern Video",        "video/x-mlv",            "Video",        (".mlv",)),
    (0,  b'30&\xB2u\x8Ef\xCF\x11\xA6\xD9\x00\xAA\x00b\xCEl', "ASF/WMA/WMV", "video/x-ms-asf",    "Media",        (".asf", ".wma", ".wmv")),

    # ── Documents ─────────────────────────────────────────────────────────────
    (0,  b'%PDF-',                           "PDF Document",               "application/pdf",        "Document",     (".pdf",)),
    (0,  b'\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1', "MS Office Legacy (DOC/XLS/PPT/MSG)", "application/msword","Document",(".doc", ".xls", ".ppt", ".msi", ".msg", ".mpp", ".pub", ".pps", ".pot")),
    (0,  b'PK\x03\x04',                     "ZIP / Office Open XML",      "application/zip",        "Archive",      (".zip", ".docx", ".xlsx", ".pptx", ".odt", ".ods", ".odp", ".odg", ".epub", ".jar", ".apk", ".ipa", ".xpi", ".kmz", ".pk3", ".pk4", ".usdz", ".vsdx", ".crx", ".maff", ".msix", ".aar", ".nupkg", ".whl")),
    (0,  b'PK\x05\x06',                     "ZIP Archive (empty)",        "application/zip",        "Archive",      (".zip",)),
    (0,  b'PK\x07\x08',                     "ZIP Archive (spanned)",      "application/zip",        "Archive",      (".zip",)),
    (0,  b'{\x5Crtf',                        "RTF Document",               "application/rtf",        "Document",     (".rtf",)),
    (0,  b'%!PS-Adobe-3.0 EPSF-3.0',        "EPS Document v3.0",          "application/postscript", "Document",     (".eps", ".epsf")),
    (0,  b'%!PS-Adobe-3.1 EPSF-3.0',        "EPS Document v3.1",          "application/postscript", "Document",     (".eps", ".epsf")),
    (0,  b'%!PS',                            "PostScript Document",        "application/postscript", "Document",     (".ps",)),
    (0,  b'ITSF\x03\x00\x00\x00\x60\x00\x00\x00', "CHM Help File",       "application/vnd.ms-htmlhelp","Document", (".chm",)),
    (0,  b'?\x5F',                           "Windows HLP File",           "application/winhlp",     "Document",     (".hlp",)),
    (0,  b'CWS',                             "Adobe Flash SWF (compressed)","application/x-shockwave-flash","Flash", (".swf",)),
    (0,  b'FWS',                             "Adobe Flash SWF (plain)",    "application/x-shockwave-flash","Flash",  (".swf",)),
    (0,  b'\x06\x06\xED\xF5\xD8\x1D\x46\xE5\xBD\x31\xEF\xE7\xFE\x74\xB7\x1D', "Adobe InDesign Document","application/x-indesign","Document",(".indd",)),
    (0,  b'\x06\x0E\x2B\x34',               "MXF Media Exchange Format",  "application/mxf",        "Media",        (".mxf",)),

    # ── Archives / Compressed ─────────────────────────────────────────────────
    (0,  b'Rar!\x1A\x07\x00',               "RAR Archive v1.5+",          "application/x-rar",      "Archive",      (".rar",)),
    (0,  b'Rar!\x1A\x07\x01\x00',           "RAR Archive v5+",            "application/x-rar",      "Archive",      (".rar",)),
    (0,  b'\x1F\x8B',                        "GZIP Compressed",            "application/gzip",       "Archive",      (".gz", ".tgz", ".tar.gz")),
    (0,  b'BZh',                             "BZIP2 Compressed",           "application/x-bzip2",    "Archive",      (".bz2", ".tar.bz2")),
    (0,  b'\xFD7zXZ\x00',                   "XZ Compressed",              "application/x-xz",       "Archive",      (".xz", ".tar.xz")),
    (0,  b'7z\xBC\xAF\x27\x1C',             "7-Zip Archive",              "application/x-7z-compressed","Archive",  (".7z",)),
    (0,  b'MSCF',                            "Microsoft CAB Archive",      "application/vnd.ms-cab-compressed","Archive",(".cab",)),
    (0,  b'LZIP',                            "LZIP Compressed",            "application/x-lzip",     "Archive",      (".lz",)),
    (0,  b'\x1F\x9D',                        "LZW Compressed (.Z)",        "application/x-compress", "Archive",      (".z", ".tar.z")),
    (0,  b'\x1F\xA0',                        "LZH Compressed (.Z)",        "application/x-lzh",      "Archive",      (".z",)),
    (0,  b'\x04"M\x18',                      "LZ4 Frame",                  "application/x-lz4",      "Archive",      (".lz4",)),
    (0,  b'\xB5\x2F\xFD',                   "Zstandard (zstd)",           "application/zstd",       "Archive",      (".zst",)),
    (0,  b'xar!',                            "XAR Archive",                "application/x-xar",      "Archive",      (".xar",)),
    (0,  b'SZDD\x88\xF0\x273',              "MS Quantum Compressed",      "application/octet-stream","Archive",      ("._",)),
    (0,  b'\x52\x4E\x43\x01',               "RNC Compressed v1",          "application/x-rnc",      "Archive",      ()),
    (0,  b'\x52\x4E\x43\x02',               "RNC Compressed v2",          "application/x-rnc",      "Archive",      ()),
    (2,  b'-lh0-',                           "LZH Archive (method 0)",     "application/x-lzh",      "Archive",      (".lzh", ".lha")),
    (2,  b'-lh5-',                           "LZH Archive (method 5)",     "application/x-lzh",      "Archive",      (".lzh", ".lha")),
    (0,  b'070701',                          "CPIO Archive (new ASCII)",   "application/x-cpio",     "Archive",      (".cpio",)),
    (0,  b'070702',                          "CPIO Archive (CRC)",         "application/x-cpio",     "Archive",      (".cpio",)),
    (0,  b'070707',                          "CPIO Archive (old ASCII)",   "application/x-cpio",     "Archive",      (".cpio",)),
    (257, b'ustar\x0000',                    "TAR Archive (POSIX)",        "application/x-tar",      "Archive",      (".tar",)),
    (257, b'ustar  \x00',                    "TAR Archive (GNU)",          "application/x-tar",      "Archive",      (".tar",)),

    # ── Executables / Binaries ────────────────────────────────────────────────
    (0,  b'MZ',                              "Windows PE/DOS Executable",  "application/x-msdownload","Executable",  (".exe", ".dll", ".sys", ".scr", ".mui", ".cpl", ".ocx", ".ax", ".iec", ".ime", ".rs", ".tsp", ".fon", ".efi", ".drv", ".msi", ".msp")),
    (0,  b'ZM',                              "DOS ZM Executable (rare)",   "application/x-msdownload","Executable",  (".exe",)),
    (0,  b'\x7FELF',                         "ELF Executable (Linux/Unix)","application/x-elf",      "Executable",   (".elf", ".so", ".o", ".out", ".ko", ".mod", ".axf", ".prx", ".puff")),
    (0,  b'\xFE\xED\xFA\xCE',               "Mach-O Binary (32-bit BE)",  "application/x-mach-binary","Executable", (".dylib", "")),
    (0,  b'\xFE\xED\xFA\xCF',               "Mach-O Binary (64-bit BE)",  "application/x-mach-binary","Executable", (".dylib", "")),
    (0,  b'\xCE\xFA\xED\xFE',               "Mach-O Binary (32-bit LE)",  "application/x-mach-binary","Executable", (".dylib", "")),
    (0,  b'\xCF\xFA\xED\xFE',               "Mach-O Binary (64-bit LE)",  "application/x-mach-binary","Executable", (".dylib", "")),
    (0,  b'\xCA\xFE\xBA\xBE',               "Java Class / Mach-O Fat Binary","application/java-vm", "Executable",   (".class",)),
    (0,  b'dex\n035\x00',                   "Dalvik DEX (Android)",       "application/x-dex",      "Executable",   (".dex",)),
    (0,  b'dex\n036\x00',                   "Dalvik DEX v36 (Android)",   "application/x-dex",      "Executable",   (".dex",)),
    (0,  b'dex\n037\x00',                   "Dalvik DEX v37 (Android)",   "application/x-dex",      "Executable",   (".dex",)),
    (0,  b'dex\n038\x00',                   "Dalvik DEX v38 (Android)",   "application/x-dex",      "Executable",   (".dex",)),
    (0,  b'dex\n039\x00',                   "Dalvik DEX v39 (Android)",   "application/x-dex",      "Executable",   (".dex",)),
    (0,  b'#!',                             "Script (Shebang)",           "text/x-shellscript",     "Script",       (".sh", ".bash", ".zsh", ".py", ".pl", ".rb")),
    (0,  b'!<arch>\n',                       "Linux DEB Package",          "application/vnd.debian.binary-package","Package",(".deb",)),
    (0,  b'\xED\xAB\xEE\xDB',              "RPM Package",                "application/x-rpm",      "Package",      (".rpm",)),
    (0,  b'\x00asm',                         "WebAssembly Binary",         "application/wasm",       "Executable",   (".wasm",)),
    (0,  b'Cr24',                            "Chrome Extension (CRX)",     "application/x-chrome-extension","Package",(".crx",)),
    (0,  b'NES\x1A',                         "NES ROM Image",              "application/x-nes-rom",  "ROM",          (".nes",)),

    # ── Disk Images ───────────────────────────────────────────────────────────
    (0,  b'KDM',                             "VMDK Disk Image",            "application/x-vmdk",     "Disk Image",   (".vmdk",)),
    (0,  b'# Disk Descriptor',               "VMDK Descriptor File",       "application/x-vmdk",     "Disk Image",   (".vmdk",)),
    (0,  b'conectix',                        "VHD Disk Image",             "application/x-vhd",      "Disk Image",   (".vhd",)),
    (0,  b'vhdxfile',                        "VHDX Disk Image",            "application/x-vhdx",     "Disk Image",   (".vhdx",)),
    (0,  b'QFI\xFB',                         "QCOW2 Disk Image",           "application/x-qemu-disk","Disk Image",   (".qcow2", ".qcow")),
    (0,  b'\x71\xFB',                        "QCOW Disk Image (v1)",       "application/x-qemu-disk","Disk Image",   (".qcow",)),
    (0,  b'koly',                            "Apple DMG Disk Image",       "application/x-apple-diskimage","Disk Image",(".dmg",)),
    (0,  b'ER\x02\x00\x00\x00',             "Roxio Toast Disc Image",     "application/x-toast",    "Disk Image",   (".toast",)),
    (0,  b'MSWIM\x00\x00\x00\xD0\x00\x00\x00\x00', "Windows WIM Image",  "application/x-ms-wim",   "Disk Image",   (".wim", ".swm", ".esd")),
    (0x8001, b'CD001',                       "ISO 9660 CD/DVD Image",      "application/x-iso9660-image","Disk Image",(".iso",)),

    # ── Databases ─────────────────────────────────────────────────────────────
    (0,  b'SQLite format 3\x00',            "SQLite Database",            "application/x-sqlite3",  "Database",     (".db", ".sqlite", ".sqlite3", ".sqlitedb", ".db3")),
    (0,  b'\x00\x01\x00\x00Standard Jet DB',"MS Access Database (.mdb)", "application/x-msaccess", "Database",     (".mdb",)),
    (0,  b'\x00\x01\x00\x00Standard ACE DB',"MS Access Database (.accdb)","application/x-msaccess","Database",     (".accdb",)),
    (0,  b'PWS3',                            "Password Gorilla DB",        "application/x-psafe3",   "Database",     (".psafe3",)),

    # ── Network Captures ──────────────────────────────────────────────────────
    (0,  b'\xD4\xC3\xB2\xA1',               "PCAP Capture (LE)",          "application/vnd.tcpdump.pcap","Network", (".pcap",)),
    (0,  b'\xA1\xB2\xC3\xD4',               "PCAP Capture (BE)",          "application/vnd.tcpdump.pcap","Network", (".pcap",)),
    (0,  b'\x4D\x3C\xB2\xA1',               "PCAP Nanosecond (LE)",       "application/vnd.tcpdump.pcap","Network", (".pcap",)),
    (0,  b'\x0A\x0D\x0D\x0A',               "PCAPng Capture",             "application/x-pcapng",   "Network",      (".pcapng",)),

    # ── Crypto / Certificates / Keys ─────────────────────────────────────────
    (0,  b'-----BEGIN CERTIFICATE-----',    "PEM Certificate",            "application/x-pem-file", "Crypto",       (".crt", ".pem", ".cer")),
    (0,  b'-----BEGIN CERTIFICATE REQUEST-----', "PEM CSR",               "application/x-pem-file", "Crypto",       (".csr", ".pem")),
    (0,  b'-----BEGIN PRIVATE KEY-----',    "PEM Private Key (PKCS#8)",   "application/x-pem-file", "Crypto",       (".key", ".pem")),
    (0,  b'-----BEGIN RSA PRIVATE KEY-----',"PEM RSA Private Key",        "application/x-pem-file", "Crypto",       (".key", ".pem")),
    (0,  b'-----BEGIN DSA PRIVATE KEY-----',"PEM DSA Private Key",        "application/x-pem-file", "Crypto",       (".key", ".pem")),
    (0,  b'-----BEGIN OPENSSH PRIVATE KEY-----', "OpenSSH Private Key",   "application/x-pem-file", "Crypto",       (".key", "")),
    (0,  b'-----BEGIN SSH2 PUBLIC KEY-----',"OpenSSH Public Key",         "application/x-pem-file", "Crypto",       (".pub",)),
    (0,  b'PuTTY-User-Key-File-2:',         "PuTTY Private Key v2",       "application/x-putty-key","Crypto",       (".ppk",)),
    (0,  b'PuTTY-User-Key-File-3:',         "PuTTY Private Key v3",       "application/x-putty-key","Crypto",       (".ppk",)),
    (0,  b'\x0A\x16org.bitcoin',            "MultiBit Bitcoin Wallet",    "application/x-bitcoin-wallet","Crypto",  (".wallet",)),

    # ── Fonts ─────────────────────────────────────────────────────────────────
    (0,  b'wOFF',                            "WOFF Font",                  "font/woff",              "Font",         (".woff",)),
    (0,  b'wOF2',                            "WOFF2 Font",                 "font/woff2",             "Font",         (".woff2",)),
    (0,  b'\x00\x01\x00\x00\x00',           "TrueType Font",              "font/ttf",               "Font",         (".ttf", ".tte", ".dfont")),
    (0,  b'OTTO',                            "OpenType Font",              "font/otf",               "Font",         (".otf",)),

    # ── Text / Markup ─────────────────────────────────────────────────────────
    (0,  b'\xEF\xBB\xBF',                   "UTF-8 BOM Text",             "text/plain",             "Text",         (".txt", ".xml", ".html", ".csv")),
    (0,  b'\xFF\xFE\x00\x00',               "UTF-32 LE BOM Text",         "text/plain",             "Text",         (".txt",)),
    (0,  b'\x00\x00\xFE\xFF',               "UTF-32 BE BOM Text",         "text/plain",             "Text",         (".txt",)),
    (0,  b'\xFF\xFE',                        "UTF-16 LE BOM Text",         "text/plain",             "Text",         (".txt", ".csv")),
    (0,  b'\xFE\xFF',                        "UTF-16 BE BOM Text",         "text/plain",             "Text",         (".txt", ".csv")),
    (0,  b'<?xml ',                          "XML Document",               "text/xml",               "Document",     (".xml", ".xsd", ".xsl", ".xslt", ".svg", ".rss", ".atom", ".xhtml")),
    (0,  b'<!DOCTYPE',                       "HTML Document",              "text/html",              "Document",     (".html", ".htm")),
    (0,  b'<html',                           "HTML Document",              "text/html",              "Document",     (".html", ".htm")),
    (0,  b'<HTML',                           "HTML Document",              "text/html",              "Document",     (".html", ".htm")),
    (0,  b'<?php',                           "PHP Script",                 "text/x-php",             "Script",       (".php", ".php3", ".php4", ".php5", ".phtml")),

    # ── Scientific / Data formats ─────────────────────────────────────────────
    (0,  b'\x0E\x03\x13\x01',               "HDF4 Data",                  "application/x-hdf",      "Data",         (".hdf4", ".h4", ".hdf")),
    (0,  b'\x89HDF\r\n\x1a\n',              "HDF5 Data",                  "application/x-hdf5",     "Data",         (".hdf5", ".h5", ".hdf")),
    (0,  b'SIMPLE  =',                       "FITS Astronomical Data",     "image/fits",             "Data",         (".fits", ".fit", ".fts")),
    (0,  b'DICM',                            "DICOM Medical Image",        "application/dicom",      "Medical",      (".dcm",)),  # normally at offset 128 but checking 0 for misnamed files

    # ── Game / ROM formats ────────────────────────────────────────────────────
    (0,  b'IWAD',                            "Doom IWAD Game Data",        "application/x-doom",     "Game",         (".wad",)),
    (0,  b'PWAD',                            "Doom PWAD Patch",            "application/x-doom",     "Game",         (".wad",)),
    (0,  b'GCR-1541',                        "C64 G64 Disk Image",         "application/octet-stream","ROM",         (".g64",)),
    (0,  b'C64 CARTRIDGE   ',                "C64 Cartridge Image",        "application/octet-stream","ROM",         (".crt",)),

    # ── Misc / Productivity ───────────────────────────────────────────────────
    (0,  b'bplist',                          "Apple Binary Property List", "application/x-bplist",   "Data",         (".plist",)),
    (0,  b'TDF$',                            "Telegram Desktop File",      "application/octet-stream","Messaging",   (".tdf",)),
    (0,  b'TDEF',                            "Telegram Desktop Encrypted", "application/octet-stream","Messaging",   (".tdef",)),
    (0,  b'SMSNF200',                        "SmartSniff Packets File",    "application/octet-stream","Network",     (".ssp",)),
    (0,  b'SP01',                            "Amazon Kindle Update",       "application/octet-stream","Firmware",    (".bin",)),
    (0,  b'\x00\x00\x02\x00\x06\x04\x06\x00', "Lotus 1-2-3 v1",          "application/x-lotus",    "Spreadsheet",  (".wk1",)),
    (0,  b'\x00\x00\x1A\x00\x00\x10\x04\x00', "Lotus 1-2-3 v3",          "application/x-lotus",    "Spreadsheet",  (".wk3",)),
    (0,  b'\x00\x00\x1A\x00\x02\x10\x04\x00', "Lotus 1-2-3 v4/5",        "application/x-lotus",    "Spreadsheet",  (".wk4", ".wk5")),
    (0,  b'\x00\x00\x1A\x00\x05\x10\x04',   "Lotus 1-2-3 v9",            "application/x-lotus",    "Spreadsheet",  (".123",)),
    (0,  b'\xBE\xBA\xFE\xCA',               "Palm DBA Archive",           "application/x-palm",     "PDA",          (".dba",)),
    (0,  b'\x00\x01\x42\x44',               "Palm To Do Archive",         "application/x-palm",     "PDA",          (".dba",)),
    (0,  b'\x00\x01\x44\x54',               "Palm Desktop Calendar",      "application/x-palm",     "PDA",          (".tda",)),
    (0,  b'PMOCCMOC',                        "Windows USMT Repository",    "application/octet-stream","System",      (".dat",)),
    (0,  b'MLVI',                            "Magic Lantern Video",        "video/x-mlv",            "Video",        (".mlv",)),
]

# ---------------------------------------------------------------------------
# EXTENSION → VALID TYPE LABELS MAP  (auto-built from SIGNATURES)
# ---------------------------------------------------------------------------
def _build_ext_map() -> dict[str, list[str]]:
    ext_map: dict[str, set[str]] = {}
    for entry in SIGNATURES:
        _, _, label, _, _, exts = entry
        for ext in exts:
            if ext:
                ext_map.setdefault(ext, set()).add(label)
    return {k: sorted(v) for k, v in ext_map.items()}

EXTENSION_TYPE_MAP: dict[str, list[str]] = _build_ext_map()

# ---------------------------------------------------------------------------
# HIGH-RISK DISGUISE PAIRS
# Format: (detected_label_substring, claimed_extension, risk_level, message)
# Substring matching is used so one entry covers multiple related labels.
# ---------------------------------------------------------------------------
HIGH_RISK_PAIRS: list[tuple[str, str, str, str]] = [

    # ── PE/ELF/Mach-O Executables disguised as anything ──────────────────────
    ("Executable",     ".jpg",  "CRITICAL", "Executable disguised as JPEG — classic malware dropper tactic"),
    ("Executable",     ".jpeg", "CRITICAL", "Executable disguised as JPEG"),
    ("Executable",     ".png",  "CRITICAL", "Executable disguised as PNG image"),
    ("Executable",     ".gif",  "CRITICAL", "Executable disguised as GIF image"),
    ("Executable",     ".bmp",  "HIGH",     "Executable disguised as BMP image"),
    ("Executable",     ".tif",  "HIGH",     "Executable disguised as TIFF image"),
    ("Executable",     ".tiff", "HIGH",     "Executable disguised as TIFF image"),
    ("Executable",     ".webp", "HIGH",     "Executable disguised as WebP image"),
    ("Executable",     ".ico",  "HIGH",     "Executable disguised as icon file"),
    ("Executable",     ".pdf",  "CRITICAL", "Executable disguised as PDF — common phishing payload"),
    ("Executable",     ".doc",  "CRITICAL", "Executable disguised as Word document"),
    ("Executable",     ".docx", "CRITICAL", "Executable disguised as Word document"),
    ("Executable",     ".xls",  "CRITICAL", "Executable disguised as Excel spreadsheet"),
    ("Executable",     ".xlsx", "CRITICAL", "Executable disguised as Excel spreadsheet"),
    ("Executable",     ".ppt",  "CRITICAL", "Executable disguised as PowerPoint file"),
    ("Executable",     ".pptx", "CRITICAL", "Executable disguised as PowerPoint file"),
    ("Executable",     ".txt",  "HIGH",     "Executable disguised as plain text file"),
    ("Executable",     ".csv",  "HIGH",     "Executable disguised as CSV file"),
    ("Executable",     ".log",  "MEDIUM",   "Executable disguised as log file"),
    ("Executable",     ".dat",  "MEDIUM",   "Executable disguised as data file"),
    ("Executable",     ".mp3",  "HIGH",     "Executable disguised as MP3 audio"),
    ("Executable",     ".mp4",  "HIGH",     "Executable disguised as MP4 video"),
    ("Executable",     ".avi",  "HIGH",     "Executable disguised as AVI video"),
    ("Executable",     ".mkv",  "HIGH",     "Executable disguised as MKV video"),
    ("Executable",     ".wav",  "HIGH",     "Executable disguised as WAV audio"),
    ("Executable",     ".flac", "HIGH",     "Executable disguised as FLAC audio"),
    ("Executable",     ".ogg",  "HIGH",     "Executable disguised as OGG audio"),
    ("Executable",     ".zip",  "MEDIUM",   "Executable disguised as ZIP archive"),
    ("Executable",     ".rar",  "MEDIUM",   "Executable disguised as RAR archive"),

    # ── Mach-O specifically ───────────────────────────────────────────────────
    ("Mach-O",         ".jpg",  "CRITICAL", "macOS/iOS binary disguised as JPEG image"),
    ("Mach-O",         ".png",  "CRITICAL", "macOS/iOS binary disguised as PNG image"),
    ("Mach-O",         ".pdf",  "CRITICAL", "macOS/iOS binary disguised as PDF"),
    ("Mach-O",         ".txt",  "HIGH",     "macOS/iOS binary disguised as text file"),
    ("Mach-O",         ".mp3",  "HIGH",     "macOS/iOS binary disguised as audio"),
    ("Mach-O",         ".mp4",  "HIGH",     "macOS/iOS binary disguised as video"),
    ("Mach-O",         ".docx", "CRITICAL", "macOS/iOS binary disguised as Word document"),

    # ── Dalvik / Android DEX ──────────────────────────────────────────────────
    ("Dalvik",         ".jpg",  "CRITICAL", "Android DEX executable disguised as image"),
    ("Dalvik",         ".pdf",  "CRITICAL", "Android DEX executable disguised as PDF"),
    ("Dalvik",         ".txt",  "HIGH",     "Android DEX executable disguised as text"),
    ("Dalvik",         ".mp3",  "HIGH",     "Android DEX executable disguised as audio"),
    ("Dalvik",         ".mp4",  "HIGH",     "Android DEX executable disguised as video"),
    ("Dalvik",         ".docx", "CRITICAL", "Android DEX disguised as Word document"),

    # ── Java Class / Mach-O Fat Binary ───────────────────────────────────────
    ("Java Class",     ".jpg",  "HIGH",     "Java bytecode / Fat Binary disguised as image"),
    ("Java Class",     ".pdf",  "HIGH",     "Java bytecode disguised as PDF"),
    ("Java Class",     ".txt",  "MEDIUM",   "Java bytecode disguised as text"),
    ("Java Class",     ".mp3",  "HIGH",     "Java bytecode disguised as audio"),

    # ── WebAssembly ───────────────────────────────────────────────────────────
    ("WebAssembly",    ".jpg",  "HIGH",     "WebAssembly binary disguised as image"),
    ("WebAssembly",    ".pdf",  "HIGH",     "WebAssembly binary disguised as PDF"),
    ("WebAssembly",    ".txt",  "MEDIUM",   "WebAssembly binary disguised as text file"),
    ("WebAssembly",    ".docx", "HIGH",     "WebAssembly binary disguised as Word document"),

    # ── Scripts (Shebang) ─────────────────────────────────────────────────────
    ("Script (Shebang)", ".jpg",  "CRITICAL", "Script file disguised as image"),
    ("Script (Shebang)", ".pdf",  "HIGH",     "Script file disguised as PDF"),
    ("Script (Shebang)", ".doc",  "HIGH",     "Script file disguised as Word document"),
    ("Script (Shebang)", ".mp3",  "HIGH",     "Script file disguised as audio"),
    ("Script (Shebang)", ".png",  "HIGH",     "Script file disguised as PNG image"),
    ("PHP Script",       ".jpg",  "CRITICAL", "PHP script disguised as image — web shell risk"),
    ("PHP Script",       ".png",  "CRITICAL", "PHP script disguised as image — web shell risk"),
    ("PHP Script",       ".gif",  "CRITICAL", "PHP script disguised as image — web shell risk"),
    ("PHP Script",       ".pdf",  "HIGH",     "PHP script disguised as PDF"),

    # ── ZIP-based archives and Office polyglots ───────────────────────────────
    ("ZIP",            ".jpg",  "HIGH",     "ZIP archive disguised as image — polyglot/exploit risk"),
    ("ZIP",            ".jpeg", "HIGH",     "ZIP archive disguised as JPEG"),
    ("ZIP",            ".png",  "HIGH",     "ZIP archive disguised as PNG"),
    ("ZIP",            ".gif",  "HIGH",     "ZIP archive disguised as GIF"),
    ("ZIP",            ".pdf",  "MEDIUM",   "ZIP archive disguised as PDF — possible exploit container"),
    ("ZIP",            ".txt",  "MEDIUM",   "ZIP archive disguised as text file"),
    ("ZIP",            ".mp3",  "MEDIUM",   "ZIP archive disguised as audio file"),
    ("ZIP",            ".mp4",  "MEDIUM",   "ZIP archive disguised as video file"),
    ("ZIP",            ".csv",  "MEDIUM",   "ZIP archive disguised as CSV"),

    ("RAR Archive",    ".jpg",  "HIGH",     "RAR archive disguised as image"),
    ("RAR Archive",    ".pdf",  "HIGH",     "RAR archive disguised as PDF"),
    ("RAR Archive",    ".doc",  "HIGH",     "RAR archive disguised as Word document"),
    ("RAR Archive",    ".mp3",  "MEDIUM",   "RAR archive disguised as audio"),
    ("RAR Archive",    ".txt",  "MEDIUM",   "RAR archive disguised as text"),

    ("7-Zip",          ".jpg",  "HIGH",     "7-Zip archive disguised as image"),
    ("7-Zip",          ".pdf",  "HIGH",     "7-Zip archive disguised as PDF"),
    ("7-Zip",          ".doc",  "HIGH",     "7-Zip archive disguised as Word document"),
    ("7-Zip",          ".txt",  "MEDIUM",   "7-Zip archive disguised as text"),

    ("GZIP",           ".jpg",  "HIGH",     "GZIP archive disguised as image"),
    ("GZIP",           ".pdf",  "MEDIUM",   "GZIP archive disguised as PDF"),
    ("GZIP",           ".doc",  "HIGH",     "GZIP archive disguised as Word document"),
    ("GZIP",           ".txt",  "LOW",      "GZIP archive disguised as text file"),

    ("BZIP2",          ".jpg",  "HIGH",     "BZIP2 archive disguised as image"),
    ("BZIP2",          ".pdf",  "MEDIUM",   "BZIP2 archive disguised as PDF"),

    # ── PDF disguised as other types ─────────────────────────────────────────
    ("PDF Document",   ".jpg",  "HIGH",     "PDF disguised as JPEG — possible exploit/polyglot"),
    ("PDF Document",   ".png",  "HIGH",     "PDF disguised as PNG image"),
    ("PDF Document",   ".gif",  "HIGH",     "PDF disguised as GIF image"),
    ("PDF Document",   ".txt",  "MEDIUM",   "PDF disguised as plain text"),
    ("PDF Document",   ".mp3",  "HIGH",     "PDF disguised as audio file"),
    ("PDF Document",   ".mp4",  "HIGH",     "PDF disguised as video file"),
    ("PDF Document",   ".csv",  "MEDIUM",   "PDF disguised as CSV"),
    ("PDF Document",   ".wav",  "HIGH",     "PDF disguised as WAV audio"),

    # ── MS Office Legacy (OLE) disguised ─────────────────────────────────────
    ("MS Office",      ".jpg",  "CRITICAL", "OLE/Office document disguised as image — macro delivery vector"),
    ("MS Office",      ".jpeg", "CRITICAL", "OLE/Office document disguised as JPEG"),
    ("MS Office",      ".png",  "CRITICAL", "OLE/Office document disguised as PNG"),
    ("MS Office",      ".gif",  "HIGH",     "OLE/Office document disguised as GIF"),
    ("MS Office",      ".txt",  "HIGH",     "OLE/Office document disguised as text file"),
    ("MS Office",      ".mp3",  "HIGH",     "OLE/Office document disguised as audio"),
    ("MS Office",      ".mp4",  "HIGH",     "OLE/Office document disguised as video"),
    ("MS Office",      ".pdf",  "HIGH",     "OLE/Office document disguised as PDF"),
    ("MS Office",      ".csv",  "HIGH",     "OLE/Office document disguised as CSV"),

    # ── Flash/SWF disguised ───────────────────────────────────────────────────
    ("Flash",          ".jpg",  "HIGH",     "Flash SWF disguised as image — possible exploit"),
    ("Flash",          ".pdf",  "HIGH",     "Flash SWF disguised as PDF"),
    ("Flash",          ".doc",  "HIGH",     "Flash SWF disguised as Word document"),
    ("Flash",          ".txt",  "MEDIUM",   "Flash SWF disguised as text"),
    ("Flash",          ".mp3",  "MEDIUM",   "Flash SWF disguised as audio"),

    # ── SQLite Database disguised ─────────────────────────────────────────────
    ("SQLite",         ".jpg",  "HIGH",     "SQLite database disguised as image — data exfiltration risk"),
    ("SQLite",         ".jpeg", "HIGH",     "SQLite database disguised as JPEG"),
    ("SQLite",         ".png",  "HIGH",     "SQLite database disguised as PNG"),
    ("SQLite",         ".txt",  "MEDIUM",   "SQLite database disguised as text file"),
    ("SQLite",         ".mp3",  "MEDIUM",   "SQLite database disguised as audio"),
    ("SQLite",         ".pdf",  "MEDIUM",   "SQLite database disguised as PDF"),
    ("SQLite",         ".csv",  "MEDIUM",   "SQLite database disguised as CSV"),

    # ── Network captures disguised ────────────────────────────────────────────
    ("PCAP",           ".jpg",  "HIGH",     "Network capture disguised as image — possible data exfil"),
    ("PCAP",           ".pdf",  "MEDIUM",   "Network capture disguised as PDF"),
    ("PCAP",           ".txt",  "LOW",      "Network capture disguised as text file"),
    ("PCAP",           ".mp3",  "MEDIUM",   "Network capture disguised as audio"),
    ("PCAP",           ".docx", "HIGH",     "Network capture disguised as Word document"),

    # ── Disk images / ISOs disguised ─────────────────────────────────────────
    ("ISO 9660",       ".jpg",  "HIGH",     "CD/DVD ISO image disguised as JPEG"),
    ("ISO 9660",       ".pdf",  "MEDIUM",   "CD/DVD ISO image disguised as PDF"),
    ("ISO 9660",       ".mp3",  "HIGH",     "CD/DVD ISO image disguised as audio"),
    ("VMDK",           ".jpg",  "HIGH",     "VM disk image disguised as image file"),
    ("VMDK",           ".pdf",  "HIGH",     "VM disk image disguised as PDF"),
    ("VHD",            ".jpg",  "HIGH",     "VHD disk image disguised as image file"),
    ("QCOW",           ".jpg",  "HIGH",     "QEMU disk image disguised as image file"),
    ("Apple DMG",      ".jpg",  "HIGH",     "Apple DMG disguised as image"),
    ("Apple DMG",      ".pdf",  "HIGH",     "Apple DMG disguised as PDF"),

    # ── Crypto keys disguised ─────────────────────────────────────────────────
    ("Private Key",    ".jpg",  "HIGH",     "Private key disguised as image — data theft artifact"),
    ("Private Key",    ".pdf",  "MEDIUM",   "Private key disguised as PDF"),
    ("Private Key",    ".mp3",  "HIGH",     "Private key disguised as audio file"),
    ("Private Key",    ".txt",  "LOW",      "Private key with .txt extension"),
    ("Private Key",    ".csv",  "MEDIUM",   "Private key disguised as CSV"),
    ("OpenSSH",        ".jpg",  "HIGH",     "SSH key disguised as image"),
    ("OpenSSH",        ".pdf",  "HIGH",     "SSH key disguised as PDF"),
    ("OpenSSH",        ".mp3",  "HIGH",     "SSH key disguised as audio"),
    ("PuTTY",          ".jpg",  "HIGH",     "PuTTY key disguised as image"),
    ("Certificate",    ".jpg",  "MEDIUM",   "Certificate disguised as image"),
    ("Bitcoin Wallet", ".jpg",  "HIGH",     "Bitcoin wallet disguised as image — financial data exfil"),
    ("Bitcoin Wallet", ".pdf",  "HIGH",     "Bitcoin wallet disguised as PDF"),

    # ── Java / Dalvik in APK context ─────────────────────────────────────────
    ("Java Class",     ".jpg",  "HIGH",     "Java class file disguised as image"),
    ("Java Class",     ".pdf",  "HIGH",     "Java class file disguised as PDF"),

    # ── DEB/RPM packages disguised ───────────────────────────────────────────
    ("DEB Package",    ".jpg",  "HIGH",     "Linux DEB package disguised as image"),
    ("DEB Package",    ".pdf",  "HIGH",     "Linux DEB package disguised as PDF"),
    ("DEB Package",    ".txt",  "MEDIUM",   "Linux DEB package disguised as text"),
    ("RPM Package",    ".jpg",  "HIGH",     "RPM package disguised as image"),
    ("RPM Package",    ".pdf",  "HIGH",     "RPM package disguised as PDF"),
]


def lookup_risk(detected_label: str, ext: str) -> tuple[str, str] | None:
    """
    Returns (risk_level, message) if a high-risk disguise pattern matches.
    Uses case-insensitive substring matching on detected_label.
    """
    for contains, risk_ext, risk_level, msg in HIGH_RISK_PAIRS:
        if ext == risk_ext and contains.lower() in detected_label.lower():
            return risk_level, msg
    return None
