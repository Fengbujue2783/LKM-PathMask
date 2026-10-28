#!/usr/bin/env python3
# Build a minimal arm64 ELF + a plausible auxv with arm64-ish AT_PLATFORM.
import struct

# 64-byte ELF header for EM_AARCH64, ET_EXEC, no program headers
ehdr = bytearray(64)
ehdr[0:4] = b"\x7fELF"
ehdr[4] = 2        # ELFCLASS64
ehdr[5] = 1        # LSB
ehdr[6] = 1        # version
ehdr[7] = 0        # sysv
struct.pack_into("<H", ehdr, 16, 2)     # e_type = ET_EXEC
struct.pack_into("<H", ehdr, 18, 0xB7)  # e_machine = EM_AARCH64
struct.pack_into("<I", ehdr, 20, 1)     # e_version
struct.pack_into("<Q", ehdr, 24, 0x400000)  # e_entry
struct.pack_into("<Q", ehdr, 32, 64)     # e_phoff (bogus but harmless)
struct.pack_into("<Q", ehdr, 48, 64)     # e_ehsize
struct.pack_into("<H", ehdr, 56, 56)     # e_phentsize
struct.pack_into("<H", ehdr, 58, 0)      # e_phnum
open(r"D:\Downloads\Heytea\work\fake_exe", "wb").write(bytes(ehdr))

# auxv: AT_PAGESZ, AT_UID/GID, AT_SECURE=0, AT_RANDOM ptr, AT_HWCAP arm,
# AT_PLATFORM -> "aarch64", AT_EXECFN -> "/system/bin/dalvikvm64", AT_NULL
entries = []
def ent(tag, val): entries.append(struct.pack("<QQ", tag, val))
AT_NULL, AT_PAGESZ, AT_HWCAP, AT_CLKTCK = 0, 6, 16, 17
AT_PHDR, AT_PHENT, AT_PHNUM, AT_BASE, AT_FLAGS = 3, 4, 5, 7, 8
AT_ENTRY, AT_UID, AT_EUID, AT_GID, AT_EGID = 9, 11, 12, 13, 14
AT_SECURE, AT_RANDOM, AT_HWCAP2, AT_EXECFN, AT_PLATFORM = 23, 25, 26, 31, 15
ent(AT_PAGESZ, 4096)
ent(AT_CLKTCK, 100)
ent(AT_PHDR, 0x400040)
ent(AT_PHENT, 56)
ent(AT_PHNUM, 4)
ent(AT_BASE, 0)
ent(AT_FLAGS, 0)
ent(AT_ENTRY, 0x543210)
ent(AT_UID, 10065)
ent(AT_EUID, 10065)
ent(AT_GID, 10065)
ent(AT_EGID, 10065)
ent(AT_SECURE, 0)
ent(AT_RANDOM, 0x7ffffffff000)
ent(AT_HWCAP, 0x3ffffffff)   # plenty of arm64 caps
ent(AT_HWCAP2, 0)
ent(AT_EXECFN, 0x7fffffff0000)
ent(AT_PLATFORM, 0x7fffffff0100)
ent(AT_NULL, 0)
blob = b"".join(entries)
blob += b"aarch64\x00"                      # at AT_PLATFORM pointer
blob += b"/system/bin/dalvikvm64\x00"       # at AT_EXECFN pointer
open(r"D:\Downloads\Heytea\work\fake_auxv", "wb").write(blob)
print("fake_exe:", len(ehdr), "bytes; fake_auxv:", len(blob), "bytes")
