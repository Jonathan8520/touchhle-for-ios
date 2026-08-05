#!/usr/bin/env python3
"""Disassemble a guest app around the addresses touchHLE complained about.

touchHLE reports guest addresses — the LR of an ignored UndefinedInstruction,
the PC of a bad branch — and on their own they say nothing. This prints the
instructions around them.

The main executable is loaded with a slide of zero (see Environment::new), so
the addresses in the log are the addresses in the binary and no adjustment is
needed. The low bit of an address selects Thumb, as it does in a real branch
target, and is honoured here.

Usage:
    dev-scripts/disassemble-guest.py <app.ipa | Foo.app | Mach-O> <address>...

Addresses are hexadecimal, with or without an 0x prefix. Requires capstone
(`pip install capstone`).
"""

import os
import plistlib
import struct
import sys
import zipfile

FAT_MAGIC = 0xCAFEBABE
MH_MAGIC = 0xFEEDFACE
CPU_TYPE_ARM = 12
CPU_SUBTYPE_ARM_V7 = 9
LC_SEGMENT = 0x1

WINDOW_BEFORE = 0x40
WINDOW_AFTER = 0x40


def die(message):
    sys.exit("disassemble-guest: " + message)


def find_executable(path):
    """Return the bytes of the Mach-O to look at, given an IPA, a .app or a
    Mach-O."""
    if os.path.isdir(path):
        with open(os.path.join(path, "Info.plist"), "rb") as info:
            name = plistlib.load(info)["CFBundleExecutable"]
        with open(os.path.join(path, name), "rb") as executable:
            return executable.read()

    with open(path, "rb") as candidate:
        head = candidate.read(4)
    # A fat binary starts with a big-endian FAT_MAGIC, a thin 32-bit one with
    # a little-endian MH_MAGIC. Anything else is taken to be an IPA.
    if head in (struct.pack(">I", FAT_MAGIC), struct.pack("<I", MH_MAGIC)):
        with open(path, "rb") as executable:
            return executable.read()

    # An IPA is a zip with one Payload/<name>.app.
    with zipfile.ZipFile(path) as ipa:
        names = ipa.namelist()
        plists = [n for n in names if n.count("/") == 2 and n.endswith(".app/Info.plist")]
        if not plists:
            die("no Payload/*.app/Info.plist in " + path)
        app_dir = plists[0][: -len("Info.plist")]
        executable_name = plistlib.loads(ipa.read(plists[0]))["CFBundleExecutable"]
        return ipa.read(app_dir + executable_name)


def armv7_slice(data):
    """Return the armv7 slice of a fat binary, or the whole thing if it is
    already thin."""
    (magic,) = struct.unpack_from(">I", data, 0)
    if magic != FAT_MAGIC:
        return data
    (count,) = struct.unpack_from(">I", data, 4)
    for i in range(count):
        cputype, cpusubtype, offset, size, _align = struct.unpack_from(
            ">iiIII", data, 8 + i * 20
        )
        if cputype == CPU_TYPE_ARM and cpusubtype == CPU_SUBTYPE_ARM_V7:
            return data[offset : offset + size]
    die("no armv7 slice in this binary")


def segments(data):
    """Yield (vmaddr, vmsize, fileoff, filesize) for every LC_SEGMENT."""
    magic, _cputype, _cpusubtype, _filetype, ncmds, _sizeofcmds, _flags = struct.unpack_from(
        "<IiiIIII", data, 0
    )
    if magic != MH_MAGIC:
        die("not a 32-bit little-endian Mach-O")
    offset = 28
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack_from("<II", data, offset)
        if cmd == LC_SEGMENT:
            _name, vmaddr, vmsize, fileoff, filesize = struct.unpack_from(
                "<16sIIII", data, offset + 8
            )
            yield vmaddr, vmsize, fileoff, filesize
        offset += cmdsize


def file_offset(data, address):
    for vmaddr, vmsize, fileoff, filesize in segments(data):
        if filesize and vmaddr <= address < vmaddr + vmsize:
            return fileoff + (address - vmaddr)
    return None


def main(argv):
    if len(argv) < 3:
        sys.exit(__doc__)

    try:
        import capstone
    except ImportError:
        die("capstone is not installed (pip install capstone)")

    data = armv7_slice(find_executable(argv[1]))

    for raw in argv[2:]:
        address = int(raw, 16)
        thumb = bool(address & 1)
        address &= ~1
        start = address - WINDOW_BEFORE
        offset = file_offset(data, start)
        print()
        print("=== {:#x} ({}) ===".format(address, "Thumb" if thumb else "ARM"))
        if offset is None:
            print("not inside any mapped segment")
            continue
        code = data[offset : offset + WINDOW_BEFORE + WINDOW_AFTER]
        mode = capstone.CS_MODE_THUMB if thumb else capstone.CS_MODE_ARM
        md = capstone.Cs(capstone.CS_ARCH_ARM, mode)
        for instruction in md.disasm(code, start):
            marker = "  <-- here" if instruction.address == address else ""
            print(
                "{:#010x}  {:<10} {}{}".format(
                    instruction.address,
                    instruction.mnemonic,
                    instruction.op_str,
                    marker,
                )
            )


if __name__ == "__main__":
    main(sys.argv)
