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
    dev-scripts/disassemble-guest.py --xref <app.ipa | ...> <address>...

`--xref` answers the other question: not "what is at this address" but
"what code reaches it". It sweeps every executable section following the
`movw`/`movt`/`add rD,pc` triples that position-independent code uses to
form a data address, and reports each site that forms one of the given
addresses, saying whether it goes on to read it or write it. That is how
you find who is supposed to fill in a global that turned out to be zero.

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
LC_SYMTAB = 0x2
LC_DYSYMTAB = 0xB
VM_PROT_EXECUTE = 0x4

SECTION_TYPE = 0xFF
S_ZEROFILL = 0x1
S_NON_LAZY_SYMBOL_POINTERS = 0x6
S_LAZY_SYMBOL_POINTERS = 0x7
S_SYMBOL_STUBS = 0x8
S_GB_ZEROFILL = 0xC
S_THREAD_LOCAL_ZEROFILL = 0x12
POINTER_SECTION_TYPES = (
    S_NON_LAZY_SYMBOL_POINTERS,
    S_LAZY_SYMBOL_POINTERS,
    S_SYMBOL_STUBS,
)
# These have no bytes in the file at all; the loader zeroes them.
ZEROFILL_SECTION_TYPES = (S_ZEROFILL, S_GB_ZEROFILL, S_THREAD_LOCAL_ZEROFILL)

N_STAB = 0xE0
N_TYPE = 0x0E
N_SECT = 0xE

INDIRECT_SYMBOL_LOCAL = 0x80000000
INDIRECT_SYMBOL_ABS = 0x40000000

WINDOW_BEFORE = 0xC0
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


def load_commands(data):
    """Yield (cmd, offset, cmdsize) for every load command."""
    magic, _cputype, _cpusubtype, _filetype, ncmds, _sizeofcmds, _flags = struct.unpack_from(
        "<IiiIIII", data, 0
    )
    if magic != MH_MAGIC:
        die("not a 32-bit little-endian Mach-O")
    offset = 28
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack_from("<II", data, offset)
        if cmdsize == 0:
            break
        yield cmd, offset, cmdsize
        offset += cmdsize


def segments(data):
    """Yield (vmaddr, vmsize, fileoff, filesize, initprot) for every
    LC_SEGMENT."""
    for cmd, offset, _cmdsize in load_commands(data):
        if cmd == LC_SEGMENT:
            _name, vmaddr, vmsize, fileoff, filesize, _maxprot, initprot = (
                struct.unpack_from("<16sIIIIii", data, offset + 8)
            )
            yield vmaddr, vmsize, fileoff, filesize, initprot


def sections(data):
    """Yield one dict per section, across every LC_SEGMENT.

    A 32-bit section header is 68 bytes and the headers follow their
    segment command inline, `nsects` of them."""
    for cmd, offset, _cmdsize in load_commands(data):
        if cmd != LC_SEGMENT:
            continue
        segname, _vmaddr, _vmsize, _fileoff, _filesize, _maxprot, _initprot, nsects, _fl = (
            struct.unpack_from("<16sIIIIiiII", data, offset + 8)
        )
        at = offset + 56
        for _ in range(nsects):
            sectname, _sn, addr, size, _off, _align, _reloff, _nreloc, flags, r1, r2 = (
                struct.unpack_from("<16s16sIIIIIIIII", data, at)
            )
            yield {
                "segment": segname.rstrip(b"\0").decode("ascii", "replace"),
                "name": sectname.rstrip(b"\0").decode("ascii", "replace"),
                "addr": addr,
                "size": size,
                "type": flags & SECTION_TYPE,
                "reserved1": r1,
                "reserved2": r2,
            }
            at += 68


# Parsing the symbol tables of a 30 MB binary is not free and every
# annotated instruction wants them, so they are built once. `data` is kept
# alive by main() for the whole run, which is what makes id() safe here.
_TABLES = {}


def tables(data):
    """Address -> symbol name, for defined symbols and for the imported
    ones reached through a pointer slot or a stub."""
    cached = _TABLES.get(id(data))
    if cached is not None:
        return cached

    defined = {}
    undefined_names = []
    indirect = {}

    symoff = nsyms = stroff = strsize = 0
    indirect_off = nindirect = 0
    for cmd, offset, _cmdsize in load_commands(data):
        if cmd == LC_SYMTAB:
            symoff, nsyms, stroff, strsize = struct.unpack_from("<IIII", data, offset + 8)
        elif cmd == LC_DYSYMTAB:
            indirect_off, nindirect = struct.unpack_from("<II", data, offset + 56)

    def string_at(index):
        if index == 0 or stroff + index >= stroff + strsize:
            return None
        start = stroff + index
        end = data.find(b"\0", start, stroff + strsize)
        if end < 0:
            return None
        return data[start:end].decode("ascii", "replace") or None

    # An nlist is {n_strx, n_type, n_sect, n_desc, n_value} = 12 bytes. A
    # symbol is only an address if it is N_SECT and not a debug entry.
    all_symbols = []
    for i in range(nsyms):
        at = symoff + i * 12
        if at + 12 > len(data):
            break
        n_strx, n_type, _n_sect, _n_desc, n_value = struct.unpack_from("<IBBhI", data, at)
        name = string_at(n_strx)
        all_symbols.append(name)
        if name is None or n_type & N_STAB:
            continue
        if (n_type & N_TYPE) == N_SECT and n_value:
            defined.setdefault(n_value, name)

    # Pointer slots and stubs do not carry their symbol; each is the nth
    # entry of its section, and `reserved1` says where that section starts
    # in the indirect symbol table.
    for section in sections(data):
        if section["type"] not in POINTER_SECTION_TYPES:
            continue
        stride = section["reserved2"] if section["type"] == S_SYMBOL_STUBS else 4
        if not stride:
            continue
        for slot in range(section["size"] // stride):
            index = section["reserved1"] + slot
            if index >= nindirect:
                break
            (symbol_index,) = struct.unpack_from("<I", data, indirect_off + index * 4)
            if symbol_index & (INDIRECT_SYMBOL_LOCAL | INDIRECT_SYMBOL_ABS):
                continue
            if symbol_index >= len(all_symbols):
                continue
            name = all_symbols[symbol_index]
            if name is None:
                continue
            indirect[section["addr"] + slot * stride] = (name, section["name"])
            undefined_names.append(name)

    built = {"defined": defined, "indirect": indirect}
    _TABLES[id(data)] = built
    return built


def section_for(data, address):
    for section in sections(data):
        if section["addr"] <= address < section["addr"] + section["size"]:
            return section
    return None


def symbol_for(data, address):
    """The best name for `address`: an import slot, an exact symbol, or a
    symbol plus an offset."""
    built = tables(data)
    entry = built["indirect"].get(address)
    if entry is not None:
        name, section_name = entry
        return "{} [{}]".format(name, section_name)
    defined = built["defined"]
    exact = defined.get(address)
    if exact is not None:
        return exact
    # Thumb function symbols carry the low bit; a call target does too, so
    # both spellings have to be tried.
    exact = defined.get(address | 1)
    if exact is not None:
        return exact
    # Falling back to the nearest preceding symbol only makes sense inside
    # a function. In data it would attach the name of whatever happened to
    # be defined earlier, which says nothing.
    if not is_executable(data, address):
        return None
    best = None
    for symbol_address, name in defined.items():
        base = symbol_address & ~1
        if base <= address and (best is None or base > best[0]):
            best = (base, name)
    if best is None or address - best[0] > 0x2000:
        return None
    if address == best[0]:
        return best[1]
    return "{}+{:#x}".format(best[1], address - best[0])


def is_zerofill(data, address):
    """Whether `address` is in a section the loader zeroes rather than one
    the file supplies. __bss and __common are the usual ones, and a
    function pointer living there is an uninitialised global, not an
    import waiting to be bound."""
    section = section_for(data, address)
    return section is not None and section["type"] in ZEROFILL_SECTION_TYPES


def file_offset(data, address):
    for vmaddr, vmsize, fileoff, filesize, _initprot in segments(data):
        if not filesize or not vmaddr <= address < vmaddr + vmsize:
            continue
        # A segment's vmsize can exceed its filesize: the tail is zero-fill
        # with nothing behind it. Mapping it to a file offset anyway would
        # read whatever bytes happen to follow in the file and report them
        # as the contents of a variable.
        if address - vmaddr >= filesize:
            return None
        return fileoff + (address - vmaddr)
    return None


def is_executable(data, address):
    for vmaddr, vmsize, _fileoff, filesize, initprot in segments(data):
        if filesize and vmaddr <= address < vmaddr + vmsize:
            return bool(initprot & VM_PROT_EXECUTE)
    return False


def c_string_at(data, address, limit=192):
    """The NUL-terminated printable string at `address`, if there is one.

    Used to turn a selector reference into a selector name: the reference
    holds a pointer, and the pointer leads to the name."""
    offset = file_offset(data, address)
    if offset is None:
        return None
    end = data.find(b"\0", offset, offset + limit)
    if end <= offset:
        return None
    try:
        text = data[offset:end].decode("ascii")
    except UnicodeDecodeError:
        return None
    return text if text.isprintable() else None


def describe_pointer(data, address):
    """What the word at `address` is, and what it points at."""
    slot = tables(data)["indirect"].get(address)
    if slot is None and is_zerofill(data, address):
        section = section_for(data, address)
        return (
            "in {},{}: zero-filled at load. Nothing binds this — it is an "
            "uninitialised global, and it reads as 0 until the app writes it.".format(
                section["segment"], section["name"]
            )
        )
    offset = file_offset(data, address)
    if offset is None or offset + 4 > len(data):
        return None
    (word,) = struct.unpack_from("<I", data, offset)
    if slot is not None:
        name, section_name = slot
        return "{} slot for {} (holds {:#x})".format(section_name, name, word)
    if word == 0:
        return "holds 0 (bound at load time — an external symbol)"
    text = c_string_at(data, word)
    if text is not None:
        return "holds {:#x} -> {!r}".format(word, text)
    name = class_name_at(data, word)
    if name is not None:
        return "holds {:#x} -> class {!r}".format(word, name)
    name = symbol_for(data, word)
    if name is not None:
        return "holds {:#x} -> {}".format(word, name)
    return "holds {:#x}".format(word)


def read_word(data, address):
    offset = file_offset(data, address)
    if offset is None or offset + 4 > len(data):
        return None
    (word,) = struct.unpack_from("<I", data, offset)
    return word


def class_name_at(data, address):
    """The name of the Objective-C class object at `address`, if it is one.

    32-bit ObjC2 lays a class out as {isa, superclass, cache, vtable, data},
    and the read-only part it points at as {flags, instanceStart,
    instanceSize, ivarLayout, name, ...}, so the name is two hops away at
    +0x10 each."""
    class_ro = read_word(data, address + 0x10)
    if not class_ro:
        return None
    name_ptr = read_word(data, class_ro + 0x10)
    if not name_ptr:
        return None
    return c_string_at(data, name_ptr, limit=128)


def describe_slot(data, slot):
    """A parenthesised note about what lives at `slot`, or nothing."""
    section = section_for(data, slot)
    entry = tables(data)["indirect"].get(slot)
    if entry is not None:
        name, section_name = entry
        return " ({}, {})".format(name, section_name)
    if is_zerofill(data, slot):
        return " (in {},{}: zero-filled at load, so an uninitialised global — nothing binds it)".format(
            section["segment"], section["name"]
        )
    word = read_word(data, slot)
    if word is None:
        return " (outside the file)"
    where = ", in {},{}".format(section["segment"], section["name"]) if section else ""
    name = symbol_for(data, word) or symbol_for(data, word & ~1)
    if name is not None:
        return " (holds {:#x} = {}{})".format(word, name, where)
    if word == 0:
        return " (holds 0 in the file: filled in at load time{})".format(where)
    return " (holds {:#x}{})".format(word, where)


def literal_address(capstone, instruction, thumb):
    """The address a `[pc, #imm]` load reads from, if this is one.

    The PC an instruction sees is two instructions ahead, and in Thumb the
    result is then rounded down to a word boundary."""
    for operand in instruction.operands:
        if operand.type != capstone.arm.ARM_OP_MEM:
            continue
        if operand.mem.base != capstone.arm.ARM_REG_PC or operand.mem.index != 0:
            continue
        if thumb:
            return ((instruction.address + 4) & ~3) + operand.mem.disp
        return instruction.address + 8 + operand.mem.disp
    return None


def track(capstone, instruction, thumb, known, from_slot):
    """Follow the three instructions that build a PC-relative address.

    Position-independent Thumb-2 code reaches a data slot as
    `movw rD,#lo; movt rD,#hi; add rD,pc`, and only loads through it
    afterwards. `known` maps a register to the constant it holds and
    `from_slot` remembers which slot a loaded value came from, which is
    what lets a later `blx rD` say what it is calling.

    Anything else that writes a register clears what was known about it,
    so a stale value is never carried forward onto an unrelated use."""
    arm = capstone.arm
    operands = instruction.operands
    mnemonic = instruction.mnemonic

    def is_reg(operand, register):
        return operand.type == arm.ARM_OP_REG and operand.reg == register

    handled = False
    if mnemonic == "movw" and len(operands) == 2 and operands[1].type == arm.ARM_OP_IMM:
        known[operands[0].reg] = operands[1].imm & 0xFFFF
        handled = True
    elif mnemonic == "movt" and len(operands) == 2 and operands[1].type == arm.ARM_OP_IMM:
        low = known.get(operands[0].reg, 0) & 0xFFFF
        known[operands[0].reg] = low | ((operands[1].imm & 0xFFFF) << 16)
        handled = True
    elif mnemonic == "add" and len(operands) == 2 and is_reg(operands[1], arm.ARM_REG_PC):
        base = known.get(operands[0].reg)
        if base is not None:
            # The PC an instruction sees is two instructions ahead.
            pc = instruction.address + (4 if thumb else 8)
            known[operands[0].reg] = (base + pc) & 0xFFFFFFFF
            handled = True
    elif (
        mnemonic.startswith("ldr")
        and len(operands) == 2
        and operands[1].type == arm.ARM_OP_MEM
        and operands[1].mem.index == 0
        and operands[1].mem.disp == 0
    ):
        slot = known.get(operands[1].mem.base)
        if slot is not None:
            from_slot[operands[0].reg] = slot
            known.pop(operands[0].reg, None)
            handled = True

    if not handled:
        _read, written = instruction.regs_access()
        for register in written:
            known.pop(register, None)
            from_slot.pop(register, None)


def annotate(capstone, data, instruction, thumb, known, from_slot):
    """What is worth saying about one instruction, if anything.

    Three things carry the answer to "what did it call": the literal a
    `ldr rN, [pc, #imm]` loads, the slot a tracked `ldr rN, [rM]` reads,
    and the target of a direct branch."""
    arm = capstone.arm
    operands = instruction.operands

    # `blx rN` / `bx rN` where rN was loaded from a slot we followed.
    if instruction.mnemonic in ("blx", "bx") and operands:
        if operands[0].type == arm.ARM_OP_REG:
            slot = from_slot.get(operands[0].reg)
            if slot is not None:
                return "calls through the pointer at {:#x}{}".format(
                    slot, describe_slot(data, slot)
                )

    if (
        instruction.mnemonic.startswith("ldr")
        and len(operands) == 2
        and operands[1].type == arm.ARM_OP_MEM
        and operands[1].mem.index == 0
        and operands[1].mem.disp == 0
        and known.get(operands[1].mem.base) is not None
    ):
        slot = known[operands[1].mem.base]
        return "reads {:#x}{}".format(slot, describe_slot(data, slot))

    literal = literal_address(capstone, instruction, thumb)
    if literal is not None:
        word = read_word(data, literal)
        if word is None:
            return "literal at {:#x} is outside the file".format(literal)
        note = "= [{:#x}] = {:#x}".format(literal, word)
        name = symbol_for(data, word) or symbol_for(data, word & ~1)
        if name is not None:
            return "{} ({})".format(note, name)
        text = c_string_at(data, word)
        if text is not None:
            return "{} ({!r})".format(note, text)
        described = describe_pointer(data, word)
        if described is not None and not described.startswith("holds"):
            return "{} ({})".format(note, described)
        return note

    if instruction.mnemonic.startswith(("bl", "b.", "b")) and instruction.operands:
        operand = instruction.operands[0]
        if operand.type == capstone.arm.ARM_OP_IMM:
            name = symbol_for(data, operand.imm)
            if name is not None:
                return "-> {}".format(name)
    return None


def disassemble_window(md, data, address, thumb):
    """Instructions around `address`, decoded from a start that lands on it.

    There is no way to know where the instruction before a given one
    begins, so the window has to start at a guess. A guess that is wrong
    decodes into something that never contains `address` at all, and the
    movw/movt pair the annotation depends on would be misread. Try each
    start in turn and keep the earliest one that does land on `address`,
    since that is the one with the most context before it."""
    fallback = None
    for back in range(WINDOW_BEFORE, -1, -2):
        start = address - back
        offset = file_offset(data, start)
        if offset is None:
            continue
        code = data[offset : offset + back + WINDOW_AFTER]
        instructions = list(md.disasm(code, start))
        if any(instruction.address == address for instruction in instructions):
            return instructions
        if fallback is None:
            fallback = instructions
    return fallback or []


def executable_sections(data):
    for section in sections(data):
        if section["type"] in ZEROFILL_SECTION_TYPES or not section["size"]:
            continue
        if is_executable(data, section["addr"]):
            yield section


def xref(capstone, data, targets):
    """Report every site that forms one of `targets` as a PC-relative address.

    A linear sweep, because there is no map of where the functions are. It
    desynchronises on data mixed into the code, but Thumb re-synchronises
    within an instruction or two, so a missed site is the exception rather
    than the rule. Each hit is worth confirming with a normal disassembly
    of the address it reports."""
    arm = capstone.arm
    md = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_THUMB)
    md.detail = True
    found = {target: [] for target in targets}
    wanted = set(targets)

    for section in executable_sections(data):
        offset = file_offset(data, section["addr"])
        if offset is None:
            continue
        code = data[offset : offset + section["size"]]
        print(
            "sweeping {},{} ({} bytes from {:#x})".format(
                section["segment"], section["name"], len(code), section["addr"]
            ),
            file=sys.stderr,
        )
        known, from_slot = {}, {}
        pending = {}
        # A `str rX, [rD]` does not write rD, so without this the register
        # would still hold the address on the next instruction and the same
        # site would be reported again.
        consumed = {}
        for instruction in md.disasm(code, section["addr"]):
            # A register that has just become one of the targets was formed
            # by the `add rD,pc` on this line; what happens to it next says
            # whether this site reads the global or writes it.
            operands = instruction.operands
            if pending:
                for register, (site, value) in list(pending.items()):
                    action = None
                    if (
                        len(operands) == 2
                        and operands[1].type == arm.ARM_OP_MEM
                        and operands[1].mem.base == register
                    ):
                        if instruction.mnemonic.startswith("str"):
                            action = "writes"
                        elif instruction.mnemonic.startswith("ldr"):
                            action = "reads"
                    if action is not None:
                        found[value].append((site, action, instruction.address))
                        del pending[register]
                        consumed[register] = value
                    elif instruction.address - site > 0x40:
                        found[value].append((site, "forms", None))
                        del pending[register]
                        consumed[register] = value

            track(capstone, instruction, True, known, from_slot)
            for register, value in known.items():
                if value in wanted and register not in pending:
                    if consumed.get(register) != value:
                        pending[register] = (instruction.address, value)
            for register in list(consumed):
                if known.get(register) != consumed[register]:
                    del consumed[register]
        for register, (site, value) in pending.items():
            found[value].append((site, "forms", None))

    for target in targets:
        print()
        print("=== references to {:#x} ===".format(target))
        hits = found[target]
        if not hits:
            print("(none found — the sweep may have missed it, see the docstring)")
            continue
        for site, action, at in sorted(hits):
            where = symbol_for(data, site) or symbol_for(data, site | 1)
            print(
                "{:#010x}  {}{}{}".format(
                    site,
                    action,
                    " at {:#x}".format(at) if at is not None else " the address only",
                    "   in {}".format(where) if where else "",
                )
            )


def main(argv):
    if argv[1:2] == ["--xref"]:
        if len(argv) < 4:
            sys.exit(__doc__)
        try:
            import capstone
        except ImportError:
            die("capstone is not installed (pip install capstone)")
        data = armv7_slice(find_executable(argv[2]))
        xref(capstone, data, [int(raw, 16) & ~1 for raw in argv[3:]])
        return

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
        print()
        section = section_for(data, address)
        print(
            "=== {:#x} ({}{}) ===".format(
                address,
                "Thumb" if thumb else "ARM",
                ", {},{}".format(section["segment"], section["name"]) if section else "",
            )
        )
        # A zero-fill section has no file offset, but it is mapped and worth
        # describing, so it must not be turned away here.
        if file_offset(data, address) is None and not is_zerofill(data, address):
            print("not inside any mapped segment")
            continue
        # In code, the useful thing is which function this is inside. In
        # data it is what the word there holds — printing that for code
        # would just re-print the instruction as a number.
        slot = tables(data)["indirect"].get(address)
        if slot is None and is_executable(data, address):
            containing = symbol_for(data, address)
            if containing is not None:
                print("in {}".format(containing))
        else:
            pointer = describe_pointer(data, address)
            if pointer is not None:
                print(pointer)
        if not is_executable(data, address):
            # A selector or class reference, not code. Disassembling it would
            # print noise.
            print("(not in an executable segment; not disassembling)")
            continue
        mode = capstone.CS_MODE_THUMB if thumb else capstone.CS_MODE_ARM
        md = capstone.Cs(capstone.CS_ARCH_ARM, mode)
        md.detail = True
        instructions = disassemble_window(md, data, address, thumb)
        if not instructions:
            print("(nothing decodable around this address)")
            continue
        known, from_slot = {}, {}
        for instruction in instructions:
            note = annotate(capstone, data, instruction, thumb, known, from_slot)
            track(capstone, instruction, thumb, known, from_slot)
            marker = "  <-- here" if instruction.address == address else ""
            print(
                "{:#010x}  {:<10} {:<28}{}{}".format(
                    instruction.address,
                    instruction.mnemonic,
                    instruction.op_str,
                    "; " + note if note else "",
                    marker,
                )
            )


if __name__ == "__main__":
    main(sys.argv)
