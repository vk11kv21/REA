/**
 * Minimal ELF parser (Linux/Android/BSD executables, shared objects, cores).
 * Reports headers, sections, and the hardening signals a triage pass cares
 * about: PIE, NX stack, RELRO and whether a dynamic linker is present.
 */
import { shannon } from "./entropy.js";
import { round } from "./util.js";

const TYPES = {
  0: "none",
  1: "relocatable object",
  2: "executable",
  3: "shared object / PIE",
  4: "core dump"
};

const MACHINES = {
  2: "SPARC",
  3: "x86 (i386)",
  8: "MIPS",
  20: "PowerPC",
  21: "PowerPC64",
  40: "ARM",
  42: "SuperH",
  62: "x64 (AMD64)",
  183: "ARM64 (AArch64)",
  243: "RISC-V"
};

const SECTION_TYPES = {
  0: "NULL",
  1: "PROGBITS",
  2: "SYMTAB",
  3: "STRTAB",
  4: "RELA",
  5: "HASH",
  6: "DYNAMIC",
  7: "NOTE",
  8: "NOBITS",
  9: "REL",
  11: "DYNSYM",
  14: "INIT_ARRAY",
  15: "FINI_ARRAY",
  16: "PREINIT_ARRAY",
  17: "GROUP",
  18: "SYMTAB_SHNDX"
};

const PT_INTERP = 3;
const PT_GNU_STACK = 0x6474e551;
const PT_GNU_RELRO = 0x6474e552;

export function parseElf(buffer) {
  if (!Buffer.isBuffer(buffer) || buffer.length < 0x34) throw new Error("file too small to be an ELF image");
  if (buffer[0] !== 0x7f || buffer[1] !== 0x45 || buffer[2] !== 0x4c || buffer[3] !== 0x46) {
    throw new Error("not an ELF image (missing \\x7fELF signature)");
  }

  const elfClass = buffer[4];
  const is64 = elfClass === 2;
  if (!is64 && elfClass !== 1) throw new Error(`unknown ELF class ${elfClass}`);

  const encoding = buffer[5];
  if (encoding !== 1 && encoding !== 2) throw new Error(`unknown ELF data encoding ${encoding}`);
  const little = encoding === 1;

  const u16 = offset => (little ? buffer.readUInt16LE(offset) : buffer.readUInt16BE(offset));
  const u32 = offset => (little ? buffer.readUInt32LE(offset) : buffer.readUInt32BE(offset));
  const u64 = offset => Number(little ? buffer.readBigUInt64LE(offset) : buffer.readBigUInt64BE(offset));
  const word = offset => (is64 ? u64(offset) : u32(offset));

  const type = u16(16);
  const machine = u16(18);
  const entry = word(24);

  const phoff = is64 ? u64(0x20) : u32(0x1c);
  const shoff = is64 ? u64(0x28) : u32(0x20);
  const phentsize = u16(is64 ? 0x36 : 0x2a);
  const phnum = u16(is64 ? 0x38 : 0x2c);
  const shentsize = u16(is64 ? 0x3a : 0x2e);
  const shnum = u16(is64 ? 0x3c : 0x30);
  const shstrndx = u16(is64 ? 0x3e : 0x32);

  const programHeaders = [];
  for (let i = 0; i < phnum; i += 1) {
    const at = phoff + i * phentsize;
    if (at + phentsize > buffer.length) break;
    programHeaders.push({
      type: u32(at),
      flags: is64 ? u32(at + 4) : u32(at + 24),
      offset: word(at + (is64 ? 8 : 4)),
      virtualAddress: word(at + (is64 ? 16 : 8)),
      fileSize: word(at + (is64 ? 32 : 16))
    });
  }

  const rawSections = [];
  for (let i = 0; i < shnum; i += 1) {
    const at = shoff + i * shentsize;
    if (at + shentsize > buffer.length) break;
    rawSections.push({
      nameOffset: u32(at),
      type: u32(at + 4),
      flags: word(at + 8),
      address: word(at + (is64 ? 16 : 12)),
      offset: word(at + (is64 ? 24 : 16)),
      size: word(at + (is64 ? 32 : 20))
    });
  }

  const strTable = rawSections[shstrndx];
  const sections = rawSections.map(section => {
    let name = "";
    if (strTable && strTable.offset + section.nameOffset < buffer.length) {
      const start = strTable.offset + section.nameOffset;
      let end = start;
      const limit = Math.min(strTable.offset + strTable.size, buffer.length);
      while (end < limit && buffer[end] !== 0) end += 1;
      name = buffer.subarray(start, end).toString("latin1");
    }
    const readable = section.type !== 8 && section.size > 0;
    const start = Math.min(section.offset, buffer.length);
    const end = Math.min(section.offset + section.size, buffer.length);
    return {
      name: name || `<section ${section.address.toString(16)}>`,
      type: SECTION_TYPES[section.type] ?? `0x${section.type.toString(16)}`,
      address: section.address,
      offset: section.offset,
      size: section.size,
      entropy: readable && end > start ? round(shannon(buffer.subarray(start, end))) : 0
    };
  });

  const hasInterp = programHeaders.some(header => header.type === PT_INTERP);
  const gnuStack = programHeaders.find(header => header.type === PT_GNU_STACK);
  const execStack = gnuStack ? Boolean(gnuStack.flags & 0x1) : null;

  return {
    class: is64 ? "64-bit" : "32-bit",
    endianness: little ? "little" : "big",
    type,
    typeName: TYPES[type] ?? `unknown (${type})`,
    machine,
    machineName: MACHINES[machine] ?? `unknown (${machine})`,
    entry,
    isPie: type === 3 && hasInterp,
    execStack,
    hasRelro: programHeaders.some(header => header.type === PT_GNU_RELRO),
    programHeaderCount: programHeaders.length,
    sectionCount: shnum,
    sections,
    interpreter: hasInterp
      ? readInterp(buffer, programHeaders.find(header => header.type === PT_INTERP))
      : null
  };
}

function readInterp(buffer, header) {
  if (!header) return null;
  const start = Math.min(header.offset, buffer.length);
  const end = Math.min(header.offset + header.fileSize, buffer.length);
  return buffer
    .subarray(start, end)
    .toString("latin1")
    .replace(/\0.*$/s, "");
}
