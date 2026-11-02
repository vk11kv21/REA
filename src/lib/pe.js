/**
 * Minimal PE/COFF parser (Windows .exe/.dll/.sys).
 * Reads only what a triage pass needs: headers, sections, imports, exports,
 * the CodeView PDB path, overlay data and per-section entropy.
 */
import { shannon } from "./entropy.js";
import { round } from "./util.js";

const MACHINES = {
  0x014c: "x86 (i386)",
  0x0166: "MIPS R4000",
  0x01c0: "ARM",
  0x01c4: "ARMv7 (Thumb-2)",
  0x01f0: "PowerPC",
  0x0200: "Itanium",
  0x8664: "x64 (AMD64)",
  0xaa64: "ARM64",
  0x5032: "RISC-V 32",
  0x5064: "RISC-V 64"
};

const SUBSYSTEMS = {
  1: "native",
  2: "Windows GUI",
  3: "Windows console",
  5: "OS/2 console",
  7: "POSIX console",
  9: "Windows CE GUI",
  10: "EFI application",
  11: "EFI boot driver",
  12: "EFI runtime driver",
  14: "Xbox",
  16: "Windows boot application"
};

const FILE_CHARACTERISTICS = {
  0x0001: "relocs stripped",
  0x0002: "executable",
  0x0020: "large address aware",
  0x0100: "32-bit",
  0x2000: "DLL"
};

const DLL_CHARACTERISTICS = {
  0x0020: "high entropy VA",
  0x0040: "dynamic base (ASLR)",
  0x0080: "force integrity",
  0x0100: "NX compatible (DEP)",
  0x0200: "no isolation",
  0x0400: "no SEH",
  0x0800: "no bind",
  0x1000: "app container",
  0x2000: "WDM driver",
  0x4000: "control flow guard",
  0x8000: "terminal server aware"
};

const DIRECTORIES = [
  "export",
  "import",
  "resource",
  "exception",
  "certificate",
  "base relocation",
  "debug",
  "architecture",
  "global ptr",
  "TLS",
  "load config",
  "bound import",
  "IAT",
  "delay import",
  "CLR runtime",
  "reserved"
];

const SECTION_CHARACTERISTICS = [
  [0x00000020, "code"],
  [0x00000040, "initialised data"],
  [0x00000080, "uninitialised data"],
  [0x02000000, "discardable"],
  [0x04000000, "not cached"],
  [0x08000000, "not paged"],
  [0x10000000, "shared"],
  [0x20000000, "execute"],
  [0x40000000, "read"],
  [0x80000000, "write"]
];

const flagNames = (value, table) => {
  const entries =
    table instanceof Map
      ? [...table.entries()]
      : Array.isArray(table)
        ? table
        : Object.entries(table).map(([bit, name]) => [Number(bit), name]);
  return entries.filter(([bit]) => value & Number(bit)).map(([, name]) => name);
};

/** @param {Buffer} buffer */
export function parsePe(buffer) {
  if (!Buffer.isBuffer(buffer) || buffer.length < 0x40) throw new Error("file too small to be a PE image");
  if (buffer[0] !== 0x4d || buffer[1] !== 0x5a) throw new Error("not a PE image (missing MZ signature)");

  const peOffset = buffer.readUInt32LE(0x3c);
  if (peOffset + 24 > buffer.length) throw new Error("invalid PE header offset (truncated file?)");
  if (buffer.readUInt32BE(peOffset) !== 0x50450000) throw new Error("not a PE image (missing PE\\0\\0 signature)");

  const coff = peOffset + 4;
  const machine = buffer.readUInt16LE(coff);
  const sectionCount = buffer.readUInt16LE(coff + 2);
  const timestamp = buffer.readUInt32LE(coff + 4);
  const symbolTable = buffer.readUInt32LE(coff + 8);
  const optionalHeaderSize = buffer.readUInt16LE(coff + 16);
  const characteristics = buffer.readUInt16LE(coff + 18);

  const opt = coff + 20;
  if (opt + 2 > buffer.length) throw new Error("truncated optional header");
  const magic = buffer.readUInt16LE(opt);
  if (magic !== 0x010b && magic !== 0x020b) throw new Error(`unknown optional header magic ${magic.toString(16)}`);
  const is64 = magic === 0x020b;
  if (opt + optionalHeaderSize > buffer.length) throw new Error("truncated optional header");

  const entryPoint = buffer.readUInt32LE(opt + 16);
  const imageBase = is64
    ? Number(buffer.readBigUInt64LE(opt + 24))
    : buffer.readUInt32LE(opt + 28);
  const sectionAlignment = buffer.readUInt32LE(opt + 32);
  const fileAlignment = buffer.readUInt32LE(opt + 36);
  const sizeOfImage = buffer.readUInt32LE(opt + 56);
  const sizeOfHeaders = buffer.readUInt32LE(opt + 60);
  const subsystem = buffer.readUInt16LE(opt + 68);
  const dllCharacteristics = buffer.readUInt16LE(opt + 70);
  const rvaCount = buffer.readUInt32LE(opt + (is64 ? 108 : 92));
  const dirBase = opt + (is64 ? 112 : 96);

  const directories = [];
  for (let i = 0; i < Math.min(rvaCount, 16); i += 1) {
    const entry = dirBase + i * 8;
    if (entry + 8 > buffer.length) break;
    const rva = buffer.readUInt32LE(entry);
    const size = buffer.readUInt32LE(entry + 4);
    directories.push({ index: i, name: DIRECTORIES[i] ?? `dir ${i}`, rva, size });
  }

  const sections = [];
  const sectionTable = opt + optionalHeaderSize;
  for (let i = 0; i < sectionCount; i += 1) {
    const at = sectionTable + i * 40;
    if (at + 40 > buffer.length) break;
    const name = buffer
      .subarray(at, at + 8)
      .toString("latin1")
      .replace(/\0.*$/s, "")
      .trim();
    const virtualSize = buffer.readUInt32LE(at + 8);
    const virtualAddress = buffer.readUInt32LE(at + 12);
    const rawSize = buffer.readUInt32LE(at + 16);
    const rawPointer = buffer.readUInt32LE(at + 20);
    const flags = buffer.readUInt32LE(at + 36);
    const start = Math.min(rawPointer, buffer.length);
    const end = Math.min(rawPointer + rawSize, buffer.length);
    sections.push({
      name: name || `section${i}`,
      virtualAddress,
      virtualSize,
      rawPointer,
      rawSize,
      flags,
      permissions: flagNames(flags, SECTION_CHARACTERISTICS).join(","),
      entropy: rawSize > 0 && end > start ? round(shannon(buffer.subarray(start, end))) : 0
    });
  }

  const toOffset = rva => {
    for (const section of sections) {
      const span = Math.max(section.virtualSize, section.rawSize);
      if (rva >= section.virtualAddress && rva < section.virtualAddress + span) {
        return section.rawPointer + (rva - section.virtualAddress);
      }
    }
    return rva < sizeOfHeaders ? rva : -1;
  };

  const imports = readImports(buffer, directories[1], toOffset, is64);
  const exports = readExports(buffer, directories[0], toOffset);
  const debug = readDebug(buffer, directories[6], toOffset);
  const clr = directories[14] && directories[14].rva !== 0;

  const lastSectionEnd = sections.reduce(
    (max, section) => Math.max(max, section.rawPointer + section.rawSize),
    0
  );
  const overlaySize = Math.max(0, buffer.length - lastSectionEnd);

  return {
    peOffset,
    machine,
    machineName: MACHINES[machine] ?? `unknown (0x${machine.toString(16)})`,
    sectionCount,
    timestamp,
    builtAt: timestamp ? new Date(timestamp * 1000).toISOString() : null,
    is64,
    optionalHeaderMagic: magic,
    entryPoint,
    imageBase,
    sectionAlignment,
    fileAlignment,
    sizeOfImage,
    sizeOfHeaders,
    subsystem,
    subsystemName: SUBSYSTEMS[subsystem] ?? `unknown (${subsystem})`,
    dllCharacteristics,
    dllCharacteristicNames: flagNames(dllCharacteristics, DLL_CHARACTERISTICS),
    characteristics,
    characteristicNames: flagNames(characteristics, FILE_CHARACTERISTICS),
    isDll: Boolean(characteristics & 0x2000),
    isManaged: Boolean(clr),
    directories,
    sections,
    imports,
    exports,
    pdbPath: debug.pdbPath ?? null,
    debugEntries: debug.count,
    overlaySize,
    symbolTable
  };
}

function readCString(buffer, offset, max = 512) {
  if (offset < 0 || offset >= buffer.length) return null;
  const end = Math.min(offset + max, buffer.length);
  let cursor = offset;
  while (cursor < end && buffer[cursor] !== 0) cursor += 1;
  return buffer.subarray(offset, cursor).toString("latin1");
}

function readImports(buffer, directory, toOffset, is64) {
  if (!directory || directory.rva === 0 || directory.size === 0) return [];
  const base = toOffset(directory.rva);
  if (base < 0) return [];

  const libraries = [];
  for (let i = 0; i < 256; i += 1) {
    const at = base + i * 20;
    if (at + 20 > buffer.length) break;
    const originalFirstThunk = buffer.readUInt32LE(at);
    const nameRva = buffer.readUInt32LE(at + 12);
    const firstThunk = buffer.readUInt32LE(at + 16);
    if (originalFirstThunk === 0 && nameRva === 0 && firstThunk === 0) break;

    const name = readCString(buffer, toOffset(nameRva)) ?? "<unnamed>";
    const thunkRva = originalFirstThunk || firstThunk;
    const thunkBase = toOffset(thunkRva);
    const functions = [];
    if (thunkBase >= 0) {
      const step = is64 ? 8 : 4;
      for (let j = 0; j < 4096; j += 1) {
        const slot = thunkBase + j * step;
        if (slot + step > buffer.length) break;
        const value = is64 ? Number(buffer.readBigUInt64LE(slot)) : buffer.readUInt32LE(slot);
        if (value === 0) break;
        const byOrdinal = is64 ? value >= 2 ** 63 : Boolean(value & 0x80000000);
        if (byOrdinal) {
          functions.push(`#${value & 0xffff}`);
        } else {
          const hintName = readCString(buffer, toOffset(value) + 2, 256);
          functions.push(hintName ?? `<rva 0x${value.toString(16)}>`);
        }
        if (functions.length >= 512) break;
      }
    }
    libraries.push({ name, functions });
  }
  return libraries;
}

function readExports(buffer, directory, toOffset) {
  if (!directory || directory.rva === 0 || directory.size === 0) return null;
  const base = toOffset(directory.rva);
  if (base < 0 || base + 40 > buffer.length) return null;
  return {
    name: readCString(buffer, toOffset(buffer.readUInt32LE(base + 12))) ?? "<unnamed>",
    base: buffer.readUInt32LE(base + 16),
    functionCount: buffer.readUInt32LE(base + 20),
    nameCount: buffer.readUInt32LE(base + 24)
  };
}

function readDebug(buffer, directory, toOffset) {
  if (!directory || directory.rva === 0 || directory.size === 0) return { count: 0 };
  const base = toOffset(directory.rva);
  if (base < 0) return { count: 0 };
  const count = Math.floor(directory.size / 28);
  let pdbPath = null;
  for (let i = 0; i < Math.min(count, 32); i += 1) {
    const at = base + i * 28;
    if (at + 28 > buffer.length) break;
    const type = buffer.readUInt32LE(at + 12);
    const dataOffset = toOffset(buffer.readUInt32LE(at + 20));
    if (type !== 2 || dataOffset < 0 || dataOffset + 24 > buffer.length) continue;
    if (buffer.subarray(dataOffset, dataOffset + 4).toString("latin1") !== "RSDS") continue;
    pdbPath = readCString(buffer, dataOffset + 24, 260);
  }
  return { count, pdbPath };
}
