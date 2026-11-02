import { test } from "node:test";
import assert from "node:assert/strict";
import { parseElf } from "../src/lib/elf.js";

/** Minimal 64-bit little-endian shared object header with no sections. */
function buildElf64({ type = 3, machine = 62 } = {}) {
  const buffer = Buffer.alloc(64);
  buffer[0] = 0x7f;
  buffer.write("ELF", 1, "latin1");
  buffer[4] = 2; // 64-bit
  buffer[5] = 1; // little endian
  buffer[6] = 1; // version
  buffer.writeUInt16LE(type, 16);
  buffer.writeUInt16LE(machine, 18);
  buffer.writeBigUInt64LE(0x1040n, 24);
  buffer.writeUInt16LE(64, 0x34);
  buffer.writeUInt16LE(0, 0x36);
  buffer.writeUInt16LE(0, 0x38);
  buffer.writeUInt16LE(64, 0x3a);
  buffer.writeUInt16LE(0, 0x3c);
  buffer.writeUInt16LE(0, 0x3e);
  return buffer;
}

test("parses a 64-bit ELF header", () => {
  const info = parseElf(buildElf64());
  assert.equal(info.class, "64-bit");
  assert.equal(info.endianness, "little");
  assert.equal(info.typeName, "shared object / PIE");
  assert.equal(info.machineName, "x64 (AMD64)");
  assert.equal(info.entry, 0x1040);
  assert.equal(info.sectionCount, 0);
  assert.equal(info.interpreter, null);
});

test("detects a missing interpreter as not PIE", () => {
  const info = parseElf(buildElf64());
  assert.equal(info.isPie, false);
});

test("lists sections and computes entropy", () => {
  const header = buildElf64({ type: 2 });
  const sectionTableOffset = 64;
  const stringTableOffset = 64 + 64 * 3;
  const names = Buffer.from("\0.text\0.shstrtab\0", "latin1");
  const buffer = Buffer.alloc(stringTableOffset + 64 + names.length);
  header.copy(buffer, 0);

  buffer.writeUInt16LE(2, 0x3c); // e_shnum
  buffer.writeUInt16LE(1, 0x3e); // e_shstrndx
  buffer.writeBigUInt64LE(BigInt(sectionTableOffset), 0x28);

  // section 0: .text at file offset 0 with entropy 0
  const text = sectionTableOffset;
  buffer.writeUInt32LE(1, text); // name offset of ".text" (index 1 in names)
  buffer.writeUInt32LE(1, text + 4); // PROGBITS
  buffer.writeBigUInt64LE(BigInt(sectionTableOffset), text + 24);
  buffer.writeBigUInt64LE(32n, text + 32);

  // section 1: .shstrtab
  const strtab = sectionTableOffset + 64;
  buffer.writeUInt32LE(7, strtab);
  buffer.writeUInt32LE(3, strtab + 4);
  buffer.writeBigUInt64LE(BigInt(stringTableOffset), strtab + 24);
  buffer.writeBigUInt64LE(BigInt(names.length), strtab + 32);
  names.copy(buffer, stringTableOffset);

  const info = parseElf(buffer);
  assert.equal(info.sectionCount, 2);
  assert.equal(info.sections[0].name, ".text");
  assert.equal(info.sections[1].name, ".shstrtab");
});

test("rejects files that are not ELF images", () => {
  assert.throws(() => parseElf(Buffer.from("not an elf file at all")), /too small|not an ELF/);
  assert.throws(() => parseElf(Buffer.concat([Buffer.from([0x7f]), Buffer.alloc(100)])), /not an ELF/);
});
