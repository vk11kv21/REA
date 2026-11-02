import { test } from "node:test";
import assert from "node:assert/strict";
import { parsePe } from "../src/lib/pe.js";

/** Smallest PE32+ image that still exercises the parser end to end. */
function buildPe() {
  const buffer = Buffer.alloc(0x400);
  buffer.write("MZ", 0, "latin1");
  buffer.writeUInt32LE(0x80, 0x3c);
  buffer.write("PE\0\0", 0x80, "latin1");

  const coff = 0x84;
  buffer.writeUInt16LE(0x8664, coff);
  buffer.writeUInt16LE(1, coff + 2);
  buffer.writeUInt32LE(0x5f000000, coff + 4);
  buffer.writeUInt16LE(0xf0, coff + 16);
  buffer.writeUInt16LE(0x22, coff + 18);

  const opt = coff + 20;
  buffer.writeUInt16LE(0x20b, opt);
  buffer.writeUInt32LE(0x1000, opt + 16);
  buffer.writeBigUInt64LE(0x140000000n, opt + 24);
  buffer.writeUInt32LE(0x1000, opt + 32);
  buffer.writeUInt32LE(0x200, opt + 36);
  buffer.writeUInt32LE(0x2000, opt + 56);
  buffer.writeUInt32LE(0x200, opt + 60);
  buffer.writeUInt16LE(3, opt + 68);
  buffer.writeUInt16LE(0x8160, opt + 70);
  buffer.writeUInt32LE(16, opt + 108);

  const section = opt + 0xf0;
  buffer.write(".text", section, "latin1");
  buffer.writeUInt32LE(0x200, section + 8);
  buffer.writeUInt32LE(0x1000, section + 12);
  buffer.writeUInt32LE(0x200, section + 16);
  buffer.writeUInt32LE(0x200, section + 20);
  buffer.writeUInt32LE(0x60000020, section + 36);

  buffer.fill("A", 0x200, 0x400);
  return buffer;
}

test("parses headers and sections", () => {
  const info = parsePe(buildPe());
  assert.equal(info.is64, true);
  assert.equal(info.machineName, "x64 (AMD64)");
  assert.equal(info.subsystemName, "Windows console");
  assert.equal(info.sectionCount, 1);
  assert.equal(info.sections[0].name, ".text");
  assert.deepEqual(info.sections[0].permissions.split(","), ["code", "execute", "read"]);
  assert.equal(info.entryPoint, 0x1000);
  assert.equal(info.imageBase, 0x140000000);
});

test("reports mitigation flags", () => {
  const info = parsePe(buildPe());
  assert.ok(info.dllCharacteristicNames.includes("dynamic base (ASLR)"));
  assert.ok(info.dllCharacteristicNames.includes("NX compatible (DEP)"));
  assert.equal(info.isDll, false);
  assert.equal(info.isManaged, false);
});

test("returns no imports for an image without an import directory", () => {
  const info = parsePe(buildPe());
  assert.deepEqual(info.imports, []);
  assert.equal(info.pdbPath, null);
  assert.equal(info.overlaySize, 0);
});

test("rejects files that are not PE images", () => {
  assert.throws(() => parsePe(Buffer.from("#!/bin/sh\necho hi\n")), /too small|not a PE/);
  assert.throws(() => parsePe(Buffer.concat([Buffer.from("MZ"), Buffer.alloc(200)])), /invalid PE header|not a PE/);
});
