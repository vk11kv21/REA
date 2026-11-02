import { test } from "node:test";
import assert from "node:assert/strict";
import { deflateRawSync } from "node:zlib";
import { looksLikeApk, parseZip } from "../src/lib/zip.js";

const CRC_TABLE = (() => {
  const table = new Uint32Array(256);
  for (let i = 0; i < 256; i += 1) {
    let value = i;
    for (let bit = 0; bit < 8; bit += 1) {
      value = value & 1 ? 0xedb88320 ^ (value >>> 1) : value >>> 1;
    }
    table[i] = value >>> 0;
  }
  return table;
})();

function crc32(buffer) {
  let crc = 0xffffffff;
  for (const byte of buffer) crc = CRC_TABLE[(crc ^ byte) & 0xff] ^ (crc >>> 8);
  return (crc ^ 0xffffffff) >>> 0;
}

/** Build a real (deflate) ZIP archive in memory. */
function buildZip(files) {
  const locals = [];
  const central = [];
  let offset = 0;

  for (const [name, content] of Object.entries(files)) {
    const data = Buffer.from(content);
    const compressed = deflateRawSync(data);
    const nameBuffer = Buffer.from(name, "utf8");

    const local = Buffer.alloc(30);
    local.writeUInt32LE(0x04034b50, 0);
    local.writeUInt16LE(20, 4);
    local.writeUInt16LE(0x0800, 6);
    local.writeUInt16LE(8, 8);
    local.writeUInt32LE(crc32(data), 14);
    local.writeUInt32LE(compressed.length, 18);
    local.writeUInt32LE(data.length, 22);
    local.writeUInt16LE(nameBuffer.length, 26);

    const entry = Buffer.alloc(46);
    entry.writeUInt32LE(0x02014b50, 0);
    entry.writeUInt16LE(20, 4);
    entry.writeUInt16LE(20, 6);
    entry.writeUInt16LE(0x0800, 8);
    entry.writeUInt16LE(8, 10);
    entry.writeUInt32LE(crc32(data), 16);
    entry.writeUInt32LE(compressed.length, 20);
    entry.writeUInt32LE(data.length, 24);
    entry.writeUInt16LE(nameBuffer.length, 28);
    entry.writeUInt32LE(offset, 42);

    locals.push(local, nameBuffer, compressed);
    central.push(entry, nameBuffer);
    offset += local.length + nameBuffer.length + compressed.length;
  }

  const directory = Buffer.concat(central);
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);
  eocd.writeUInt16LE(Object.keys(files).length, 8);
  eocd.writeUInt16LE(Object.keys(files).length, 10);
  eocd.writeUInt32LE(directory.length, 12);
  eocd.writeUInt32LE(offset, 16);

  return Buffer.concat([...locals, directory, eocd]);
}

test("reads entry names and sizes", () => {
  const zip = parseZip(buildZip({ "a.txt": "hello", "dir/b.bin": "binary-data" }));
  assert.equal(zip.entries.length, 2);
  assert.deepEqual(zip.entries.map(entry => entry.name), ["a.txt", "dir/b.bin"]);
  assert.equal(zip.entries[0].size, 5);
  assert.equal(zip.entries[0].methodName, "deflate");
  assert.equal(zip.entries[0].encrypted, false);
});

test("detects APK layout", () => {
  const apk = parseZip(
    buildZip({
      "AndroidManifest.xml": "manifest",
      "classes.dex": "dex",
      "lib/arm64-v8a/libnative.so": "elf"
    })
  );
  assert.equal(looksLikeApk(apk.entries), true);
});

test("does not mistake a plain zip for an APK", () => {
  const zip = parseZip(buildZip({ "readme.txt": "hello" }));
  assert.equal(looksLikeApk(zip.entries), false);
});

test("rejects files without an end-of-central-directory record", () => {
  assert.throws(() => parseZip(Buffer.alloc(64)), /not a ZIP/);
  assert.throws(() => parseZip(Buffer.from("PK")), /too small/);
});
