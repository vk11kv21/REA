import { test } from "node:test";
import assert from "node:assert/strict";
import { detectFormat, looksLikeText } from "../src/lib/format.js";

const png = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0, 0, 0, 0]);
const elf = Buffer.from([0x7f, 0x45, 0x4c, 0x46, 0x02, 0x01, 0x01, 0x00]);
const zip = Buffer.from([0x50, 0x4b, 0x03, 0x04, 0x14, 0x00, 0x00, 0x00]);
const pe = Buffer.concat([Buffer.from("MZ"), Buffer.alloc(64)]);
const gzip = Buffer.from([0x1f, 0x8b, 0x08, 0x00]);

test("identifies common signatures", () => {
  assert.equal(detectFormat(png)?.id, "png");
  assert.equal(detectFormat(elf)?.id, "elf");
  assert.equal(detectFormat(zip)?.id, "zip");
  assert.equal(detectFormat(pe)?.id, "pe");
  assert.equal(detectFormat(gzip)?.id, "gzip");
});

test("classifies printable data as text", () => {
  const text = Buffer.from("hello rea\nsecond line\n");
  assert.equal(detectFormat(text)?.kind, "text");
  assert.equal(looksLikeText(text), true);
});

test("returns null for unrecognised binary data", () => {
  const binary = Buffer.from(Array.from({ length: 64 }, (_, i) => (i * 37) % 256));
  assert.equal(detectFormat(binary), null);
  assert.equal(looksLikeText(binary), false);
});

test("never throws on tiny buffers", () => {
  assert.equal(detectFormat(Buffer.from([0x4d])), null);
  assert.equal(detectFormat(Buffer.alloc(0)), null);
});
