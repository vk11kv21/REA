import { test } from "node:test";
import assert from "node:assert/strict";
import { extractStrings, filterStrings } from "../src/lib/strings.js";

test("extracts ascii strings", () => {
  const buffer = Buffer.from("\x01\x02https://example.com/report\x00short\x00\xff", "latin1");
  const found = extractStrings(buffer, { min: 4, encoding: "ascii" }).map(entry => entry.value);
  assert.deepEqual(found, ["https://example.com/report", "short"]);
});

test("respects the minimum length", () => {
  const buffer = Buffer.from("abc\x00abcd\x00", "latin1");
  assert.deepEqual(
    extractStrings(buffer, { min: 4, encoding: "ascii" }).map(entry => entry.value),
    ["abcd"]
  );
});

test("extracts utf16le strings", () => {
  const buffer = Buffer.from("HKEY_LOCAL_MACHINE\\Software", "utf16le");
  const found = extractStrings(buffer, { min: 8, encoding: "utf16le" });
  assert.equal(found.length, 1);
  assert.equal(found[0].value, "HKEY_LOCAL_MACHINE\\Software");
  assert.equal(found[0].encoding, "utf16le");
});

test("finds both encodings and sorts by offset", () => {
  const buffer = Buffer.concat([
    Buffer.from("first-ascii", "latin1"),
    Buffer.from([0, 0]),
    Buffer.from("second-utf16", "utf16le")
  ]);
  const found = extractStrings(buffer, { min: 6, encoding: "both" });
  assert.equal(found.length, 2);
  assert.ok(found[0].offset < found[1].offset);
});

test("filters case-insensitively", () => {
  const entries = [
    { offset: 0, encoding: "ascii", value: "https://EXAMPLE.com/a" },
    { offset: 10, encoding: "ascii", value: "C:\\Windows\\Temp" }
  ];
  assert.equal(filterStrings(entries, "example").length, 1);
  assert.equal(filterStrings(entries, /windows/i).length, 1);
});
