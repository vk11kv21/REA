import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const BIN = fileURLToPath(new URL("../bin/rea.js", import.meta.url));

const run = (args, options = {}) =>
  spawnSync(process.execPath, [BIN, ...args], { encoding: "utf8", ...options });

test("help lists commands", () => {
  const result = run(["help"]);
  assert.equal(result.status, 0);
  assert.match(result.stdout, /Commands/);
  assert.match(result.stdout, /entropy/);
});

test("version prints a semver", () => {
  const result = run(["--version"]);
  assert.equal(result.status, 0);
  assert.match(result.stdout.trim(), /^rea \d+\.\d+\.\d+$/);
});

test("info --json returns hashes", () => {
  const result = run(["info", "package.json", "--json"], { cwd: fileURLToPath(new URL("..", import.meta.url)) });
  assert.equal(result.status, 0);
  const parsed = JSON.parse(result.stdout);
  assert.equal(parsed[0].format, "text");
  assert.match(parsed[0].hashes.sha256, /^[0-9a-f]{64}$/);
});

test("unknown command exits with a usage error", () => {
  const result = run(["nope"]);
  assert.equal(result.status, 2);
  assert.match(result.stderr, /unknown command/);
});

test("reports parser failures as usage errors", () => {
  const result = run(["pe", "package.json"], { cwd: fileURLToPath(new URL("..", import.meta.url)) });
  assert.equal(result.status, 2);
  assert.match(result.stderr, /not a PE image/);
});

test("init scaffolds a workspace", () => {
  const dir = mkdtempSync(join(tmpdir(), "rea-init-"));
  const result = run(["init", dir]);
  assert.equal(result.status, 0);
  for (const file of ["rea.json", ".gitignore", "notes/README.md", "findings/README.md", "samples/.gitkeep"]) {
    assert.ok(existsSync(join(dir, file)), `${file} should exist`);
  }
  const config = JSON.parse(readFileSync(join(dir, "rea.json"), "utf8"));
  assert.equal(config.version, 1);
});

test("report writes markdown for a sample file", () => {
  const dir = mkdtempSync(join(tmpdir(), "rea-report-"));
  const sample = join(dir, "sample.txt");
  writeFileSync(sample, "https://example.com\n", "utf8");

  const out = join(dir, "report.md");
  const result = run(["report", sample, "--out", out]);
  assert.equal(result.status, 0);

  const markdown = readFileSync(out, "utf8");
  assert.match(markdown, /# REA triage report/);
  assert.match(markdown, /\| File \| Size \| Format \|/);
  assert.match(markdown, /## Findings/);
});

test("strings --json extracts values", () => {
  const dir = mkdtempSync(join(tmpdir(), "rea-strings-"));
  const sample = join(dir, "sample.bin");
  writeFileSync(sample, "prefix https://example.com/api suffix");

  const result = run(["strings", sample, "--grep", "https", "--json"]);
  assert.equal(result.status, 0);
  const parsed = JSON.parse(result.stdout);
  assert.equal(parsed.length, 1);
  assert.match(parsed[0].value, /https:\/\/example\.com\/api/);
});
