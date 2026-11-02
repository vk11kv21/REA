import { test } from "node:test";
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { entropyBlocks, highEntropyRuns, shannon } from "../src/lib/entropy.js";

test("entropy of uniform data is zero", () => {
  assert.equal(shannon(Buffer.alloc(1024)), 0);
});

test("entropy of random data approaches 8 bits/byte", () => {
  const value = shannon(randomBytes(4096));
  assert.ok(value > 7.7, `expected > 7.7, got ${value}`);
});

test("entropy of empty buffer is zero", () => {
  assert.equal(shannon(Buffer.alloc(0)), 0);
});

test("blocks cover the whole buffer", () => {
  const buffer = Buffer.alloc(1000);
  const blocks = entropyBlocks(buffer, 256);
  assert.equal(blocks.length, 4);
  assert.equal(blocks[0].offset, 0);
  assert.equal(blocks.at(-1).end ?? blocks.at(-1).offset + blocks.at(-1).size, 1000);
});

test("finds a random region hidden inside zeros", () => {
  const buffer = Buffer.concat([Buffer.alloc(4096), randomBytes(4096), Buffer.alloc(4096)]);
  const runs = highEntropyRuns(buffer, { blockSize: 256, threshold: 6.5, minRun: 512 });
  assert.ok(runs.length >= 1);
  const covered = runs.reduce((sum, run) => sum + run.length, 0);
  assert.ok(covered >= 3800, `expected the random region to be covered, got ${covered} bytes`);
  for (const run of runs) {
    assert.ok(run.offset >= 4096 && run.end <= 8192, "runs must stay inside the random region");
  }
});

test("reports no runs for low-entropy data", () => {
  assert.equal(highEntropyRuns(Buffer.alloc(8192), { minRun: 256 }).length, 0);
});
