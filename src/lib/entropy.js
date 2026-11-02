/**
 * Shannon entropy over byte buffers.
 * Entropy close to 8 bits/byte means compressed or encrypted content —
 * the fastest way to spot packing, encryption or embedded archives.
 */
import { createHash } from "node:crypto";
import { createReadStream } from "node:fs";
import { round } from "./util.js";

/**
 * Shannon entropy of a buffer, in bits per byte (0..8).
 * @param {Buffer} buffer
 */
export function shannon(buffer) {
  if (!buffer || buffer.length === 0) return 0;
  const counts = new Uint32Array(256);
  for (const byte of buffer) counts[byte] += 1;
  const total = buffer.length;
  let entropy = 0;
  for (const count of counts) {
    if (count === 0) continue;
    const p = count / total;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

/**
 * Entropy per fixed-size block, useful for charting a whole file.
 * @param {Buffer} buffer
 * @param {number} blockSize
 * @returns {Array<{ offset: number, size: number, entropy: number }>}
 */
export function entropyBlocks(buffer, blockSize = 256) {
  const size = Math.max(16, Math.floor(blockSize) || 256);
  const blocks = [];
  for (let offset = 0; offset < buffer.length; offset += size) {
    const chunk = buffer.subarray(offset, Math.min(offset + size, buffer.length));
    blocks.push({ offset, size: chunk.length, entropy: shannon(chunk) });
  }
  return blocks;
}

/**
 * Split a file into runs of high entropy. Random-looking runs bigger than
 * `minRun` bytes usually mean packed code or an embedded compressed blob.
 * @returns {Array<{ offset: number, end: number, length: number, entropy: number }>}
 */
export function highEntropyRuns(buffer, { blockSize = 256, threshold = 7.2, minRun = 512 } = {}) {
  const runs = [];
  let current = null;
  for (const block of entropyBlocks(buffer, blockSize)) {
    if (block.entropy >= threshold) {
      if (!current) current = { offset: block.offset, end: block.offset + block.size, weight: 0 };
      current.end = block.offset + block.size;
      current.weight += block.entropy * block.size;
    } else if (current) {
      pushRun(runs, current, minRun, buffer, threshold);
      current = null;
    }
  }
  if (current) pushRun(runs, current, minRun, buffer, threshold);
  return runs;
}

function pushRun(runs, run, minRun, buffer, threshold) {
  const length = run.end - run.offset;
  if (length < minRun) return;
  runs.push({
    offset: run.offset,
    end: run.end,
    length,
    entropy: round(shannon(buffer.subarray(run.offset, run.end)))
  });
}

/** Streaming hashes so multi-gigabyte firmware images stay cheap to inspect. */
export async function hashFile(path, algorithms = ["sha256"]) {
  const hashes = algorithms.map(alg => createHash(alg));
  await new Promise((resolve, reject) => {
    const stream = createReadStream(path);
    stream.on("data", chunk => hashes.forEach(h => h.update(chunk)));
    stream.on("error", reject);
    stream.on("end", resolve);
  });
  return Object.fromEntries(algorithms.map((alg, i) => [alg, hashes[i].digest("hex")]));
}

export function hashBuffer(buffer, algorithms = ["sha256"]) {
  return Object.fromEntries(algorithms.map(alg => [alg, createHash(alg).update(buffer).digest("hex")]));
}
