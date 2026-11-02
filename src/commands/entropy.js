import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { entropyBlocks, highEntropyRuns, shannon } from "../lib/entropy.js";
import { UsageError, c, heading, humanBytes, pairs, percent, round, table } from "../lib/util.js";

const SPARK = ["▁", "▂", "▃", "▄", "▅", "▆", "▇", "█"];

/** Compress per-block entropy into a fixed-width sparkline. */
function sparkline(blocks, width = 64) {
  if (blocks.length === 0) return "";
  const step = Math.max(1, Math.ceil(blocks.length / width));
  const buckets = [];
  for (let i = 0; i < blocks.length; i += step) {
    const slice = blocks.slice(i, i + step);
    const average = slice.reduce((sum, block) => sum + block.entropy, 0) / slice.length;
    const index = Math.min(SPARK.length - 1, Math.max(0, Math.floor((average / 8) * SPARK.length)));
    buckets.push(SPARK[index]);
  }
  return buckets.join("");
}

export default {
  name: "entropy",
  summary: "Map entropy across a file to find packed or encrypted regions",
  usage: "rea entropy <file> [--block 256] [--threshold 7.2] [--json]",
  spec: {
    block: { type: "number", alias: ["b"], default: 256 },
    threshold: { type: "number", alias: ["t"], default: 7.2 },
    json: { type: "boolean" }
  },
  async run({ positional, options }) {
    const target = positional[0];
    if (!target) throw new UsageError("entropy needs a file");

    const path = resolve(target);
    let buffer;
    try {
      buffer = readFileSync(path);
    } catch {
      throw new UsageError(`cannot read "${target}"`);
    }
    if (buffer.length === 0) throw new UsageError(`"${target}" is empty`);

    const overall = round(shannon(buffer));
    const blocks = entropyBlocks(buffer, options.block);
    const runs = highEntropyRuns(buffer, { blockSize: options.block, threshold: options.threshold });

    if (options.json) {
      process.stdout.write(
        `${JSON.stringify({ path, size: buffer.length, entropy: overall, blockSize: options.block, threshold: options.threshold, runs }, null, 2)}\n`
      );
      return;
    }

    const zeroBlocks = blocks.filter(block => block.entropy === 0).length;

    process.stdout.write(`${c.bold(c.cyan(path))}\n`);
    process.stdout.write(
      heading("entropy") +
        "\n" +
        pairs([
          ["size", `${humanBytes(buffer.length)} (${buffer.length.toLocaleString()} bytes)`],
          ["overall", `${overall} bits/byte`],
          ["blocks", `${blocks.length.toLocaleString()} × ${options.block} bytes`],
          ["zeroed", `${zeroBlocks.toLocaleString()} blocks (${percent(zeroBlocks / blocks.length)})`],
          ["high", `${runs.length} run(s) ≥ ${options.threshold} bits/byte`]
        ]) +
        "\n"
    );

    process.stdout.write(
      `\n  ${c.dim("0.0")} ${sparkline(blocks)} ${c.dim("8.0")}\n`
    );

    if (runs.length > 0) {
      process.stdout.write(heading("high-entropy runs") + "\n");
      const rows = runs
        .sort((a, b) => b.length - a.length)
        .slice(0, 20)
        .map(run => [
          `0x${run.offset.toString(16).padStart(8, "0")}`,
          `0x${run.end.toString(16).padStart(8, "0")}`,
          humanBytes(run.length),
          String(run.entropy)
        ]);
      process.stdout.write(`\n${table(rows, ["start", "end", "length", "entropy"])}\n`);
      process.stdout.write(
        c.dim(
          "\n  Sustained entropy above ~7.2 usually means compressed or encrypted data:\n" +
            "  packed code, an embedded archive, or an encrypted payload.\n"
        )
      );
    } else {
      process.stdout.write(c.green("\n  no high-entropy runs found\n"));
    }
  }
};
