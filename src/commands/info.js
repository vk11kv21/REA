import { readFileSync, statSync } from "node:fs";
import { resolve } from "node:path";
import { detectFormat, describeUnknown } from "../lib/format.js";
import { hashBuffer, shannon } from "../lib/entropy.js";
import { UsageError, c, humanBytes, pairs, round } from "../lib/util.js";

const HINTS = {
  pe: "rea pe <file>",
  elf: "rea elf <file>",
  zip: "rea archive <file>",
  gzip: "rea archive <file>  (gzip needs gunzip first)",
  macho32: "rea strings <file> --grep http",
  macho64: "rea strings <file> --grep http",
  dex: "rea archive <file>  (DEX inside APK)" ,
  class: "rea strings <file>"
};

function describeEntropy(value) {
  if (value >= 7.5) return c.red("very high — encrypted or compressed");
  if (value >= 7.2) return c.yellow("high — likely packed/compressed");
  if (value >= 6.0) return c.green("normal for compiled code");
  if (value >= 4.0) return "low — mostly structured data";
  return "very low — text, padding or zeros";
}

export default {
  name: "info",
  summary: "Identify files: format, size, hashes and entropy",
  usage: "rea info <file...> [--no-hash] [--json]",
  spec: {
    json: { type: "boolean" },
    hash: { type: "boolean", default: true }
  },
  async run({ positional, options }) {
    if (positional.length === 0) throw new UsageError("info needs at least one file");

    const records = [];
    for (const arg of positional) {
      const path = resolve(arg);
      let stat;
      try {
        stat = statSync(path);
      } catch {
        throw new UsageError(`cannot read "${arg}" — file not found`);
      }
      if (!stat.isFile()) throw new UsageError(`"${arg}" is not a regular file`);

      const buffer = readFileSync(path);
      const format = detectFormat(buffer);
      const entropy = round(shannon(buffer));

      records.push({
        path,
        size: stat.size,
        format: format ? format.id : "unknown",
        formatLabel: format ? format.label : describeUnknown(buffer),
        kind: format ? format.kind : "unknown",
        entropy,
        hashes: options.hash ? hashBuffer(buffer, ["md5", "sha256"]) : {}
      });
    }

    if (options.json) {
      process.stdout.write(`${JSON.stringify(records, null, 2)}\n`);
      return;
    }

    records.forEach((record, index) => {
      if (index > 0) process.stdout.write("\n");
      process.stdout.write(`${c.bold(c.cyan(record.path))}\n`);
      process.stdout.write(
        pairs([
          ["size", `${humanBytes(record.size)} (${record.size.toLocaleString()} bytes)`],
          ["format", `${record.formatLabel} ${c.dim(`[${record.format}]`)}`],
          ["entropy", `${record.entropy} bits/byte — ${describeEntropy(record.entropy)}`],
          ...(record.hashes.md5 ? [["md5", record.hashes.md5]] : []),
          ...(record.hashes.sha256 ? [["sha256", record.hashes.sha256]] : [])
        ]) + "\n"
      );

      const hint = HINTS[record.format];
      if (hint) process.stdout.write(c.dim(`  next: ${hint}\n`));
    });
  }
};
