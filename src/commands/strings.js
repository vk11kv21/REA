import { readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { extractStrings, filterStrings } from "../lib/strings.js";
import { UsageError, c, heading, table } from "../lib/util.js";

const MAX_SHOWN = 400;

export default {
  name: "strings",
  summary: "Extract ASCII and UTF-16LE strings from any file",
  usage: "rea strings <file> [--min 4] [--encoding ascii|utf16le|both] [--grep text] [--regex] [--limit 50] [--json] [--out file]",
  spec: {
    min: { type: "number", alias: ["m"], default: 4 },
    encoding: { type: "string", alias: ["e"], default: "both" },
    grep: { type: "string", alias: ["g"] },
    regex: { type: "boolean", default: false },
    limit: { type: "number", alias: ["l"], default: 40 },
    json: { type: "boolean" },
    out: { type: "string", alias: ["o"] },
    unique: { type: "boolean", alias: ["u"], default: false }
  },
  async run({ positional, options }) {
    const target = positional[0];
    if (!target) throw new UsageError("strings needs a file");
    if (!["ascii", "utf16le", "both"].includes(options.encoding)) {
      throw new UsageError('--encoding must be one of: ascii, utf16le, both');
    }

    const path = resolve(target);
    let buffer;
    try {
      buffer = readFileSync(path);
    } catch {
      throw new UsageError(`cannot read "${target}"`);
    }

    let entries = extractStrings(buffer, {
      min: options.min,
      encoding: options.encoding
    });

    if (options.grep) {
      const pattern = options.regex ? new RegExp(options.grep, "i") : options.grep;
      entries = filterStrings(entries, pattern);
    }

    if (options.unique) {
      const seen = new Set();
      entries = entries.filter(entry => {
        if (seen.has(entry.value)) return false;
        seen.add(entry.value);
        return true;
      });
    }

    if (options.out) {
      writeFileSync(resolve(options.out), entries.map(entry => entry.value).join("\n") + "\n", "utf8");
      process.stdout.write(`${c.green(`wrote ${entries.length} strings`)} → ${options.out}\n`);
      return;
    }

    if (options.json) {
      process.stdout.write(`${JSON.stringify(entries, null, 2)}\n`);
      return;
    }

    if (entries.length === 0) {
      process.stdout.write(c.yellow("no strings matched\n"));
      return;
    }

    process.stdout.write(`${c.bold(c.cyan(path))}\n`);
    process.stdout.write(heading(`${entries.length} strings (min ${options.min} chars)`));

    const shown = entries.slice(0, Math.max(1, options.limit));
    const rows = shown.map(entry => [
      c.dim(entry.offset.toString(16).padStart(8, "0")),
      entry.encoding === "utf16le" ? c.magenta("utf16") : c.blue("ascii"),
      entry.value.length > 120 ? `${entry.value.slice(0, 117)}...` : entry.value
    ]);

    process.stdout.write(`\n${table(rows)}\n`);

    if (entries.length > shown.length) {
      process.stdout.write(
        c.dim(`\n  showing ${shown.length} of ${entries.length} — use --limit or --json for more\n`)
      );
    }
  }
};
