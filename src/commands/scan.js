import { openSync, readSync, closeSync, readFileSync, statSync } from "node:fs";
import { resolve } from "node:path";
import { detectFormat, describeUnknown } from "../lib/format.js";
import { hashBuffer, hashFile, shannon } from "../lib/entropy.js";
import { walk } from "../lib/walk.js";
import { UsageError, c, heading, humanBytes, pairs, table } from "../lib/util.js";

const HEAD = 64 * 1024;
const SUSPICIOUS_EXTENSIONS = new Set([".exe", ".dll", ".scr", ".sys", ".apk", ".dex", ".so", ".bin", ".dat", ".tmp"]);

function readHead(path) {
  const fd = openSync(path, "r");
  try {
    const buffer = Buffer.alloc(HEAD);
    const read = readSync(fd, buffer, 0, HEAD, 0);
    return buffer.subarray(0, read);
  } finally {
    closeSync(fd);
  }
}

export default {
  name: "scan",
  summary: "Triage a folder: classify every file and flag the interesting ones",
  usage: "rea scan <dir> [--depth 6] [--hash] [--top 25] [--min-size 0] [--json]",
  spec: {
    depth: { type: "number", alias: ["d"], default: 6 },
    hash: { type: "boolean", default: true },
    top: { type: "number", alias: ["t"], default: 25 },
    hidden: { type: "boolean", default: false },
    json: { type: "boolean" },
    minSize: { type: "number", default: 0 }
  },
  async run({ positional, options }) {
    const target = positional[0];
    if (!target) throw new UsageError("scan needs a directory (or a single file)");

    const root = resolve(target);
    let stat;
    try {
      stat = statSync(root);
    } catch {
      throw new UsageError(`cannot read "${target}"`);
    }

    const files = stat.isDirectory()
      ? walk(root, { depth: options.depth, includeHidden: options.hidden })
      : [{ path: root, relative: root.split(/[\\/]/).pop(), size: stat.size }];

    if (files.length === 0) throw new UsageError(`no files found under "${target}"`);

    const records = [];
    for (const file of files) {
      if (file.size < options.minSize) continue;
      const head = readHead(file.path);
      const format = detectFormat(head);
      const record = {
        path: file.path,
        relative: file.relative,
        size: file.size,
        format: format ? format.id : "unknown",
        formatLabel: format ? format.label : describeUnknown(head),
        kind: format ? format.kind : "unknown",
        entropy: Number(shannon(head).toFixed(2)),
        hashes: {}
      };

      if (options.hash) {
        record.hashes =
          file.size <= 64 * 1024 * 1024
            ? hashBuffer(readFileSync(file.path), ["sha256"])
            : await hashFile(file.path, ["sha256"]);
      }

      records.push(record);
    }

    const byKind = new Map();
    for (const record of records) {
      const current = byKind.get(record.kind) ?? { count: 0, bytes: 0 };
      byKind.set(record.kind, { count: current.count + 1, bytes: current.bytes + record.size });
    }

    const duplicates = new Map();
    if (options.hash) {
      for (const record of records) {
        const hash = record.hashes.sha256;
        if (!hash) continue;
        duplicates.set(hash, [...(duplicates.get(hash) ?? []), record.relative]);
      }
    }

    const flags = record => {
      const notes = [];
      if (record.entropy >= 7.2) notes.push("high entropy");
      if (/\.(jpg|png|pdf|txt|docx)$/i.test(record.relative) && [".exe", ".dll", ".scr"].includes(extensionOf(record.relative))) {
        notes.push("double extension");
      }
      if (SUSPICIOUS_EXTENSIONS.has(extensionOf(record.relative)) && record.kind === "unknown") {
        notes.push("binary with unknown format");
      }
      if (/^[A-Za-z0-9+/=]{40,}$/.test(record.relative)) notes.push("base64-looking name");
      if (options.hash && (duplicates.get(record.hashes.sha256)?.length ?? 0) > 1) notes.push("duplicate");
      return notes.join(", ");
    };

    if (options.json) {
      process.stdout.write(
        `${JSON.stringify({ root, fileCount: records.length, files: records.map(record => ({ ...record, flags: flags(record) })) }, null, 2)}\n`
      );
      return;
    }

    const totalBytes = records.reduce((sum, record) => sum + record.size, 0);
    process.stdout.write(`${c.bold(c.cyan(root))}\n`);
    process.stdout.write(
      heading("summary") +
        "\n" +
        pairs([
          ["files", `${records.length.toLocaleString()} (${humanBytes(totalBytes)})`],
          ...([...byKind.entries()]
            .sort((a, b) => b[1].count - a[1].count)
            .map(([kind, value]) => [kind, `${value.count} files, ${humanBytes(value.bytes)}`]))
        ]) +
        "\n"
    );

    const interesting = records
      .map(record => ({ record, notes: flags(record) }))
      .filter(item => item.notes)
      .sort((a, b) => b.record.size - a.record.size);

    if (interesting.length > 0) {
      process.stdout.write(heading(`flagged (${interesting.length})`) + "\n");
      const rows = interesting.slice(0, options.top).map(item => [
        item.record.relative,
        humanBytes(item.record.size),
        item.record.format,
        item.record.entropy >= 7.2 ? c.yellow(String(item.record.entropy)) : String(item.record.entropy),
        item.notes
      ]);
      process.stdout.write(`\n${table(rows, ["file", "size", "format", "entropy", "why"])}\n`);
    }

    const largest = [...records].sort((a, b) => b.size - a.size).slice(0, options.top);
    process.stdout.write(heading(`largest (${largest.length})`) + "\n");
    const rows = largest.map(record => [
      record.relative.length > 60 ? `…${record.relative.slice(-59)}` : record.relative,
      humanBytes(record.size),
      record.format
    ]);
    process.stdout.write(`\n${table(rows, ["file", "size", "format"])}\n`);
    process.stdout.write(c.dim(`\n  next: rea report ${target}  → markdown case notes\n`));
  }
};

function extensionOf(name) {
  const match = name.toLowerCase().match(/\.[a-z0-9]+$/);
  return match ? match[0] : "";
}
