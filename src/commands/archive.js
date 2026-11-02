import { readFileSync } from "node:fs";
import { extname, resolve } from "node:path";
import { gunzipSync } from "node:zlib";
import { detectFormat } from "../lib/format.js";
import { looksLikeApk, parseZip } from "../lib/zip.js";
import { UsageError, c, heading, humanBytes, pairs, percent, table } from "../lib/util.js";

export default {
  name: "archive",
  summary: "List ZIP/APK/JAR contents and summarise what is inside",
  usage: "rea archive <file.zip|apk|jar|docx|gz> [--all] [--grep name] [--json]",
  spec: {
    all: { type: "boolean", default: false },
    grep: { type: "string", alias: ["g"] },
    limit: { type: "number", alias: ["l"], default: 40 },
    json: { type: "boolean" }
  },
  async run({ positional, options }) {
    const target = positional[0];
    if (!target) throw new UsageError("archive needs a file");

    const path = resolve(target);
    let buffer;
    try {
      buffer = readFileSync(path);
    } catch {
      throw new UsageError(`cannot read "${target}"`);
    }

    const format = detectFormat(buffer);
    if (format?.id === "gzip") {
      return showGzip(buffer);
    }
    if (format?.id !== "zip") {
      throw new UsageError(`${target} is not a ZIP container (detected: ${format?.label ?? "unknown"})`);
    }

    let zip;
    try {
      zip = parseZip(buffer);
    } catch (error) {
      throw new UsageError(`${target}: ${error.message}`);
    }

    if (zip.zip64) {
      throw new UsageError(`${target}: ZIP64 archives are not supported yet`);
    }

    let entries = zip.entries.filter(entry => !entry.isDirectory);
    if (options.grep) {
      const needle = options.grep.toLowerCase();
      entries = entries.filter(entry => entry.name.toLowerCase().includes(needle));
    }
    entries.sort((a, b) => b.size - a.size);

    const isApk = looksLikeApk(zip.entries);
    const totalSize = entries.reduce((sum, entry) => sum + entry.size, 0);
    const totalCompressed = entries.reduce((sum, entry) => sum + entry.compressedSize, 0);
    const encrypted = entries.filter(entry => entry.encrypted).length;

    if (options.json) {
      process.stdout.write(
        `${JSON.stringify({ path, kind: isApk ? "apk" : "zip", entryCount: zip.entries.length, entries }, null, 2)}\n`
      );
      return;
    }

    process.stdout.write(`${c.bold(c.cyan(path))}\n`);
    process.stdout.write(
      heading("summary") +
        "\n" +
        pairs([
          ["kind", isApk ? "Android APK" : "ZIP container"],
          ["entries", `${zip.entries.length} (${zip.entries.filter(e => e.isDirectory).length} directories)`],
          ["unpacked", humanBytes(totalSize)],
          ["packed", humanBytes(totalCompressed)],
          ["ratio", totalSize > 0 ? percent(totalCompressed / totalSize) : "—"],
          ...(encrypted > 0 ? [["encrypted", c.yellow(`${encrypted} entries`)]] : [])
        ]) +
        "\n"
    );

    if (isApk) {
      const dex = zip.entries.filter(entry => /^classes\d*\.dex$/.test(entry.name));
      const abis = [
        ...new Set(
          zip.entries
            .map(entry => entry.name.match(/^lib[\\/]([^\\/]+)[\\/]/)?.[1])
            .filter(Boolean)
        )
      ];
      const signed = zip.entries.some(entry => /^META-INF\/.*\.(RSA|DSA|EC)$/i.test(entry.name));
      process.stdout.write(heading("android") + "\n");
      process.stdout.write(
        pairs([
          ["dex files", dex.map(entry => `${entry.name} (${humanBytes(entry.size)})`).join(", ") || "none"],
          ["ABIs", abis.join(", ") || "none"],
          ["signature", signed ? "v1 (JAR) signature present" : "no v1 signature found"]
        ]) + "\n"
      );
    }

    const byExtension = new Map();
    for (const entry of entries) {
      const key = extname(entry.name).toLowerCase() || "(no extension)";
      const current = byExtension.get(key) ?? { count: 0, bytes: 0 };
      byExtension.set(key, { count: current.count + 1, bytes: current.bytes + entry.size });
    }
    const extensionRows = [...byExtension.entries()]
      .sort((a, b) => b[1].bytes - a[1].bytes)
      .slice(0, 8)
      .map(([key, value]) => [key, String(value.count), humanBytes(value.bytes)]);

    process.stdout.write(heading("content by type") + "\n");
    process.stdout.write(`\n${table(extensionRows, ["extension", "files", "unpacked"])}\n`);

    const shown = options.all ? entries : entries.slice(0, options.limit);
    const rows = shown.map(entry => [
      entry.name.length > 64 ? `…${entry.name.slice(-63)}` : entry.name,
      humanBytes(entry.size),
      entry.methodName,
      entry.encrypted ? c.yellow("yes") : ""
    ]);

    process.stdout.write(heading(options.all ? `all ${entries.length} entries` : `largest ${shown.length} entries`) + "\n");
    process.stdout.write(`\n${table(rows, ["name", "size", "method", "encrypted"])}\n`);

    if (!options.all && entries.length > shown.length) {
      process.stdout.write(c.dim(`\n  ${entries.length - shown.length} more — use --all or --grep\n`));
    }
  }
};

function showGzip(buffer) {
  const raw = gunzipSync(buffer);
  const inner = detectFormat(raw);
  process.stdout.write(
    `${c.bold(c.cyan("gzip stream"))}\n` +
      pairs([
        ["compressed", humanBytes(buffer.length)],
        ["unpacked", humanBytes(raw.length)],
        ["inner format", inner ? inner.label : "unrecognised binary"],
        ["inner head", raw.subarray(0, 16).toString("hex")]
      ]) +
      "\n"
  );
  process.stdout.write(c.dim("  decompress and inspect: gunzip <file> then rea info <file>\n"));
}
