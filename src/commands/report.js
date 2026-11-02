import { closeSync, openSync, readFileSync, readSync, statSync, writeFileSync } from "node:fs";
import { dirname, relative, resolve } from "node:path";
import { detectFormat, describeUnknown } from "../lib/format.js";
import { hashBuffer, shannon } from "../lib/entropy.js";
import { parseElf } from "../lib/elf.js";
import { parsePe } from "../lib/pe.js";
import { looksLikeApk, parseZip } from "../lib/zip.js";
import { walk } from "../lib/walk.js";
import { UsageError, c, humanBytes, round } from "../lib/util.js";

const FULL_READ_LIMIT = 32 * 1024 * 1024;

const mdCell = value => String(value ?? "").replace(/\|/g, "\\|").replace(/\n/g, " ");

/** Read at most `limit` bytes from the start of a file. */
function readHead(path, limit) {
  const fd = openSync(path, "r");
  try {
    const buffer = Buffer.alloc(limit);
    const read = readSync(fd, buffer, 0, limit, 0);
    return buffer.subarray(0, read);
  } finally {
    closeSync(fd);
  }
}

const mdTable = (headers, rows) =>
  [
    `| ${headers.map(mdCell).join(" | ")} |`,
    `| ${headers.map(() => "---").join(" | ")} |`,
    ...rows.map(row => `| ${row.map(mdCell).join(" | ")} |`)
  ].join("\n");

export default {
  name: "report",
  summary: "Write a markdown triage report for a file or folder",
  usage: "rea report <path> [--out rea-report.md] [--title name] [--depth 6] [--no-hash]",
  spec: {
    out: { type: "string", alias: ["o"] },
    title: { type: "string", alias: ["t"] },
    depth: { type: "number", alias: ["d"], default: 6 },
    hash: { type: "boolean", default: true },
    hidden: { type: "boolean", default: false }
  },
  async run({ positional, options }) {
    const target = positional[0];
    if (!target) throw new UsageError("report needs a file or directory");

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

    const baseDir = stat.isDirectory() ? root : dirname(root);
    const analysis = files.map(file => analyse(file, options.hash, baseDir));
    const outputPath = resolve(options.out ?? `rea-report-${new Date().toISOString().slice(0, 10)}.md`);
    const markdown = buildReport({
      title: options.title ?? (stat.isDirectory() ? root : analysis[0]?.name ?? root),
      root,
      analysis,
      isDirectory: stat.isDirectory()
    });

    writeFileSync(outputPath, markdown, "utf8");
    process.stdout.write(
      `${c.green("report written")} → ${outputPath}\n` +
        c.dim(`  ${analysis.length} file(s), ${analysis.filter(item => item.flags.length > 0).length} flagged\n`)
    );
  }
};

function analyse(file, withHash, baseDir) {
  const buffer =
    file.size <= FULL_READ_LIMIT
      ? readFileSync(file.path)
      : readHead(file.path, 1024 * 1024);
  const truncated = file.size > FULL_READ_LIMIT;
  const format = detectFormat(buffer);
  const record = {
    name: baseDir ? relative(baseDir, file.path) : relative(process.cwd(), file.path),
    size: file.size,
    format: format?.id ?? "unknown",
    formatLabel: format ? format.label : describeUnknown(buffer),
    entropy: round(shannon(buffer)),
    sha256: withHash ? hashBuffer(buffer, ["sha256"]).sha256 : "",
    flags: [],
    details: null
  };

  if (record.entropy >= 7.2) record.flags.push("high entropy (packed or encrypted)");
  if (truncated) record.flags.push("large file: analysed first 1 MB only");

  try {
    if (record.format === "pe") {
      const info = parsePe(buffer);
      record.details = {
        kind: "pe",
        lines: [
          `architecture: ${info.machineName}`,
          `built: ${info.builtAt ?? "unknown"}`,
          `subsystem: ${info.subsystemName}`,
          `imports: ${info.imports.length} libraries`,
          `sections: ${info.sectionCount}`,
          ...(info.pdbPath ? [`pdb: \`${info.pdbPath}\``] : [])
        ],
        sections: info.sections.map(section => [section.name, section.permissions, humanBytes(section.rawSize), section.entropy])
      };
      if (info.imports.length === 0) record.flags.push("no import table");
      if (info.isManaged) record.flags.push(".NET assembly");
      if (info.overlaySize > 0) record.flags.push(`overlay ${humanBytes(info.overlaySize)}`);
    } else if (record.format === "elf") {
      const info = parseElf(buffer);
      record.details = {
        kind: "elf",
        lines: [
          `architecture: ${info.machineName} (${info.class})`,
          `type: ${info.typeName}`,
          `pie: ${info.isPie ? "yes" : "no"}`,
          `nx stack: ${info.execStack ? "no" : "yes"}`,
          `relro: ${info.hasRelro ? "yes" : "no"}`
        ]
      };
    } else if (record.format === "zip" || record.format === "apk") {
      const zip = parseZip(buffer);
      record.details = {
        kind: "zip",
        lines: [
          `entries: ${zip.entries.length}`,
          `apk: ${looksLikeApk(zip.entries) ? "yes" : "no"}`
        ],
        entries: zip.entries.slice(0, 10).map(entry => [entry.name, humanBytes(entry.size), entry.methodName])
      };
    }
  } catch {
    record.flags.push("parser could not read this file");
  }

  return record;
}

function buildReport({ title, root, analysis, isDirectory }) {
  const totalBytes = analysis.reduce((sum, item) => sum + item.size, 0);
  const flagged = analysis.filter(item => item.flags.length > 0);

  const lines = [
    `# REA triage report: ${title}`,
    "",
    `- Generated: ${new Date().toISOString()}`,
    `- Target: \`${root}\` (${isDirectory ? "directory" : "file"})`,
    `- Files analysed: ${analysis.length}`,
    `- Total size: ${humanBytes(totalBytes)}`,
    `- Flagged: ${flagged.length}`,
    "",
    "## Inventory",
    "",
    mdTable(
      ["File", "Size", "Format", "Entropy", "SHA-256"],
      analysis
        .sort((a, b) => b.size - a.size)
        .map(item => [item.name, humanBytes(item.size), item.format, item.entropy, item.sha256 || "—"])
    ),
    ""
  ];

  if (flagged.length > 0) {
    lines.push("## Observations", "");
    for (const item of flagged) {
      lines.push(`- \`${item.name}\` — ${item.flags.join("; ")}`);
    }
    lines.push("");
  }

  const detailed = analysis.filter(item => item.details);
  if (detailed.length > 0) {
    lines.push("## Details", "");
    for (const item of detailed) {
      lines.push(`### ${item.name}`, "");
      for (const line of item.details.lines) lines.push(`- ${line}`);
      lines.push("");
      if (item.details.sections) {
        lines.push(mdTable(["Section", "Flags", "Raw size", "Entropy"], item.details.sections), "");
      }
      if (item.details.entries) {
        lines.push(mdTable(["Entry", "Size", "Method"], item.details.entries), "");
      }
    }
  }

  lines.push(
    "## Findings",
    "",
    "- [ ] What is this software and who publishes it?",
    "- [ ] What is the entry point and how does it start?",
    "- [ ] What network endpoints, files and registry keys does it use?",
    "- [ ] Is anything packed, encrypted or intentionally hidden?",
    "",
    "## Next steps",
    "",
    "```sh",
    "# extract strings and look for URLs, paths and keys",
    "rea strings <file> --grep http --limit 100",
    "",
    "# locate packed or encrypted regions",
    "rea entropy <file>",
    "",
    "# dig into a Windows binary",
    "rea pe <file> --imports 40",
    "```",
    "",
    "> Only analyse software you are authorised to examine. Respect licences, terms of service and local law.",
    ""
  );

  return lines.join("\n");
}
