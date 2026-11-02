import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { parseElf } from "../lib/elf.js";
import { UsageError, c, heading, humanBytes, pairs, table } from "../lib/util.js";

const HARDENING = [
  ["PIE", info => (info.isPie ? "yes" : "no")],
  ["NX stack", info => (info.execStack === null ? "unknown" : info.execStack ? "no (executable stack)" : "yes")],
  ["RELRO", info => (info.hasRelro ? "partial/full" : "no")]
];

export default {
  name: "elf",
  summary: "Parse an ELF executable: headers, sections and hardening flags",
  usage: "rea elf <file> [--json]",
  spec: {
    json: { type: "boolean" }
  },
  async run({ positional, options }) {
    const target = positional[0];
    if (!target) throw new UsageError("elf needs a file");

    const path = resolve(target);
    let buffer;
    try {
      buffer = readFileSync(path);
    } catch {
      throw new UsageError(`cannot read "${target}"`);
    }

    let info;
    try {
      info = parseElf(buffer);
    } catch (error) {
      throw new UsageError(`${target}: ${error.message}`);
    }

    if (options.json) {
      process.stdout.write(`${JSON.stringify({ path, ...info }, null, 2)}\n`);
      return;
    }

    process.stdout.write(`${c.bold(c.cyan(path))}\n`);
    process.stdout.write(
      heading("headers") +
        "\n" +
        pairs([
          ["class", `${info.class}, ${info.endianness}-endian`],
          ["type", info.typeName],
          ["machine", info.machineName],
          ["entry", `0x${info.entry.toString(16)}`],
          ["interpreter", info.interpreter ?? "static (none)"],
          ["segments", String(info.programHeaderCount)],
          ["sections", String(info.sectionCount)]
        ]) +
        "\n"
    );

    process.stdout.write(heading("hardening") + "\n");
    for (const [label, read] of HARDENING) {
      const value = read(info);
      const good = value === "yes" || value === "partial/full";
      process.stdout.write(`  ${c.dim(label.padEnd(10))} ${good ? c.green(value) : c.yellow(value)}\n`);
    }

    const interesting = info.sections
      .filter(section => section.type === "PROGBITS" && section.size > 0)
      .sort((a, b) => b.size - a.size)
      .slice(0, 15);

    process.stdout.write(heading("largest sections") + "\n");
    const rows = interesting.map(section => [
      section.name,
      section.type,
      `0x${section.address.toString(16)}`,
      humanBytes(section.size),
      section.entropy >= 7.2 ? c.yellow(String(section.entropy)) : String(section.entropy)
    ]);
    process.stdout.write(`\n${table(rows, ["name", "type", "address", "size", "entropy"])}\n`);

    const notes = [];
    if (info.execStack) notes.push("executable stack — shellcode-friendly, likely hand-written asm or old build");
    if (!info.isPie) notes.push("no PIE — fixed load address, easier to target with ROP");
    if (!info.hasRelro) notes.push("no RELRO — GOT is writable at runtime");
    if (notes.length > 0) {
      process.stdout.write(heading("observations") + "\n");
      for (const note of notes) process.stdout.write(`  ${c.yellow("•")} ${note}\n`);
      process.stdout.write("\n");
    }
  }
};
