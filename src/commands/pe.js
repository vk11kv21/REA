import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { parsePe } from "../lib/pe.js";
import { UsageError, c, heading, humanBytes, pairs, table } from "../lib/util.js";

export default {
  name: "pe",
  summary: "Parse a Windows PE executable: headers, sections, imports, exports",
  usage: "rea pe <file.exe> [--imports 20] [--json]",
  spec: {
    imports: { type: "number", alias: ["i"], default: 12 },
    json: { type: "boolean" }
  },
  async run({ positional, options }) {
    const target = positional[0];
    if (!target) throw new UsageError("pe needs a file");

    const path = resolve(target);
    let buffer;
    try {
      buffer = readFileSync(path);
    } catch {
      throw new UsageError(`cannot read "${target}"`);
    }

    let info;
    try {
      info = parsePe(buffer);
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
          ["architecture", `${info.machineName}${info.is64 ? " (PE32+)" : " (PE32)"}`],
          ["kind", info.isDll ? "DLL" : "executable"],
          ["built", info.builtAt ?? "unknown"],
          ["entry point", `0x${info.entryPoint.toString(16).padStart(8, "0")} (RVA)`],
          ["image base", `0x${info.imageBase.toString(16)}`],
          ["subsystem", info.subsystemName],
          ["image size", humanBytes(info.sizeOfImage)],
          ["characteristics", info.characteristicNames.join(", ") || "—"],
          ["mitigations", info.dllCharacteristicNames.join(", ") || "none reported"]
        ]) +
        "\n"
    );

    process.stdout.write(heading("sections") + "\n");
    const sectionRows = info.sections.map(section => [
      section.name,
      `0x${section.virtualAddress.toString(16).padStart(8, "0")}`,
      humanBytes(section.rawSize),
      section.permissions || "—",
      section.entropy >= 7.2 ? c.yellow(String(section.entropy)) : String(section.entropy)
    ]);
    process.stdout.write(`\n${table(sectionRows, ["name", "rva", "raw size", "flags", "entropy"])}\n`);

    if (info.imports.length > 0) {
      process.stdout.write(heading(`imports (${info.imports.length} libraries)`) + "\n");
      const rows = info.imports.map(library => [
        library.name,
        String(library.functions.length),
        library.functions.slice(0, options.imports).join(", ") +
          (library.functions.length > options.imports ? `, … +${library.functions.length - options.imports}` : "")
      ]);
      process.stdout.write(`\n${table(rows, ["library", "count", "functions"])}\n`);
    } else {
      process.stdout.write(c.yellow("\n  no import table — unusual; could be packed, bound or a driver\n"));
    }

    if (info.exports) {
      process.stdout.write(
        heading("exports") +
          "\n" +
          pairs([
            ["module", info.exports.name],
            ["base ordinal", String(info.exports.base)],
            ["functions", String(info.exports.functionCount)],
            ["named", String(info.exports.nameCount)]
          ]) +
          "\n"
      );
    }

    const notes = [];
    if (info.isManaged) notes.push("managed .NET assembly — inspect IL with a decompiler");
    if (info.pdbPath) notes.push(`PDB path leaked: ${info.pdbPath}`);
    if (info.overlaySize > 0) notes.push(`overlay: ${humanBytes(info.overlaySize)} past the last section (installer or appended payload)`);
    const packed = info.sections.filter(section => section.entropy >= 7.2);
    if (packed.length > 0) notes.push(`high entropy sections: ${packed.map(s => s.name).join(", ")} (packed or compressed?)`);
    const wx = info.sections.filter(section => section.permissions.includes("write") && section.permissions.includes("execute"));
    if (wx.length > 0) notes.push(`writable+executable sections: ${wx.map(s => s.name).join(", ")}`);
    if (info.imports.length === 0 && !info.isManaged) notes.push("no imports resolved — consider unpacking before deeper analysis");

    if (notes.length > 0) {
      process.stdout.write(heading("observations") + "\n");
      for (const note of notes) process.stdout.write(`  ${c.yellow("•")} ${note}\n`);
      process.stdout.write("\n");
    }
  }
};
