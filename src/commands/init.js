import { existsSync, mkdirSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { UsageError, c } from "../lib/util.js";

const FILES = {
  "rea.json": target => `${JSON.stringify({ version: 1, name: target, createdAt: new Date().toISOString() }, null, 2)}\n`,
  ".gitignore": () =>
    `node_modules/\nreports/\nsamples/*\n!samples/.gitkeep\n*.exe\n*.dll\n*.bin\n`,
  "samples/.gitkeep": () => "",
  "notes/README.md": target =>
    `# Notes — ${target}\n\nWorking notes for the ${target} analysis.\n\n` +
    `- Target:\n- Version / build:\n- Source:\n- Legal basis for analysis:\n\n## Questions\n\n1. What does it do?\n2. How does it start?\n3. What does it talk to?\n\n## Timeline\n\n| Date | Observation | Evidence |\n| --- | --- | --- |\n`,
  "findings/README.md": () =>
    `# Findings\n\nOne file per finding, named after the behaviour you proved.\n\n` +
    `Each finding should answer: what it does, how you know, and the exact command or\n` +
    `artifact that proves it. Prefer hashes, offsets and byte ranges over prose.\n`,
  "reports/.gitkeep": () => ""
};

export default {
  name: "init",
  summary: "Scaffold a case workspace: notes, samples, findings and reports",
  usage: "rea init [dir] [--force]",
  spec: {
    force: { type: "boolean", default: false }
  },
  async run({ positional, options }) {
    const target = resolve(positional[0] ?? ".");
    const name = target.split(/[\\/]/).pop() || "case";

    const created = [];
    const skipped = [];
    for (const [relativePath, render] of Object.entries(FILES)) {
      const path = join(target, relativePath);
      if (existsSync(path) && !options.force) {
        skipped.push(relativePath);
        continue;
      }
      mkdirSync(dirname(path), { recursive: true });
      writeFileSync(path, render(name), "utf8");
      created.push(relativePath);
    }

    if (created.length === 0 && skipped.length > 0) {
      throw new UsageError(`workspace already exists at ${target} (use --force to overwrite)`);
    }

    process.stdout.write(`${c.green("workspace ready")} → ${target}\n`);
    for (const file of created) process.stdout.write(`  ${c.green("+")} ${file}\n`);
    for (const file of skipped) process.stdout.write(`  ${c.dim("=")} ${file} ${c.dim("(exists)")}\n`);
    process.stdout.write(
      `\n${c.dim("next:")}\n` +
        `  put samples in samples/ (never commit them)\n` +
        `  rea scan samples/\n` +
        `  rea report samples/ --out reports/${name}.md\n`
    );
  }
};
