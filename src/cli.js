import { readFileSync } from "node:fs";
import info from "./commands/info.js";
import strings from "./commands/strings.js";
import entropy from "./commands/entropy.js";
import pe from "./commands/pe.js";
import elf from "./commands/elf.js";
import archive from "./commands/archive.js";
import scan from "./commands/scan.js";
import report from "./commands/report.js";
import init from "./commands/init.js";
import { UsageError, c, parseArgs } from "./lib/util.js";

const commands = { info, strings, entropy, pe, elf, archive, scan, report, init };

const GLOBAL = {
  json: { type: "boolean" },
  help: { type: "boolean", alias: ["h"] },
  version: { type: "boolean", alias: ["v"] }
};

export async function run(argv) {
  if (argv.length === 0) return printHelp();
  if (argv[0] === "help" || argv[0] === "--help" || argv[0] === "-h") {
    if (argv[1] && commands[argv[1]]) return printCommandHelp(commands[argv[1]]);
    return printHelp();
  }
  if (argv[0] === "--version" || argv[0] === "-v") return printVersion();

  const commandName = argv[0];
  const command = commands[commandName];
  if (!command) throw new UsageError(`unknown command "${commandName}" — run "rea help"`);

  const { options, positional } = parseArgs(argv.slice(1), { ...GLOBAL, ...(command.spec ?? {}) });

  if (options.help) return printCommandHelp(command);
  return command.run({ positional, options, argv: argv.slice(1) });
}

function printVersion() {
  try {
    const pkg = JSON.parse(readFileSync(new URL("../../package.json", import.meta.url), "utf8"));
    process.stdout.write(`rea ${pkg.version}\n`);
  } catch {
    process.stdout.write("rea 0.1.0\n");
  }
}

function printHelp() {
  process.stdout.write(
    `${c.bold("rea")} — dependency-free reverse-engineering triage toolkit\n\n` +
      `Usage: ${c.cyan("rea <command> [options] [files]")}\n\n` +
      `${c.bold("Commands")}\n` +
      `  ${c.cyan("info")}      Identify format, size, hashes and entropy\n` +
      `  ${c.cyan("strings")}   Extract ASCII and UTF-16LE strings\n` +
      `  ${c.cyan("entropy")}   Map entropy to find packed/encrypted regions\n` +
      `  ${c.cyan("pe")}        Parse Windows PE headers, sections, imports\n` +
      `  ${c.cyan("elf")}       Parse ELF headers, sections and hardening\n` +
      `  ${c.cyan("archive")}   Inspect ZIP/APK/JAR contents\n` +
      `  ${c.cyan("scan")}      Triage a directory and flag interesting files\n` +
      `  ${c.cyan("report")}    Write a markdown triage report\n` +
      `  ${c.cyan("init")}      Scaffold a case workspace\n\n` +
      `Global: --json, --no-color, -h/--help, -v/--version\n` +
      `Get help: ${c.cyan("rea help <command>")}\n`
  );
}

function printCommandHelp(command) {
  process.stdout.write(
    `${c.bold(command.name)} — ${command.summary}\n\n` +
      `Usage: ${c.cyan(command.usage)}\n\n`
  );
  if (command.spec) {
    process.stdout.write(`${c.bold("Options")}\n`);
    for (const [name, def] of Object.entries(command.spec)) {
      const kebab = name.replace(/[A-Z]/g, letter => `-${letter.toLowerCase()}`);
      const aliases = (def.alias ?? []).map(a => `-${a}`).join(", ");
      const label = aliases ? `--${kebab} (${aliases})` : `--${kebab}`;
      const type = def.type === "boolean" ? "" : ` <${def.type}>`;
      const defText = "default" in def ? c.dim(` [default: ${def.default}]`) : "";
      process.stdout.write(`  ${c.cyan(label)}${type}${defText}\n`);
    }
    process.stdout.write("\n");
  }
}
