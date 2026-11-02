/**
 * Shared helpers: argument parsing, terminal colours, tables and formatting.
 * Deliberately dependency-free so the toolkit runs from a bare checkout.
 */
import { stripVTControlCharacters } from "node:util";

export class UsageError extends Error {
  constructor(message, { code = 2 } = {}) {
    super(message);
    this.name = "UsageError";
    this.exitCode = code;
  }
}

const COLOR_OFF =
  process.env.NO_COLOR !== undefined ||
  process.env.TERM === "dumb" ||
  process.argv.includes("--no-color") ||
  (!process.stdout.isTTY && process.env.FORCE_COLOR !== "1");

const paint = (open, close) => value =>
  COLOR_OFF ? String(value) : `\u001b[${open}m${value}\u001b[${close}m`;

export const c = {
  bold: paint(1, 22),
  dim: paint(2, 22),
  red: paint(31, 39),
  green: paint(32, 39),
  yellow: paint(33, 39),
  blue: paint(34, 39),
  magenta: paint(35, 39),
  cyan: paint(36, 39),
  gray: paint(90, 39)
};

/** Visible width, ignoring ANSI colour codes. */
export const width = value => stripVTControlCharacters(String(value ?? "")).length;

/**
 * Render a simple left-aligned table.
 * @param {Array<Array<string|number>>} rows
 * @param {Array<string>|null} headers
 */
export function table(rows, headers = null) {
  const all = headers ? [headers, ...rows] : rows;
  if (all.length === 0) return "";
  const cols = Math.max(...all.map(row => row.length));
  const widths = Array.from({ length: cols }, (_, i) =>
    Math.max(0, ...all.map(row => width(row[i])))
  );

  const line = cells =>
    cells
      .map((cell, i) => {
        const text = String(cell ?? "");
        const pad = widths[i] - width(text) + (i === cols - 1 ? 0 : 2);
        return text + " ".repeat(Math.max(0, pad));
      })
      .join("")
      .trimEnd();

  const out = [];
  if (headers) {
    out.push(line(headers));
    out.push(
      widths.map((w, i) => "─".repeat(w + (i === cols - 1 ? 0 : 2))).join("").trimEnd()
    );
  }
  for (const row of rows) out.push(line(row));
  return out.join("\n");
}

/** 1536 -> "1.5 KB" */
export function humanBytes(bytes) {
  const n = Number(bytes) || 0;
  if (n < 1024) return `${n} B`;
  const units = ["KB", "MB", "GB", "TB"];
  let value = n / 1024;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit += 1;
  }
  return `${value.toFixed(value < 10 ? 1 : 0)} ${units[unit]}`;
}

/** 3.1423 -> "3.142" */
export const round = (value, digits = 3) => Number(Number(value).toFixed(digits));

/** 0x1f -> "0x0000001f" */
export const hex = (value, pad = 0) =>
  "0x" + (Number(value) >>> 0).toString(16).padStart(pad, "0");

export const percent = value => `${(Number(value) * 100).toFixed(0)}%`;

/**
 * Minimal argv parser.
 *
 * spec example:
 *   { min: { type: "number", alias: ["m"], default: 4 } }
 * Tokens after "--" are always positional.
 */
export function parseArgs(argv, spec = {}) {
  const aliasToName = new Map();
  for (const [name, def] of Object.entries(spec)) {
    const kebab = name.replace(/[A-Z]/g, letter => `-${letter.toLowerCase()}`);
    aliasToName.set(name, name);
    aliasToName.set(kebab, name);
    for (const alias of def.alias ?? []) aliasToName.set(alias, name);
  }

  const options = {};
  for (const [name, def] of Object.entries(spec)) {
    if ("default" in def) options[name] = def.default;
  }

  const positional = [];
  for (let i = 0; i < argv.length; i += 1) {
    const arg = String(argv[i]);
    if (arg === "--") {
      positional.push(...argv.slice(i + 1));
      break;
    }
    if (arg === "-" || !arg.startsWith("-")) {
      positional.push(arg);
      continue;
    }

    const body = arg.startsWith("--") ? arg.slice(2) : arg.slice(1);
    const eq = body.indexOf("=");
    const key = eq === -1 ? body : body.slice(0, eq);
    const inline = eq === -1 ? undefined : body.slice(eq + 1);
    let name = aliasToName.get(key);

    // `--no-flag` turns a boolean option off.
    if (!name && key.startsWith("no-")) {
      const positive = aliasToName.get(key.slice(3));
      if (positive && spec[positive].type === "boolean") {
        options[positive] = false;
        continue;
      }
    }
    if (!name) throw new UsageError(`unknown option "${arg}"`);
    const def = spec[name];

    if (def.type === "boolean") {
      options[name] = inline === undefined ? true : inline !== "false";
      continue;
    }

    const value = inline ?? argv[i + 1];
    if (value === undefined) throw new UsageError(`option "${arg}" expects a value`);
    if (inline === undefined) i += 1;

    if (def.type === "number") {
      const num = Number(value);
      if (!Number.isFinite(num)) {
        throw new UsageError(`option "${arg}" expects a number, got "${value}"`);
      }
      options[name] = num;
    } else {
      options[name] = value;
    }
  }

  return { options, positional };
}

/** Print a bold section label, e.g. "── PE headers ──────". */
export function heading(label) {
  const bar = "─".repeat(Math.max(4, 52 - width(label)));
  return `\n${c.bold(c.cyan(label))} ${c.gray(bar)}`;
}

/** Render "key: value" pairs aligned on the colon. */
export function pairs(rows) {
  const keyWidth = Math.max(...rows.map(([key]) => width(key)));
  return rows
    .map(([key, value]) => `${c.dim(key.padEnd(keyWidth))}  ${value}`)
    .join("\n");
}
