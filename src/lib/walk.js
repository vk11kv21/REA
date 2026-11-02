import { readdirSync, statSync } from "node:fs";
import { join, relative } from "node:path";

const SKIP_DIRECTORIES = new Set(["node_modules", ".git", ".hg", ".svn", "$RECYCLE.BIN", "System Volume Information"]);

/**
 * Recursively list regular files under a directory.
 * @returns {Array<{ path: string, relative: string, size: number }>}
 */
export function walk(root, { depth = Infinity, includeHidden = false, skip = SKIP_DIRECTORIES } = {}) {
  const files = [];
  const stack = [{ dir: root, level: 0 }];

  while (stack.length > 0) {
    const { dir, level } = stack.pop();
    let entries;
    try {
      entries = readdirSync(dir, { withFileTypes: true });
    } catch {
      continue;
    }

    for (const entry of entries) {
      if (!includeHidden && entry.name.startsWith(".")) continue;
      const full = join(dir, entry.name);

      if (entry.isDirectory()) {
        if (skip.has(entry.name) || level >= depth) continue;
        stack.push({ dir: full, level: level + 1 });
      } else if (entry.isFile()) {
        let size = 0;
        try {
          size = statSync(full).size;
        } catch {
          continue;
        }
        files.push({ path: full, relative: relative(root, full), size });
      }
    }
  }

  return files.sort((a, b) => a.relative.localeCompare(b.relative));
}
