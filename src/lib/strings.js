/**
 * String extraction.
 * ASCII and UTF-16LE runs are pulled straight from the byte stream, which is
 * what you want for crash triage, IOC hunting and spotting hard-coded URLs,
 * paths, registry keys or API endpoints.
 */

/**
 * @param {Buffer} buffer
 * @param {{ min?: number, encoding?: "ascii"|"utf16le"|"both", maxLength?: number }} options
 * @returns {Array<{ offset: number, encoding: string, value: string }>}
 */
export function extractStrings(buffer, { min = 4, encoding = "both", maxLength = 400 } = {}) {
  const results = [];
  const minLength = Math.max(1, Math.floor(min) || 4);

  if (encoding === "ascii" || encoding === "both") {
    results.push(...scanAscii(buffer, minLength, maxLength));
  }
  if (encoding === "utf16le" || encoding === "both") {
    results.push(...scanUtf16(buffer, minLength, maxLength));
  }

  return results.sort((a, b) => a.offset - b.offset);
}

function scanAscii(buffer, minLength, maxLength) {
  const found = [];
  let start = -1;

  for (let i = 0; i <= buffer.length; i += 1) {
    const byte = i < buffer.length ? buffer[i] : 0;
    const printable = byte === 0x09 || (byte >= 0x20 && byte <= 0x7e);

    if (printable && start === -1) start = i;
    if (!printable && start !== -1) {
      const length = i - start;
      if (length >= minLength) {
        const raw = buffer.subarray(start, Math.min(start + maxLength, i)).toString("latin1");
        found.push({ offset: start, encoding: "ascii", value: raw });
      }
      start = -1;
    }
  }
  return found;
}

function scanUtf16(buffer, minLength, maxLength) {
  // UTF-16 strings are not always 2-byte aligned in memory or in file blobs,
  // so scan both alignments and drop the duplicates that the second pass finds.
  const even = scanUtf16Aligned(buffer, 0, minLength, maxLength);
  const odd = scanUtf16Aligned(buffer, 1, minLength, maxLength);
  const merged = [...even, ...odd].sort((a, b) => a.offset - b.offset || b.value.length - a.value.length);

  const kept = [];
  for (const entry of merged) {
    const end = entry.offset + entry.value.length * 2;
    const overlaps = kept.some(other => {
      const otherEnd = other.offset + other.value.length * 2;
      return entry.offset < otherEnd && end > other.offset;
    });
    if (!overlaps) kept.push(entry);
  }
  return kept;
}

function scanUtf16Aligned(buffer, alignment, minLength, maxLength) {
  const found = [];
  let start = -1;
  let chars = 0;
  const limit = buffer.length - 1;

  const flush = () => {
    if (start === -1) return;
    if (chars >= minLength) {
      const byteLength = Math.min(chars, maxLength) * 2;
      found.push({
        offset: start,
        encoding: "utf16le",
        value: buffer.subarray(start, start + byteLength).toString("utf16le")
      });
    }
    start = -1;
    chars = 0;
  };

  for (let i = alignment; i <= limit; i += 2) {
    const low = buffer[i];
    const high = buffer[i + 1];
    const printable = high === 0 && (low === 0x09 || (low >= 0x20 && low <= 0x7e));

    if (printable) {
      if (start === -1) start = i;
      chars += 1;
    } else {
      flush();
    }
  }
  flush();

  return found;
}

/** Case-insensitive substring or RegExp filter. */
export function filterStrings(entries, pattern) {
  if (!pattern) return entries;
  const matcher =
    pattern instanceof RegExp
      ? value => pattern.test(value)
      : value => value.toLowerCase().includes(String(pattern).toLowerCase());
  return entries.filter(entry => matcher(entry.value));
}
