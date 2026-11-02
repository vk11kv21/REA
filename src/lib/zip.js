/**
 * ZIP central-directory reader.
 * No decompression needed: entry names and sizes tell you most of what matters
 * when triaging an APK, JAR, DOCX, XPI or plain archive.
 */

const EOCD_SIGNATURE = 0x06054b50;
const CENTRAL_SIGNATURE = 0x02014b50;

const METHODS = {
  0: "stored",
  8: "deflate",
  9: "deflate64",
  12: "bzip2",
  14: "lzma",
  93: "zstd",
  95: "xz",
  99: "aes"
};

/**
 * @param {Buffer} buffer
 * @returns {{ entries: Array<{name:string, method:number, methodName:string, compressedSize:number, size:number, isDirectory:boolean, encrypted:boolean, crc32:number}>, comment: string }}
 */
export function parseZip(buffer) {
  if (!Buffer.isBuffer(buffer) || buffer.length < 22) throw new Error("file too small to be a ZIP archive");

  const eocd = findEocd(buffer);
  if (eocd === -1) throw new Error("not a ZIP archive (no end-of-central-directory record)");

  const entryCount = buffer.readUInt16LE(eocd + 10);
  const directorySize = buffer.readUInt32LE(eocd + 12);
  const directoryOffset = buffer.readUInt32LE(eocd + 16);
  const commentLength = buffer.readUInt16LE(eocd + 20);
  const comment = buffer
    .subarray(eocd + 22, Math.min(eocd + 22 + commentLength, buffer.length))
    .toString("latin1");

  if (entryCount === 0xffff || directoryOffset === 0xffffffff) {
    // ZIP64: sizes live in a separate record. Report what we can instead of guessing.
    return { entries: [], comment, zip64: true };
  }

  const entries = [];
  let cursor = directoryOffset;
  for (let i = 0; i < entryCount; i += 1) {
    if (cursor + 46 > buffer.length || buffer.readUInt32LE(cursor) !== CENTRAL_SIGNATURE) break;
    const flags = buffer.readUInt16LE(cursor + 8);
    const method = buffer.readUInt16LE(cursor + 10);
    const crc32 = buffer.readUInt32LE(cursor + 16);
    const compressedSize = buffer.readUInt32LE(cursor + 20);
    const size = buffer.readUInt32LE(cursor + 24);
    const nameLength = buffer.readUInt16LE(cursor + 28);
    const extraLength = buffer.readUInt16LE(cursor + 30);
    const commentSize = buffer.readUInt16LE(cursor + 32);
    const name = buffer
      .subarray(cursor + 46, Math.min(cursor + 46 + nameLength, buffer.length))
      .toString("utf8");

    entries.push({
      name,
      method,
      methodName: METHODS[method] ?? `method ${method}`,
      compressedSize,
      size,
      isDirectory: name.endsWith("/"),
      encrypted: Boolean(flags & 0x1),
      crc32
    });

    cursor += 46 + nameLength + extraLength + commentSize;
  }

  return { entries, comment, zip64: false, directorySize };
}

function findEocd(buffer) {
  const start = Math.max(0, buffer.length - 0xffff - 22);
  for (let offset = buffer.length - 22; offset >= start; offset -= 1) {
    if (buffer.readUInt32LE(offset) === EOCD_SIGNATURE) return offset;
  }
  return -1;
}

/** Heuristic APK detection: a ZIP that contains an Android manifest and classes.dex. */
export function looksLikeApk(entries) {
  const names = new Set(entries.map(entry => entry.name));
  return names.has("AndroidManifest.xml") && [...names].some(name => /^classes\d*\.dex$/.test(name));
}
