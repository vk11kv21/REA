/**
 * Format identification from magic bytes.
 * Covers the containers you meet first when triaging an unknown blob:
 * executables, archives, firmware images, documents and media.
 */

const ascii = bytes => String.fromCharCode(...bytes);

/** @typedef {{ id: string, label: string, kind: string }} FormatInfo */

const SIGNATURES = [
  // executables / objects
  { id: "pe", label: "Windows PE / DOS executable", kind: "executable", test: b => b[0] === 0x4d && b[1] === 0x5a },
  { id: "elf", label: "ELF executable", kind: "executable", test: b => b[0] === 0x7f && ascii(b.slice(1, 4)) === "ELF" },
  { id: "macho32", label: "Mach-O 32-bit", kind: "executable", test: b => b.readUInt32BE(0) === 0xfeedface },
  { id: "macho64", label: "Mach-O 64-bit", kind: "executable", test: b => b.readUInt32BE(0) === 0xfeedfacf },
  { id: "fatmacho", label: "Mach-O universal binary", kind: "executable", test: b => b.readUInt32BE(0) === 0xcafebabe },
  { id: "wasm", label: "WebAssembly module", kind: "executable", test: b => b.readUInt32BE(0) === 0x0061736d },
  { id: "dex", label: "Android DEX", kind: "executable", test: b => ascii(b.slice(0, 4)) === "dex\n" },
  { id: "class", label: "Java class file", kind: "executable", test: b => b.readUInt32BE(0) === 0xcafebabe && b.length > 8 },
  { id: "luac", label: "Lua bytecode", kind: "executable", test: b => b[0] === 0x1b && ascii(b.slice(1, 4)) === "Lua" },

  // archives / compression
  { id: "zip", label: "ZIP container (APK/JAR/DOCX possible)", kind: "archive", test: b => b.readUInt32LE(0) === 0x04034b50 },
  { id: "gzip", label: "gzip stream", kind: "archive", test: b => b[0] === 0x1f && b[1] === 0x8b },
  { id: "7z", label: "7-Zip archive", kind: "archive", test: b => b.readUInt32BE(0) === 0x377abcaf && b[4] === 0x27 && b[5] === 0x1c },
  { id: "bzip2", label: "bzip2 archive", kind: "archive", test: b => ascii(b.slice(0, 3)) === "BZh" },
  { id: "xz", label: "xz archive", kind: "archive", test: b => b.readUInt32BE(0) === 0xfd377a58 && b[4] === 0x5a },
  { id: "zstd", label: "zstd stream", kind: "archive", test: b => b.readUInt32LE(0) === 0xfd2fb528 },
  { id: "rar", label: "RAR archive", kind: "archive", test: b => ascii(b.slice(0, 4)) === "Rar!" },
  { id: "tar", label: "POSIX tar archive", kind: "archive", test: b => b.length > 262 && ascii(b.slice(257, 262)) === "ustar" },
  { id: "cab", label: "Microsoft Cabinet", kind: "archive", test: b => ascii(b.slice(0, 4)) === "MSCF" },
  { id: "cpio", label: "cpio archive", kind: "archive", test: b => ascii(b.slice(0, 6)) === "070701" },

  // firmware / disk images
  { id: "ubi", label: "UBI image", kind: "firmware", test: b => b.readUInt32BE(0) === 0x55424923 },
  { id: "squashfs", label: "SquashFS filesystem", kind: "firmware", test: b => ascii(b.slice(0, 4)) === "hsqs" },
  { id: "cramfs", label: "CramFS filesystem", kind: "firmware", test: b => b.readUInt32LE(0) === 0x28cd3d45 },
  { id: "uimage", label: "U-Boot legacy image", kind: "firmware", test: b => b.readUInt32BE(0) === 0x27051956 },
  { id: "android_boot", label: "Android boot image", kind: "firmware", test: b => ascii(b.slice(0, 8)) === "ANDROID!" },
  { id: "iso", label: "ISO 9660 image", kind: "firmware", test: b => b.length > 32774 && ascii(b.slice(32769, 32774)) === "CD001" },

  // documents
  { id: "pdf", label: "PDF document", kind: "document", test: b => ascii(b.slice(0, 5)) === "%PDF-" },
  { id: "ole", label: "OLE2 compound file (MSI/DOC/XLS)", kind: "document", test: b => b.readUInt32BE(0) === 0xd0cf11e0 },
  { id: "sqlite", label: "SQLite database", kind: "document", test: b => ascii(b.slice(0, 15)) === "SQLite format 3" },

  // images / media
  { id: "png", label: "PNG image", kind: "media", test: b => b.readUInt32BE(0) === 0x89504e47 },
  { id: "jpeg", label: "JPEG image", kind: "media", test: b => b[0] === 0xff && b[1] === 0xd8 && b[2] === 0xff },
  { id: "gif", label: "GIF image", kind: "media", test: b => ascii(b.slice(0, 3)) === "GIF" },
  { id: "riff", label: "RIFF media (WAV/AVI/WebP)", kind: "media", test: b => ascii(b.slice(0, 4)) === "RIFF" },
  { id: "mp4", label: "ISO base media (MP4/MOV)", kind: "media", test: b => b.length > 12 && ascii(b.slice(4, 8)) === "ftyp" },
  { id: "ogg", label: "Ogg stream", kind: "media", test: b => ascii(b.slice(0, 4)) === "OggS" },
  { id: "mp3", label: "MP3 audio", kind: "media", test: b => ascii(b.slice(0, 3)) === "ID3" }
];

/**
 * Identify a buffer by magic bytes.
 * @param {Buffer} buffer
 * @returns {FormatInfo|null}
 */
export function detectFormat(buffer) {
  if (!Buffer.isBuffer(buffer) || buffer.length < 4) return null;
  for (const sig of SIGNATURES) {
    try {
      if (sig.test(buffer)) return { id: sig.id, label: sig.label, kind: sig.kind };
    } catch {
      // A short or malformed buffer must never break identification.
    }
  }
  if (looksLikeText(buffer)) return { id: "text", label: "plain text", kind: "text" };
  return null;
}

/** True when the sample is almost entirely printable ASCII. */
export function looksLikeText(buffer) {
  const sample = buffer.subarray(0, 2048);
  if (sample.length === 0) return false;
  let printable = 0;
  for (const byte of sample) {
    if (byte === 9 || byte === 10 || byte === 13 || (byte >= 0x20 && byte <= 0x7e)) printable += 1;
  }
  return printable / sample.length > 0.95;
}

/** Human label for an unknown format, heuristics based on the first bytes. */
export function describeUnknown(buffer) {
  if (!Buffer.isBuffer(buffer) || buffer.length === 0) return "empty file";
  const printableRatio =
    buffer.slice(0, 512).filter(byte => byte === 9 || byte === 10 || byte === 13 || (byte >= 0x20 && byte <= 0x7e))
      .length / Math.min(512, buffer.length);
  if (printableRatio > 0.9) return "plain text";
  return "unrecognised binary";
}
