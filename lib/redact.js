/**
 * dsh-redact: scrub secrets/PII from a DeepSeek Harness session artifact so it
 * can be shared (e.g. pasted into a bug report) without leaking credentials.
 * Zero-dependency. Reads a session.jsonl / session.jsonl.zstd, emits a redacted
 * plain-text JSONL and a count report.
 *
 * @module dsh-redact
 */

import { readFileSync } from 'node:fs'
import { zstdDecompressSync } from 'node:zlib'
import { join, sep } from 'node:path'

const ZSTD_MAGIC = 0xFD2FB528
const FILE_MAGIC = Buffer.from([0x28, 0xb5, 0x2f, 0xfd])

function scanFrames(buffer) {
  const frames = []
  let offset = 0
  while (offset < buffer.length) {
    const start = offset
    if (buffer.length - offset < 4 || buffer.readUInt32LE(offset) !== ZSTD_MAGIC) break
    offset += 4
    const d = buffer.readUInt8(offset++)
    const csf = d >>> 6
    const ss = (d & 0x20) !== 0
    const chk = (d & 0x04) !== 0
    const df = d & 0x03
    const db = df === 3 ? 4 : df
    const csb = csf === 0 ? (ss ? 1 : 0) : (1 << csf)
    offset += (ss ? 0 : 1) + db + csb
    for (;;) {
      if (buffer.length - offset < 3) return { frames }
      const bh = buffer.readUIntLE(offset, 3)
      offset += 3
      const last = (bh & 1) !== 0
      const bt = (bh >>> 1) & 3
      offset += bt === 1 ? 1 : (bh >>> 3)
      if (last) break
    }
    if (chk) offset += 4
    frames.push({ start, end: offset })
  }
  return { frames }
}

function decompress(buffer) {
  if (buffer.length >= 4 && buffer.subarray(0, 4).equals(FILE_MAGIC)) {
    const { frames } = scanFrames(buffer)
    return frames.map(f => zstdDecompressSync(buffer.subarray(f.start, f.end)).toString('utf8')).join('')
  }
  return buffer.toString('utf8')
}

function homeToTilde(text, home) {
  if (!home) return text
  const norm = home.replaceAll('\\', '/')
  return text.replaceAll(home, '~').replaceAll(norm, '~')
}

const PATTERNS = [
  { id: 'api-key', re: /\b(?:sk|ghp|gho|github_pat|xox[baprs]|AIza)[-_A-Za-z0-9]{16,}\b/g, repl: '[redacted:api-key]' },
  { id: 'aws-key', re: /\bAKIA[0-9A-Z]{16}\b/g, repl: '[redacted:aws-key]' },
  { id: 'bearer', re: /\b(Bearer|Basic)\s+[A-Za-z0-9._~+/=-]+/gi, repl: '$1 [redacted:token]' },
  { id: 'private-key', re: /-----BEGIN[A-Z ]*PRIVATE KEY-----[\s\S]*?-----END[A-Z ]*PRIVATE KEY-----/g, repl: '[redacted:private-key]' },
  { id: 'email', re: /[\w.+-]+@[\w-]+\.[\w.]+/g, repl: '[redacted:email]' },
  { id: 'secret-assignment', re: /\b((?:api[_-]?key|secret|token|password|passwd|credential|authorization)[\w-]*)\s*[=:]\s*["']?[^\s"',;]+/gi, repl: '$1=[redacted:secret]' },
]

function scrubLine(line, home, counts) {
  let out = homeToTilde(line, home)
  for (const p of PATTERNS) {
    const before = out
    out = out.replace(p.re, p.repl)
    if (out !== before) counts[p.id] = (counts[p.id] ?? 0) + 1
  }
  return out
}

export function redactSession(file, options = {}) {
  const home = options.home ?? process.env.USERPROFILE ?? process.env.HOME
  const plain = decompress(readFileSync(file))
  const counts = {}
  const lines = plain.split(/\r?\n/)
  const out = []
  for (const line of lines) {
    if (line.trim() === '') continue
    out.push(scrubLine(line, home, counts))
  }
  return { text: out.join('\n') + '\n', counts, home }
}

export function summarize(counts) {
  const entries = Object.entries(counts)
  if (entries.length === 0) return 'no secrets detected'
  return entries.map(([k, v]) => `${k}: ${v}`).join(', ')
}
