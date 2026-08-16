#!/usr/bin/env node
import { writeFileSync } from 'node:fs'
import { redactSession, summarize } from '../lib/redact.js'

function usage() {
  process.stderr.write(`dsh-redact — scrub secrets from a DSH session log before sharing

Usage:
  dsh-redact <session.jsonl[.zstd]> [--out redacted.jsonl]
  (default out: <input>.redacted.jsonl)
`)
  process.exit(2)
}

const args = process.argv.slice(2)
const file = args.find(a => !a.startsWith('--'))
if (!file || args.includes('--help') || args.includes('-h')) usage()

const outIdx = args.indexOf('--out')
const out = outIdx !== -1 ? args[outIdx + 1] : file.replace(/\.zstd$/, '') + '.redacted.jsonl'
const { text, counts } = redactSession(file)
writeFileSync(out, text)
process.stderr.write(`redacted: ${summarize(counts)}\n`)
process.stdout.write(`${out}\n`)
