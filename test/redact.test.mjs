import test from 'node:test'
import assert from 'node:assert/strict'
import { redactSession, summarize } from '../lib/redact.js'
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

test('scrubs api keys, tokens, emails, private keys, and home paths', () => {
  const dir = mkdtempSync(join(tmpdir(), 'dsh-redact-'))
  const file = join(dir, 'session.jsonl')
  try {
    writeFileSync(file, [
      JSON.stringify({ type: 'session', version: 0, id: 's', cwd: '/home/alice/work', createdAt: 0 }),
      JSON.stringify({ type: 'user/message', seq: 0, time: 0, data: { content: [{ type: 'text', text: 'set OPENAI_API_KEY=sk-abcdef1234567890abcdef and email bob@example.com' }] } }),
      JSON.stringify({ type: 'tool/result', seq: 1, time: 1, data: { message: { content: [{ type: 'text', text: 'Authorization: Bearer abc.def.ghi\n-----BEGIN PRIVATE KEY-----\nMIIabc\n-----END PRIVATE KEY-----' }] } } }),
      '',
    ].join('\n'))
    const { text, counts } = redactSession(file, { home: '/home/alice' })
    assert.ok(!text.includes('sk-abcdef1234567890abcdef'))
    assert.ok(!text.includes('bob@example.com'))
    assert.ok(!text.includes('abc.def.ghi'))
    assert.ok(!text.includes('PRIVATE KEY'))
    assert.ok(!text.includes('/home/alice'))
    assert.ok(text.includes('OPENAI_API_KEY=[redacted:secret]') || text.includes('[redacted:api-key]'))
    assert.equal(summarize(counts).includes('email'), true)
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})
