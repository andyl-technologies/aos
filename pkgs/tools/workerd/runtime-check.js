import assert from 'node:assert/strict';
import { Buffer } from 'node:buffer';

export const runtime = {
  async test() {
    const response = new Response(JSON.stringify({ answer: 42 }), {
      headers: { 'content-type': 'application/json' },
    });
    assert.deepEqual(await response.json(), { answer: 42 });
    assert.equal(Buffer.from('Workers').toString('base64'), 'V29ya2Vycw==');

    const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode('abc'));
    assert.equal(Buffer.from(digest).toString('hex'),
      'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');

    const payload = 'source-built Workers runtime';
    const compressed = new Blob([payload]).stream().pipeThrough(new CompressionStream('gzip'));
    const restored = compressed.pipeThrough(new DecompressionStream('gzip'));
    assert.equal(await new Response(restored).text(), payload);

    const formatter = new Intl.DateTimeFormat('en-US', {
      timeZone: 'UTC', year: 'numeric', month: '2-digit', day: '2-digit',
    });
    assert.equal(formatter.format(new Date('2026-08-01T00:00:00Z')), '08/01/2026');
  },
};
