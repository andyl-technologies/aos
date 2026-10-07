// Controlled SDK-boundary tests; these are not workerd or provider receipts.
import assert from 'node:assert/strict';
import test from 'node:test';
import { canonicalDigest, queueJobDigest, QUEUE_FAULT_PREFIX, QUEUE_CAPTURE_PREFIX, wrapDirectQueueFaults }
  from './_hub-direct-queue-fault-worker.mjs';

function original() {
  return { version: 1,
    admission: { sessionId: 'retained-original', logicalFingerprint: 'a'.repeat(64) },
    complete: { operationId: 'retained-complete' }, placementId: '1',
    closed: { kind: 'managed', object: { version: 'actual-controlled-version' } } };
}

async function fixture(fault, { rejectSend = false, capture = null } = {}) {
  const job = original();
  const rows = [];
  const captures = [];
  const calls = { sends: 0, acknowledgements: 0, reads: 0, puts: 0 };
  const bucket = {
    async put(key, body, options) {
      assert.equal(this, bucket);
      calls.puts += 1;
      assert.deepEqual(options.onlyIf, { etagDoesNotMatch: '*' });
      assert.equal(new TextDecoder().decode(body), JSON.stringify(job));
      if (capture) return capture({ key, body, options, job });
      return { key, size: body.byteLength };
    },
  };
  const queue = {
    async send(body, options) {
      assert.equal(this, queue);
      assert.equal(body, job);
      assert.deepEqual(options, { contentType: 'json' });
      calls.sends += 1;
      if (rejectSend) throw new Error('Controlled unknown SDK outcome');
      return { controlled: 'SDK returned' };
    },
  };
  const worker = {
    async fetch(_request, env) { return env.HUB_DIRECT_VERIFY_BULK.send(job, { contentType: 'json' }); },
    async queue(batch) {
      for (const message of batch.messages) {
        // Model the production journal's positive replay without a fresh read.
        if (!calls.reads) calls.reads += 1;
        message.ack();
      }
    },
  };
  const selection = { version: 1, sourceDigest: 'b'.repeat(64), runDigest: 'c'.repeat(64),
    admissionDigest: await canonicalDigest(job.admission), completeDigest: await canonicalDigest(job.complete),
    placementId: '1', binding: 'HUB_DIRECT_VERIFY_BULK', fault,
    capture: { version: 1, binding: 'REGISTRY_BUCKET',
      prefix: `.aos-queue-fault-capture/${'c'.repeat(64)}/`, cutoffUnixMs: Date.now() + 30_000 } };
  const wrapped = wrapDirectQueueFaults(worker, selection, line => {
    if (line.startsWith(QUEUE_CAPTURE_PREFIX)) {
      captures.push(JSON.parse(line.slice(QUEUE_CAPTURE_PREFIX.length)));
    } else {
      assert.ok(line.startsWith(QUEUE_FAULT_PREFIX));
      rows.push(JSON.parse(line.slice(QUEUE_FAULT_PREFIX.length)));
    }
  });
  const message = { body: job, ack() { assert.equal(this, message); calls.acknowledgements += 1; } };
  return { job, rows, captures, calls, selection, worker, wrapped,
    env: { HUB_DIRECT_VERIFY_BULK: queue, REGISTRY_BUCKET: bucket }, batch: { messages: [message] } };
}

test('enqueue loses only the selected caller ACK after the actual SDK returns', async () => {
  const peer = await fixture('enqueue_ack_lost');
  await assert.rejects(peer.wrapped.fetch(null, peer.env), /acknowledgement lost/);
  assert.equal(peer.calls.sends, 1);
  assert.deepEqual(peer.rows.filter(row => row.kind.startsWith('enqueue_')).map(row => row.kind),
    ['enqueue_dispatch', 'enqueue_sdk_return', 'enqueue_ack_dropped']);
  assert.equal(peer.rows.find(row => row.kind === 'enqueue_ack_dropped').sdkReturned, true);

  await peer.wrapped.fetch(null, peer.env);
  assert.equal(peer.calls.sends, 2);
  assert.equal(peer.calls.puts, 1);
  assert.equal(peer.rows.filter(row => row.kind === 'enqueue_ack_dropped').length, 1);
});

test('baseline captures actual selected argument once without changing queue receiver or options', async () => {
  const peer = await fixture('none');
  await peer.wrapped.fetch(null, peer.env);
  await peer.wrapped.fetch(null, peer.env);
  assert.equal(peer.calls.puts, 1);
  assert.equal(peer.calls.sends, 2);
  assert.equal(peer.captures.length, 1);
  assert.equal(peer.captures[0].state, 'captured');
  assert.equal(peer.captures[0].jobDigest, await queueJobDigest(peer.job));
  assert.equal(peer.captures[0].queueServerAcceptance, null);
  assert.ok(!JSON.stringify(peer.captures).includes('retained-original'));
});

test('missing, refused and unknown capture never dispatch or rewrite a selected queue job', async () => {
  for (const capture of [async () => null, async () => { throw new Error('private sink error'); }]) {
    const peer = await fixture('none', { capture });
    await assert.rejects(peer.wrapped.fetch(null, peer.env));
    await assert.rejects(peer.wrapped.fetch(null, peer.env));
    assert.equal(peer.calls.sends, 0);
    assert.equal(peer.calls.puts, 1);
    assert.notEqual(peer.captures[0].state, 'captured');
    assert.ok(!JSON.stringify(peer.captures).includes('private sink error'));
  }
  const peer = await fixture('none');
  delete peer.env.REGISTRY_BUCKET;
  await assert.rejects(peer.wrapped.fetch(null, peer.env), /binding/);
  assert.equal(peer.calls.sends, 0);
});

test('capture latency cannot dispatch after original cutoff or mutated argument', async () => {
  const clock = Date.now;
  try {
    let now = clock();
    Date.now = () => now;
    const expired = await fixture('none', { capture: async ({ key, body }) => {
      now += 31_000;
      return { key, size: body.byteLength };
    } });
    await assert.rejects(expired.wrapped.fetch(null, expired.env), /cutoff/);
    assert.equal(expired.calls.sends, 0);
  } finally {
    Date.now = clock;
  }
  const peer = await fixture('none', { capture: async ({ key, body, job }) => {
    job.closed.object.version = 'changed while awaiting capture';
    return { key, size: body.byteLength };
  } });
  await assert.rejects(peer.wrapped.fetch(null, peer.env), /changed/);
  assert.equal(peer.calls.sends, 0);
});

test('selected oversized close refuses while foreign messages bypass capture unchanged', async () => {
  const peer = await fixture('none');
  peer.job.closed.object.version = 'x'.repeat(64 * 1024);
  await assert.rejects(peer.wrapped.fetch(null, peer.env), /bound/);
  assert.equal(peer.calls.sends, 0);
  assert.equal(peer.calls.puts, 0);
  peer.job.admission.sessionId = 'foreign';
  await peer.wrapped.fetch(null, peer.env);
  assert.equal(peer.calls.sends, 1);
  assert.equal(peer.calls.puts, 0);
});

test('unknown SDK enqueue outcome cannot become an injected positive receipt', async () => {
  const peer = await fixture('enqueue_ack_lost', { rejectSend: true });
  await assert.rejects(peer.wrapped.fetch(null, peer.env), /unknown SDK/);
  assert.equal(peer.calls.sends, 1);
  assert.equal(peer.rows.find(row => row.kind === 'enqueue_sdk_return').outcome, 'unknown');
  assert.equal(peer.rows.filter(row => row.kind === 'enqueue_ack_dropped').length, 0);
});

test('completion ACK loss preserves actual job and permits ordinary redelivery', async () => {
  const peer = await fixture('completion_ack_lost');
  await assert.rejects(peer.wrapped.queue(peer.batch, peer.env), /acknowledgement lost/);
  assert.equal(peer.calls.acknowledgements, 0);
  assert.equal(peer.calls.reads, 1);
  assert.equal(peer.rows.find(row => row.kind === 'completion_ack_dropped').sdkReturned, false);

  await peer.wrapped.queue(peer.batch, peer.env);
  assert.equal(peer.calls.acknowledgements, 1);
  assert.equal(peer.calls.reads, 1);
  const jobs = peer.rows.filter(row => row.kind === 'invocation_jobs');
  assert.equal(jobs.length, 2);
  assert.equal(jobs[0].jobDigest, await queueJobDigest(peer.job));
  assert.equal(jobs[0].jobDigest, jobs[1].jobDigest);
  assert.equal(jobs[0].batchMessages, 1);
});

test('foreign original is never selected or modified by the wrapper', async () => {
  const peer = await fixture('completion_ack_lost');
  peer.job.admission.sessionId = 'other-original';
  await peer.wrapped.queue(peer.batch, peer.env);
  assert.equal(peer.calls.acknowledgements, 1);
  assert.equal(peer.rows.filter(row => row.kind === 'completion_ack_dropped').length, 0);
  assert.equal(peer.rows.find(row => row.kind === 'invocation_jobs').selectedMessages, 0);
});

test('selection mutation, extra authority fields and wrong bindings refuse', async () => {
  const peer = await fixture('none');
  const fields = [ { providerReady: true }, { sourceDigest: null }, { fault: 'authorize' },
    { binding: 'HUB_AUTHORITY_ISSUER' }, { placementId: '01' } ];
  for (const change of fields) {
    assert.throws(() => wrapDirectQueueFaults(peer.worker, { ...peer.selection, ...change }), /selection/);
  }
  peer.selection.fault = 'completion_ack_lost';
  await peer.wrapped.queue(peer.batch, peer.env);
  assert.equal(peer.calls.acknowledgements, 1);
});

test('job commitment binds source close and never logs private material', async () => {
  const peer = await fixture('none');
  const before = await queueJobDigest(peer.job);
  peer.job.closed.object.version = 'changed-source-version';
  assert.notEqual(await queueJobDigest(peer.job), before);
  await peer.wrapped.queue(peer.batch, peer.env);
  const encoded = JSON.stringify(peer.rows);
  assert.ok(!encoded.includes('changed-source-version'));
  assert.ok(!encoded.includes('retained-original'));
  assert.ok(!encoded.includes('retained-complete'));
  await assert.rejects(queueJobDigest({ ...peer.job, leakedUrl: 'https://fixture.test' }));
});

test('whole invocation begins before any selected job hashing and finishes on error', async () => {
  const peer = await fixture('none');
  await assert.rejects(peer.wrapped.queue({ messages: Array(33).fill(peer.batch.messages[0]) }, peer.env));
  assert.deepEqual(peer.rows.map(row => row.kind), ['invocation_start', 'invocation_finish']);
  assert.equal(peer.rows[1].outcome, 'threw');
  assert.equal(peer.calls.reads, 0);
});

test('mutation while matching the original admission refuses before capture and SDK send', async () => {
  const peer = await fixture('none');
  const actualCrypto = globalThis.crypto;
  let matched = false;
  Object.defineProperty(globalThis, 'crypto', { configurable: true, value: {
    getRandomValues: actualCrypto.getRandomValues.bind(actualCrypto),
    subtle: { async digest(algorithm, body) {
      const result = await actualCrypto.subtle.digest(algorithm, body);
      if (!matched) {
        matched = true;
        peer.job.admission.sessionId = 'foreign-during-first-hash';
      }
      return result;
    } },
  } });
  try {
    await assert.rejects(peer.wrapped.fetch(null, peer.env), /changed during original matching/);
    assert.equal(peer.calls.puts, 0);
    assert.equal(peer.calls.sends, 0);
  } finally {
    Object.defineProperty(globalThis, 'crypto', { configurable: true, value: actualCrypto });
  }
});

test('outer send fence refuses mutation or expiry in the capture promise handoff', async () => {
  for (const mode of ['mutation', 'expiry']) {
    const peer = await fixture('none');
    const actualCrypto = globalThis.crypto;
    const actualNow = Date.now;
    let digests = 0, finalDigest = false, scheduled = false, expired = false;
    Object.defineProperty(globalThis, 'crypto', { configurable: true, value: {
      getRandomValues: actualCrypto.getRandomValues.bind(actualCrypto),
      subtle: { async digest(algorithm, body) {
        const result = await actualCrypto.subtle.digest(algorithm, body);
        if (++digests === 5) finalDigest = true;
        return result;
      } },
    } });
    Date.now = () => {
      if (finalDigest && !scheduled) {
        scheduled = true;
        // This runs after the callee's final checks but before its awaiting
        // caller resumes. The real SDK must still receive no altered original.
        queueMicrotask(() => {
          if (mode === 'mutation') peer.job.closed.object.version = 'foreign-handoff';
          else expired = true;
        });
      }
      return expired ? peer.selection.capture.cutoffUnixMs + 1 : actualNow();
    };
    try {
      await assert.rejects(peer.wrapped.fetch(null, peer.env), mode === 'mutation' ? /changed after capture/ : /cutoff expired/);
      assert.equal(scheduled, true);
      assert.equal(peer.calls.puts, 1);
      assert.equal(peer.calls.sends, 0);
    } finally {
      Date.now = actualNow;
      Object.defineProperty(globalThis, 'crypto', { configurable: true, value: actualCrypto });
    }
  }
});
