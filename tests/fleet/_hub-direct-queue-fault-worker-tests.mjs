// Controlled SDK-boundary tests; these are not workerd or provider receipts.
import assert from 'node:assert/strict';
import test from 'node:test';
import { canonicalDigest, queueJobDigest, QUEUE_FAULT_PREFIX, wrapDirectQueueFaults }
  from './_hub-direct-queue-fault-worker.mjs';

function original() {
  return { version: 1,
    admission: { sessionId: 'retained-original', logicalFingerprint: 'a'.repeat(64) },
    complete: { operationId: 'retained-complete' }, placementId: '1',
    closed: { kind: 'managed', object: { version: 'actual-controlled-version' } } };
}

async function fixture(fault, { rejectSend = false } = {}) {
  const job = original();
  const rows = [];
  const calls = { sends: 0, acknowledgements: 0, reads: 0 };
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
    placementId: '1', binding: 'HUB_DIRECT_VERIFY_BULK', fault };
  const wrapped = wrapDirectQueueFaults(worker, selection, line => {
    assert.ok(line.startsWith(QUEUE_FAULT_PREFIX));
    rows.push(JSON.parse(line.slice(QUEUE_FAULT_PREFIX.length)));
  });
  const message = { body: job, ack() { assert.equal(this, message); calls.acknowledgements += 1; } };
  return { job, rows, calls, selection, worker, wrapped,
    env: { HUB_DIRECT_VERIFY_BULK: queue }, batch: { messages: [message] } };
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
  assert.equal(peer.rows.filter(row => row.kind === 'enqueue_ack_dropped').length, 1);
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
