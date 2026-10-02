// Observe the real Worker and inject one selected queue acknowledgement loss.
// This fixture wrapper grants no admission and never constructs a queue job.

export const QUEUE_FAULT_PREFIX = 'direct_queue_fault_observation ';
const DIGEST = /^[0-9a-f]{64}$/;
const BINDINGS = new Set(['HUB_DIRECT_VERIFY_BULK', 'HUB_DIRECT_VERIFY_METADATA']);

function closed(value, fields) {
  return value && typeof value === 'object' && !Array.isArray(value)
    && Object.keys(value).sort().join(',') === [...fields].sort().join(',');
}

function canonical(value) {
  if (value === null || typeof value === 'boolean' || typeof value === 'string') return value;
  if (typeof value === 'number' && Number.isSafeInteger(value)) return value;
  if (Array.isArray(value)) return value.map(canonical);
  if (value && Object.getPrototypeOf(value) === Object.prototype) {
    return Object.fromEntries(Object.keys(value).sort().map(key => [key, canonical(value[key])]));
  }
  throw new Error('Queue fixture requires a bounded JSON job');
}

export async function canonicalDigest(value) {
  const encoded = new TextEncoder().encode(JSON.stringify(canonical(value)));
  if (encoded.byteLength > 64 * 1024) throw new Error('Queue value exceeds its production bound');
  const digest = await crypto.subtle.digest('SHA-256', encoded);
  return [...new Uint8Array(digest)].map(byte => byte.toString(16).padStart(2, '0')).join('');
}

export async function queueJobDigest(job) {
  if (!closed(job, ['version', 'admission', 'complete', 'placementId', 'closed'])
      || job.version !== 1 || !job.admission || !job.complete || !job.closed) {
    throw new Error('Queue fixture refuses a non-production job');
  }
  return canonicalDigest(job);
}

function invocationId() {
  return [...crypto.getRandomValues(new Uint8Array(32))]
    .map(byte => byte.toString(16).padStart(2, '0')).join('');
}

/** Wraps the installed default export with exact job bodies and SDK receivers.
 *
 * The launcher must re-export the installed shim's named Durable Object exports
 * unchanged, bind both module hashes and the selected full job, and retain raw
 * console output. A fresh process loses this wrapper's one-shot latch; its
 * restart is a separate observation, never an assumed persistent disarm.
 */
export function wrapDirectQueueFaults(worker, selection, emit = console.log) {
  if (!closed(selection, ['version', 'sourceDigest', 'runDigest', 'admissionDigest',
    'completeDigest', 'placementId', 'binding', 'fault'])
      || selection.version !== 1
      || ![selection.sourceDigest, selection.runDigest, selection.admissionDigest, selection.completeDigest]
        .every(value => typeof value === 'string' && DIGEST.test(value))
      || typeof selection.placementId !== 'string' || !/^[1-9][0-9]{0,19}$/.test(selection.placementId)
      || !BINDINGS.has(selection.binding)
      || !['none', 'enqueue_ack_lost', 'completion_ack_lost'].includes(selection.fault)
      || typeof worker?.fetch !== 'function' || typeof worker?.queue !== 'function') {
    throw new Error('Queue fault selection or installed export differs');
  }
  const selected = Object.freeze({ ...selection });
  let fired = false;

  async function selectedJob(job) {
    const digest = await queueJobDigest(job);
    if (job.placementId !== selected.placementId
        || await canonicalDigest(job.admission) !== selected.admissionDigest
        || await canonicalDigest(job.complete) !== selected.completeDigest) return null;
    return digest;
  }

  function record(kind, id, fields = {}) {
    emit(QUEUE_FAULT_PREFIX + JSON.stringify({
      version: 1, sourceDigest: selected.sourceDigest, runDigest: selected.runDigest,
      kind, invocationDigest: id, atMillis: Date.now(),
      jobDigest: null, batchMessages: null, selectedMessages: null,
      outcome: 'pending', sdkReturned: null, ...fields,
    }));
  }

  function environment(env, id) {
    return new Proxy(env, {
      get(target, name) {
        const value = Reflect.get(target, name, target);
        if (name !== selected.binding || !value) return value;
        return new Proxy(value, {
          get(queue, method) {
            const original = Reflect.get(queue, method, queue);
            if (method !== 'send') return typeof original === 'function' ? original.bind(queue) : original;
            return async (job, ...options) => {
              // Non-production messages retain their original SDK behavior.
              let digest;
              try { digest = await selectedJob(job); } catch { return original.call(queue, job, ...options); }
              if (!digest || selected.fault !== 'enqueue_ack_lost' || fired) {
                return original.call(queue, job, ...options);
              }
              fired = true;
              record('enqueue_dispatch', id, { jobDigest: digest });
              let reply;
              try {
                reply = await original.call(queue, job, ...options);
              } catch (error) {
                record('enqueue_sdk_return', id, { jobDigest: digest, outcome: 'unknown', sdkReturned: false });
                throw error;
              }
              record('enqueue_sdk_return', id, { jobDigest: digest, outcome: 'positive', sdkReturned: true });
              record('enqueue_ack_dropped', id, { jobDigest: digest, outcome: 'unknown', sdkReturned: true });
              // The original SDK returned, but its caller receives no success.
              // This is not evidence of provider-side queue acceptance.
              void reply;
              throw new Error('Selected queue enqueue acknowledgement lost');
            };
          },
        });
      },
    });
  }

  return {
    ...worker,
    async fetch(request, env, context) {
      const id = invocationId();
      record('fetch_start', id);
      try {
        const reply = await worker.fetch(request, environment(env, id), context);
        record('fetch_finish', id, { outcome: 'returned' });
        return reply;
      } catch (error) {
        record('fetch_finish', id, { outcome: 'threw' });
        throw error;
      }
    },
    async queue(batch, env, context) {
      const id = invocationId();
      record('invocation_start', id);
      try {
        if (!Array.isArray(batch.messages) || batch.messages.length > 32) {
          throw new Error('Observed queue batch exceeds the qualification bound');
        }
        let selectedMessages = 0;
        const messages = await Promise.all(batch.messages.map(async message => {
          let digest;
          try { digest = await selectedJob(message.body); } catch { return message; }
          if (!digest) return message;
          selectedMessages += 1;
          return new Proxy(message, {
            get(target, name) {
              const value = Reflect.get(target, name, target);
              if (name !== 'ack') return typeof value === 'function' ? value.bind(target) : value;
              return (...args) => {
                record('completion_ack_attempt', id, { jobDigest: digest });
                if (selected.fault === 'completion_ack_lost' && !fired) {
                  fired = true;
                  record('completion_ack_dropped', id, { jobDigest: digest, outcome: 'unknown', sdkReturned: false });
                  // Durable verification precedes this actual consumer callback.
                  // Throw before the ACK SDK call; workerd decides redelivery.
                  throw new Error('Selected queue completion acknowledgement lost');
                }
                const reply = value.apply(target, args);
                record('completion_ack_sdk_return', id, { jobDigest: digest, outcome: 'returned', sdkReturned: true });
                return reply;
              };
            },
          });
        }));
        const digests = await Promise.all(messages.map(async message => {
          try { return await selectedJob(message.body); } catch { return null; }
        }));
        const selectedDigests = new Set(digests.filter(Boolean));
        if (selectedDigests.size > 1) throw new Error('One original acquired different closed queue jobs');
        record('invocation_jobs', id, { jobDigest: selectedDigests.values().next().value ?? null,
          batchMessages: messages.length, selectedMessages });
        const observed = new Proxy(batch, {
          get(target, name) {
            if (name === 'messages') return messages;
            const value = Reflect.get(target, name, target);
            return typeof value === 'function' ? value.bind(target) : value;
          },
        });
        const reply = await worker.queue(observed, environment(env, id), context);
        record('invocation_finish', id, { outcome: 'returned' });
        return reply;
      } catch (error) {
        record('invocation_finish', id, { outcome: 'threw' });
        throw error;
      }
    },
  };
}
