// Wraps only the existing fixed proxy transport; ingress and token checks stay original.
import { createProxy } from "./baseline-proxy.mjs";
import { createObservedHandler } from "./capture.mjs";

export function createCapturedProxy(configuration, capturePolicy, sink,
                                    transport = fetch, clock = () => Math.floor(Date.now() / 1000)) {
  return createObservedHandler(async (request, secrets) => {
    // Baseline omitted this signal. Explicit propagation is a disclosed change:
    // cancellation reaches the single original transport, without another fetch.
    const selectedTransport = outgoing => transport(new Request(outgoing, { signal: request.signal }));
    return createProxy(configuration, selectedTransport, clock)(request, secrets);
  }, "origin_proxy", capturePolicy, sink, clock);
}
