// Same-URL metadata observation, with exactly one call to the installed handler.
import { createObservedHandler } from "./capture.mjs";

export function createCapturedApplication(handler, capturePolicy, sink, clock) {
  return createObservedHandler(handler, "storage_wrapper", capturePolicy, sink, clock);
}
