# Authoritative descriptor for the atomic QEMU patch artifact. The underscore
# keeps package discovery from treating this data file as a package derivation.
{
  qemuVersion = "11.1.1";
  qemuSourceHash = "sha256-B5/7/4pxEbvIkCIQfLq/O7/WFNX8nXzGdZkRlqyhJII=";
  qemuSourceUrl = "https://download.qemu.org/qemu-11.1.1.tar.xz";

  file = "crucible-qemu-11.1.1.patch";
  sha256 = "b02efd1e950abb3018757f86c79fcd1aade23e19a1b69f382357bbca05f17e45";
  subject = "Own deterministic execution, native console custody and TCG fast paths";
  body = "Bound deterministic TCG execution with versioned control requests, exact\npicosecond deadlines and coherent raw/logical coordinates. Preserve original\nfault, device-I/O, stop and preemption ordering, stopped control transfer,\nordinary RR fixed points and absent-profile fast paths.\n\nReconstruct each child's private mappings, callbacks and Linux epoll state\nunder the authenticated fork barrier before releasing workers. Make the\nnative plugin the sole console reconstruction owner and retire the old\nconsole socket stage. Bind READY, full issued authorization, UART admission\nand output stop to the actual process/resource incarnation and accepted\ndense prefix.\n\nAuthenticate forward idle clock accounting with the original dispatch\nreceipt, including sub-instruction advances. Its private lease grants no\nTCG/UART execution or refill and clears before synchronous timers.\nDistinguish NCCP v2 Acceptance from settled Observation; retain committed\noccurrences privately by value without changing authorization, accepted\ntokens, frontiers or floors. Keep pending fingerprint projection read-only\nand join post-ACK capture to the complete current pair and original native\noccurrence.\n\nKeep small invalidation page-lock sets in four caller-owned sorted entries;\nspill only for a fifth distinct page without releasing held or busy state.\nPreserve acquisition/retry order and precise-SMC cleanup. Track distinct-\npage TB memberships under the page lock, skip discovery only at an exact\nzero, and retain sticky saturation until empty/full flush recovery.\n\nCache only a thread-local TSC search position, validating current array\nlength, source kind and instance before each hit. Preserve activation/value\nreads and fallback searches. Update mutex waiter counts under the existing\nregistry guard with unchanged unsigned wrap, underflow and condition-owner\nsemantics.\n\nSelect owned serial operations through the current backend's inherited class\ncapability and pair begin/end once per operation. Ordinary backends avoid\nnegative QOM type lookups without caching backend identity or changing\nnative authorization, FIFO, loopback, retry or output-stop semantics.\n\nProvide compile-time opt-in, exact-value runtime diagnostics for existing\ncold barrier refusals. Ordinary builds omit this instrumentation; diagnostic\nsnapshots are read-only reports and never establish authority or acceptance.\n\nExtend the existing opt-in diagnostic path to console pre-save refusals.\nReport stopped snapshot custody, control framing, retained Acceptance and\nObservation pair/prefix checks, and raw/logical origin equality as\nindependent read-only samples. Preserve validation order, return values,\ncanonical state and errno; ordinary builds omit the instrumentation. These\nbounded controls use original native predicates and ABI31 mappings with\nmodeled CPU, inventory, clock and I/O providers. Actual loaded device\ncapture and guest continuation remain qualification requirements.\n\nAcquire BQL for out-of-band template and plugin-barrier QUERY before taking\ntemplate and resource locks. Keep stopped-console custody checks, barrier\ncallbacks and refusal propagation unchanged while observing the original\nlock order.\n\nRetain the atomic outstanding observer without a BQL dependency. Exercise\nthe actual template and plugin-barrier handlers with acquired and already-\nowned BQL, original provider-error unwind, and template-before-BQL release\nchecks.\n\nExercise paused control delivery in a physically forked unit dispatcher with\nsettled inherited RR generations, a fresh child wake eventfd and unchanged\nicount. Retain independent parent state and a stopped-transfer cancellation\nnegative. These bounded controls cover extracted native handlers and modeled\nCPU/event providers; full hot-fork reconstruction and fingerprint\npublication remain qualification requirements.\n\nBracket device-only VMState loads with the same stopped console transaction\nas the full-VM loader. Preserve the original pre-load ownership predicates,\nfinish every entered transaction after CPU synchronization or failure, and\nleave failed or partial loads fenced. Keep uninstalled and plugin-disabled\nloader behavior unchanged. Dedicated controls extract the original loader,\nconsole hooks and stopped predicates with bounded CPU, identity and stream\nproviders; they cover refusal, nested ownership, error cleanup and\ncompletion. They do not establish stream compatibility or physical restore\nownership.\n\nA retained output-stop receipt survives acceptance and drain until the next\nUART operation. At its next seal, the installed owner checks that prior\nreceipt. Keeping the completed operation marked active makes the original\naccepted-and-drained predicate reject an already accepted preceding output.\n\nPublish the ring and finish immutable seal metadata before marking the\noperation complete and calling the original owner. Retain BQL and producer\nadmission until the owner returns. On refusal, restore the active-operation\nfence without releasing admission or changing acceptance or authorization.\n\nAdd eight isolated GPL component controls using the configured compiler,\ncurrent protocol headers and extracted original native ownership bodies.\nCover consecutive accepted/drained operations, unaccepted or undrained\noutput, wrong grants, foreign admission, owner refusal, changed\nauthorization and an incomplete operation. Refused state is never reset or\nreused. Assertions must remain enabled. CPU, clock, inventory, READY, QOM\nand VM-stop services are modeled; linked UART, physical continuation,\nABI/license and strict equal-work performance qualification remain separate\nrequirements.\n\nKeep shared memory a versioned public process protocol with checked geometry\nand no native pointers. Retain ABI31/generated protocol headers, per-file\nlicenses and GPL-side QEMU/plugin implementation with complete matching\nsource.\n\nValidate the extracted handler and original atomic observer with the AOS\nconfigured compiler and explicitly retained historical headers and modeled\ninventory, CPU and event providers. Preserve direct unlocked-observer and\ncold-mutation assertion negatives. These controls do not establish actual\nnative console capture or fork custody.\n\nLoaded OOB capture, replay and cleanup, canonical native package checks,\nbound guest continuation, boundary gates and strict equal-work performance\nqualification against current master remain required.\n\nThe exact-to-ordinary timer fixture forked a process after test setup had\nstarted another thread. That child could inherit the QEMU thread-registry\nmutex while its owner vanished, then wait indefinitely during clock setup.\n\nProduce each exact stream with POSIX spawn of the same configured unit\nbinary in a private producer mode. The AOS glibc Linux spawn backend avoids\nthe fork child handler recreating an RCU thread through the inherited mutex.\nKeep the original clock and VMState serialization, all cross-mode\nassertions, and explicit child exit and reap checks. Bound both pipe capture\nand process completion, retaining failed child cleanup.\n\nA test-only linker wrapper holds the actual registry mutex on a separate\ninventory thread while the producer completes. Release and join that thread\nbefore ordinary consumer clock initialization. Other mutex unlocks delegate\nunchanged; production registry and hot-fork permission checks are untouched.\n\nThe generic ADMITTED-to-STOPPED callback can revisit a retained UART\noccurrence after its exact prefix was accepted. A later non-console stop\nthen compares its new generation with the original emission generation\nand refuses.\n\nUse the same private exact-prefix predicate as output retry before\nvalidating outstanding output. Keep the accepted request and body custody,\nthe next UART's acceptance-and-drain requirement, and every unaccepted\noutput flush, CPU, generation and quiescence fence.\n\nSource-extracted controls create genuine writer acceptance. Substituting\nonly the baseline callback reproduces the original refusal for accepted\ndrained and undrained prefixes; the current callback passes all 18 controls.\nThe None-only compatibility fixture also passes. CPU, clock, VM-stop,\nfrontend, resource and scheduling providers remain explicit component\nmodels; this does not qualify a linked UART, running guest or physical cause.";
  commit = "2f36775df0c558569af3e54645b7bb319eebbd51";
  tree = "0b2ec7dd9a80c35a0c01d93542a12e713b63c44a";
  catalogName = "crucible-deterministic-qemu-integration";
  class = "F";
  enforces = "DET-1,DET-35,HFORK-4,HFORK-22,CPERF-5,PATCH-39,QEMU-43,PKG-9";
  capability = "one atomic, reconstructible QEMU 11.1.1 integration artifact provides the versioned Crucible plugin protocol, deterministic execution, exact checkpoint capture and restore, retained hot fork with asynchronous-worker quiescence, device fingerprints, and their build and test plumbing";

  branchRef = "dplecki/native-retired-console-stop-atomic";
  branchModel = "single-atomic-final-state-integration-commit";
  bundle = ./crucible-qemu-11.1.1.bundle;
  bundleSha256 = "51d3ea7175384833a8be7a14f47e0b87a73c07538951bf76e2191f1df95fd93f";
  baseCommit = "1ed046750938db278a12dc55c6a7934d5fc68c14";
  baseTree = "c08cc386be14139bc835ab077baa0e72ef7ba7ef";
  deterministicAuthorName = "Dylan Plecki";
  deterministicAuthorEmail = "dylan@andyl.com";
  deterministicBaseDate = "2001-01-01T00:00:00Z";
  deterministicPatchDate = "2026-10-09T05:10:34Z";

  additionalCapabilities = [
    {
      catalogName = "rr-switch-quantum";
      carriedBy = "crucible-qemu-11.1.1.patch";
      class = "D";
      enforces = "PATCH-44,DET-1,QEMU-43";
      capability = "round-robin vCPU switch boundary pinned to node-icount";
    }
    {
      catalogName = "crucible-plugin-advance-barrier";
      carriedBy = "crucible-qemu-11.1.1.patch";
      class = "D";
      enforces = "PATCH-19,DET-1,INV-10";
      capability = "normal-mainloop barrier orders timer bottom halves before queued advance completion";
    }
    {
      catalogName = "crucible-plugin-device-wake";
      carriedBy = "crucible-qemu-11.1.1.patch";
      class = "D";
      enforces = "PATCH-20,DET-1,INV-10";
      capability = "event-driven device completion through the registered wake fd and normal main loop";
    }
    {
      catalogName = "crucible-net-direct-inject-api";
      carriedBy = "crucible-qemu-11.1.1.patch";
      class = "F";
      enforces = "PATCH-32,DET-18,E18";
      capability = "lossless RX direct-injection status API with no QEMU-private retention or stale private-queue backpressure latch";
    }
  ];
}
