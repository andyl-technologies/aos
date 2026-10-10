# Authoritative descriptor for the atomic QEMU patch artifact. The underscore
# keeps package discovery from treating this data file as a package derivation.
{
  qemuVersion = "11.1.1";
  qemuSourceHash = "sha256-B5/7/4pxEbvIkCIQfLq/O7/WFNX8nXzGdZkRlqyhJII=";
  qemuSourceUrl = "https://download.qemu.org/qemu-11.1.1.tar.xz";

  file = "crucible-qemu-11.1.1.patch";
  sha256 = "e9ebd32258d9196a6aee7acf0b22feec8bd59ccb390351516c4b6d95560af236";
  subject = "Unlink poll-ready handlers before aio_prepare returns";
  body = "aio_prepare() disables poll mode for the GLib event loop. The final poll in poll_set_started() can link a ready handler into aio_prepare()'s stack-local ready list, and the function returned with the handler still linked. The next aio_add_ready_handler() for that handler unlinked it through node_ready.le_prev, storing NULL into whatever frame had reused the slot.\n\nA hot-fork child's replacement monitor iothread enters the GLib loop with poll mode started and a notification pending. The stale store landed on the saved frame pointer of aio_dispatch(), so g_main_dispatch() faulted reading source flags through a null RBP at address 0x2c.\n\nUnlink the handlers before returning. Each keeps poll_ready, so its next dispatch still runs io_poll_ready() as before. A new test-nested-aio-poll case checks that aio_prepare() leaves the ready handler unlinked and that the next poll still delivers its readiness.";
  commit = "53b5bdeaa02ecc71771532e01210634f4bdb0366";
  tree = "84bddc551e0fd9af749d3c25b49fe2224b15960b";
  catalogName = "crucible-deterministic-qemu-integration";
  class = "F";
  enforces = "DET-1,DET-35,HFORK-4,HFORK-22,CPERF-5,PATCH-39,QEMU-43,PKG-9";
  capability = "one atomic, reconstructible QEMU 11.1.1 integration artifact provides the versioned Crucible plugin protocol, deterministic execution, exact checkpoint capture and restore, retained hot fork with asynchronous-worker quiescence, device fingerprints, and their build and test plumbing";

  branchRef = "dplecki/native-aio-prepare-unlink-atomic";
  branchModel = "single-atomic-final-state-integration-commit";
  bundle = ./crucible-qemu-11.1.1.bundle;
  bundleSha256 = "7d25702b95fa0a93454080a90c99e5d803bc245fe0aa86830c5723bac3a94109";
  baseCommit = "1ed046750938db278a12dc55c6a7934d5fc68c14";
  baseTree = "c08cc386be14139bc835ab077baa0e72ef7ba7ef";
  deterministicAuthorName = "Dylan Plecki";
  deterministicAuthorEmail = "dylan@andyl.com";
  deterministicBaseDate = "2001-01-01T00:00:00Z";
  deterministicPatchDate = "2026-10-10T01:38:50Z";

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
