# Authoritative descriptor for the atomic QEMU patch artifact. The underscore
# keeps package discovery from treating this data file as a package derivation.
{
  qemuVersion = "11.1.1";
  qemuSourceHash = "sha256-B5/7/4pxEbvIkCIQfLq/O7/WFNX8nXzGdZkRlqyhJII=";
  qemuSourceUrl = "https://download.qemu.org/qemu-11.1.1.tar.xz";

  file = "crucible-qemu-11.1.1.patch";
  sha256 = "15afc27d5431a19f9683b2c222acb49fc27303a13128ed267df4be1507872752";
  subject = "crucible: exercise RAM inventory with the complete native provider";
  body = "Retain the complete Crucible integration on the sole pinned QEMU base.\nUse the full native thread translation unit in the RAM inventory fixture,\nwith appended test-only accessors into its actual private registry. Build\nthe coordinator through its real constructor and preserve the historical\nnegative records as explicit standalone corruption inputs. Keep actual\nmembership identity, lock observations, diagnostics and return assertions.\n\nRecover the provider compile tuple and genuine utility, event-loop and QOM\nsupport from the owning configured build. Retain the component and both\nprovider objects, record their identities and verify a single provider in\neach link. Remove original dependency-output side effects and preserve\nconfigured inputs. Delete only the two actual end gate-clear writes in\nthe mutant and require its existing native_end_complete assertion.\n\nValidate the stopped-rearm fixture's authoritative QOM header before output\ncreation and emit its actual object_unref declaration. Retain that component\nobject for the owning runner's symbol audit. Refresh the RAM emitter's\ngenuine incoming fingerprints without changing inventories or validators.\n\nPreserve all other source blobs, modes, licenses, ABI, assertions, causal\ncontrols, limits and experimental support policy. Actual component symbol\nisolation, genuine provider linkage and runtime controls remain for the\nnormal owning runner. No Source or CPU activation, positive RCU grace,\nlaunched lifecycle, physical-return or performance qualification is implied.";
  commit = "bb4478755b7db3ab7b7212f0213d94d92c649ede";
  tree = "4a783f096b0d9584600b8cd38e206788dba534b7";
  catalogName = "crucible-deterministic-qemu-integration";
  class = "F";
  enforces = "DET-1,DET-35,HFORK-4,HFORK-22,CPERF-5,PATCH-39,QEMU-43,PKG-9";
  capability = "one atomic, reconstructible QEMU 11.1.1 integration artifact provides the versioned Crucible plugin protocol, deterministic execution, exact checkpoint capture and restore, retained hot fork with asynchronous-worker quiescence, device fingerprints, and their build and test plumbing";

  branchRef = "dplecki/ram-worker-real-provider-v2";
  branchModel = "single-atomic-final-state-integration-commit";
  bundle = ./crucible-qemu-11.1.1.bundle;
  bundleSha256 = "b470bc76379d645b7bb628b86977ebc4cc347102d146416987f7ccc5a9d4095c";
  baseCommit = "1ed046750938db278a12dc55c6a7934d5fc68c14";
  baseTree = "c08cc386be14139bc835ab077baa0e72ef7ba7ef";
  deterministicAuthorName = "Dylan Plecki";
  deterministicAuthorEmail = "dylan@andyl.com";
  deterministicBaseDate = "2001-01-01T00:00:00Z";
  deterministicPatchDate = "2001-01-01T00:00:00Z";

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
