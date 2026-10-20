# Authoritative descriptor for the atomic QEMU patch artifact. The underscore
# keeps package discovery from treating this data file as a package derivation.
{
  qemuVersion = "11.1.1";
  qemuSourceHash = "sha256-B5/7/4pxEbvIkCIQfLq/O7/WFNX8nXzGdZkRlqyhJII=";
  qemuSourceUrl = "https://download.qemu.org/qemu-11.1.1.tar.xz";

  file = "crucible-qemu-11.1.1.patch";
  sha256 = "1ffb66ea0bdfc9351179535a95cbc8d488f8e5b0fd6c40a5ebd839420274ca7c";
  subject = "tests/unit: retain real CPU receipt geometry wrappers";
  body = "Retain the complete reviewed Crucible source, including bounded worker and\nfactual CPU custody, typed pause return, readiness and physical-end journals,\ncached-writer declarations, Source closure, selector and pipeline/OpenRISC\nchanges. Preserve all existing assertions, bounds, licenses and runtime gates.\n\nThe actual startup-source unit linker reported missing CPU receipt bytes and\nalignment wrappers from its extracted cpu_allocation_identity_locked body.\nSelect exactly those two existing realization definitions through the storage\ngetter tuple. Each delegates to the already linked real QOM producer using\nsizeof or _Alignof the genuine private receipt. No copied layout, constant,\nweak provider or admission substitute is introduced.\n\nRefresh the primary helper's five incoming pins and the changed preexec-purpose\nhelper's incoming pin. Existing Source inputs, roots, selected bodies and\nMeson dependency sets remain unchanged. SDK, production code and licensing\nremain byte-identical; only the two literal wrapper selections and six pins\nchange. Package exactly the reviewed tree with pinned upstream as sole parent.\n\nThis source correction has not been generated, compiled, linked or executed\nhere. The reported actual startup-unit LINK failure remains an execution gap;\nno complete link or test pass is claimed. The earlier bounded-thread correction\ncompiled in the integrating check, which supplies no broader qualification.\n\nThis is WIP local source integrity, not provider, runtime, lifecycle,\nactivation, production or performance qualification. Earlier Source-unit\nevidence reached 118 PASS before incomplete genuine reserve_v7 role/provider\nrosters refused with EINVAL. Those assertions and failure remain. Genuine\nroles, matched providers, funding, task custody, census, allocator/TLS/TSD and\nselected positive CPU custody remain unjoined.\n\nThe mandatory genuine launched capture lifecycle still fails explicitly.\nActual cursor/refusal, Original/post, rearm, sticky failure and physical\ncleanup obligations remain; component controls cannot satisfy those gates.\nNo support, preinit, activation, child reconstruction or fork grant is issued.";
  commit = "652fbfb40f97c912eecd2fd9b18b79f9ebd491c6";
  tree = "6f5c8fc942db8f4806623ba452a1869e9b251faa";
  catalogName = "crucible-deterministic-qemu-integration";
  class = "F";
  enforces = "DET-1,DET-35,HFORK-4,HFORK-22,CPERF-5,PATCH-39,QEMU-43,PKG-9";
  capability = "one atomic, reconstructible QEMU 11.1.1 integration artifact provides the versioned Crucible plugin protocol, deterministic execution, exact checkpoint capture and restore, retained hot fork with asynchronous-worker quiescence, device fingerprints, and their build and test plumbing";

  branchRef = "dplecki/cpu-receipt-geometry-extraction";
  branchModel = "single-atomic-final-state-integration-commit";
  bundle = ./crucible-qemu-11.1.1.bundle;
  bundleSha256 = "3687cc1151a12e97559f6da6306e6dd3f8313eaa8c55308c92fc0d9b43ed1e4d";
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
