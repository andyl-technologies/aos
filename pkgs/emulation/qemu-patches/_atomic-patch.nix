# Authoritative descriptor for the atomic QEMU patch artifact. The underscore
# keeps package discovery from treating this data file as a package derivation.
{
  qemuVersion = "11.1.1";
  qemuSourceHash = "sha256-B5/7/4pxEbvIkCIQfLq/O7/WFNX8nXzGdZkRlqyhJII=";
  qemuSourceUrl = "https://download.qemu.org/qemu-11.1.1.tar.xz";

  file = "crucible-qemu-11.1.1.patch";
  sha256 = "741368532d4c499374634474dab0091fa83f83e609d363b28278bd7edc7dfd6f";
  subject = "crucible: retain received delivery and local lifetime borrows";
  body = "Retain the complete Crucible integration on the sole pinned QEMU base.\nSupply required run and teardown rows with real compiled fixture layouts\nand same-module exported C component providers. Derive modeled allowance\nfrom the genuine backing planner and retain the original 1 MiB refusal.\nAssert exact issued claims, retained roster/worker charges and task plans,\nwhile preserving required-role omissions and every cleanup behavior.\n\nAdmit the actual source-built glibc 2.39 cohort after auditing its GNU\nrelease allocator, TLS and user-stack thread paths. Keep the existing\n2.42 cohort and every loader, allocator, environment and THP refusal.\nThe unchanged bound covers 32 KiB heap/header minimum, 128 KiB top-pad,\n1 MiB morecore fallback, backing-page rounding, actual control requests,\nDTV max-module-id plus 14 surplus and two headers, tcache (64 bins under\n2.39, bounded by 76), and each loaded TLS size plus alignment. Explicit\nuser stacks contain pthread/first TSD/static TLS and bypass stack caches;\nfirst-thread signal setup allocates nothing. Refuse changed environment\ninputs and invalid stacks without charge or birth. Task/TLS accounting\ndoes not prove physical libc backing return.\n\nRepair serialized component dependency closures with literal native helper\nbodies and configured genuine QOM support/linker objects. Keep bounded\ncomponent providers separate from that linked support and preserve original\ncompiler target options. Retain the genuine linked RCU worker after its\nactual callback drain, including its native registry and task census;\nnever erase or relabel the record. Refresh exact input fingerprints.\n\nPreserve configured healthy completion with actual C Bridge/Child placement,\nregistration holder transfer, bounded RUN/teardown task enrollment and entry,\nRUN socket handoff, semaphore lifetime, close/join/control destruction and\nstack/Bridge/Child storage return. Bound join observations by the same\nretained installing and containing deadlines, without renewing admission.\nKeep exact residual history charged. Reach the unavailable-runtime negative\nthrough actual controller reservation before its disclosed scratch input.\nPrepared-family and completion enrollment remain isolated modeled inputs;\nno worker born, ready or returned flag is seeded. These component lifetimes\nqualify no standing, entered Original, production Rust module, Source/CPU\nactivation or launched lifecycle/VM behavior. The mandatory launched capture\nlifecycle refusal remains unchanged.\n\nRetain a completed actual command-reader journal in one paid inline delivery\nowner, including born-negative output. Pin the real receive/member/lender,\nauthenticate thread/process and nonwrapping serials, and retain the exact\noriginal creation output before canonical Runtime transfer. Refuse copied\ncreation/use holders, stale serials, saturation and reissue from the same\nstill-retained receive. Local same-thread uses pin only this lifetime; the\nsingle paid use slot admits no worker, nested or multi-vCPU cohort. Identity\nand use returns consume only on zero under the registry mutex and preserve\nall holders on every negative. Returning local delivery leaves the received\nrequest, module payload epoch and publisher/peer obligations retained.\n\nExercise literal receive/delivery bodies with an actual registered C reader,\nreal mutex/thread/process/runtime storage, and explicit modeled member and\nstanding boundary inputs. These component controls issue no action Original,\nmodule payload ownership, ACK, ActionReturn, Source/CPU activation or launched\nlifecycle qualification. Preserve the mandatory launched-lifecycle refusal.";
  commit = "5e6dec358c268ad30ab8945211fbdd964b205a20";
  tree = "eaca50e66371b3affdd48744bc89e721ab11329c";
  catalogName = "crucible-deterministic-qemu-integration";
  class = "F";
  enforces = "DET-1,DET-35,HFORK-4,HFORK-22,CPERF-5,PATCH-39,QEMU-43,PKG-9";
  capability = "one atomic, reconstructible QEMU 11.1.1 integration artifact provides the versioned Crucible plugin protocol, deterministic execution, exact checkpoint capture and restore, retained hot fork with asynchronous-worker quiescence, device fingerprints, and their build and test plumbing";

  branchRef = "dplecki/received-delivery-lifetime";
  branchModel = "single-atomic-final-state-integration-commit";
  bundle = ./crucible-qemu-11.1.1.bundle;
  bundleSha256 = "c658c992ceac053a29bdc33ee6c7b3741679035ebe25b4bb9810b558dacdd48f";
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
