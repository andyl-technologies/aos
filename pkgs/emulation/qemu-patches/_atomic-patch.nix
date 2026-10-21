# Authoritative descriptor for the atomic QEMU patch artifact. The underscore
# keeps package discovery from treating this data file as a package derivation.
{
  qemuVersion = "11.1.1";
  qemuSourceHash = "sha256-B5/7/4pxEbvIkCIQfLq/O7/WFNX8nXzGdZkRlqyhJII=";
  qemuSourceUrl = "https://download.qemu.org/qemu-11.1.1.tar.xz";

  file = "crucible-qemu-11.1.1.patch";
  sha256 = "3126675a5bbbc41fe5a5ff03f1bd40979c87d60b648662f981d0358e504c8883";
  subject = "crucible: bind module payload custody to retained delivery";
  body = "Retain the complete Crucible integration on the sole pinned QEMU base.\nSupply required run and teardown rows with real compiled fixture layouts\nand same-module exported C component providers. Derive modeled allowance\nfrom the genuine backing planner and retain the original 1 MiB refusal.\nAssert exact issued claims, retained roster/worker charges and task plans,\nwhile preserving required-role omissions and every cleanup behavior.\n\nAdmit the actual source-built glibc 2.39 cohort after auditing its GNU\nrelease allocator, TLS and user-stack thread paths. Keep the existing\n2.42 cohort and every loader, allocator, environment and THP refusal.\nThe unchanged bound covers 32 KiB heap/header minimum, 128 KiB top-pad,\n1 MiB morecore fallback, backing-page rounding, actual control requests,\nDTV max-module-id plus 14 surplus and two headers, tcache (64 bins under\n2.39, bounded by 76), and each loaded TLS size plus alignment. Explicit\nuser stacks contain pthread/first TSD/static TLS and bypass stack caches;\nfirst-thread signal setup allocates nothing. Refuse changed environment\ninputs and invalid stacks without charge or birth. Task/TLS accounting\ndoes not prove physical libc backing return.\n\nRepair serialized component dependency closures with literal native helper\nbodies and configured genuine QOM support/linker objects. Keep bounded\ncomponent providers separate from that linked support and preserve original\ncompiler target options. Retain the genuine linked RCU worker after its\nactual callback drain, including its native registry and task census;\nnever erase or relabel the record. Refresh exact input fingerprints.\n\nPreserve configured healthy completion with actual C Bridge/Child placement,\nregistration holder transfer, bounded RUN/teardown task enrollment and entry,\nRUN socket handoff, semaphore lifetime, close/join/control destruction and\nstack/Bridge/Child storage return. Bound join observations by the same\nretained installing and containing deadlines, without renewing admission.\nKeep exact residual history charged. Reach the unavailable-runtime negative\nthrough actual controller reservation before its disclosed scratch input.\nPrepared-family and completion enrollment remain isolated modeled inputs;\nno worker born, ready or returned flag is seeded. These component lifetimes\nqualify no standing, entered Original, production Rust module, Source/CPU\nactivation or launched lifecycle/VM behavior. The mandatory launched capture\nlifecycle refusal remains unchanged.\n\nRetain a completed actual command-reader journal in one paid inline delivery\nowner, including born-negative output. Pin the real receive/member/lender,\nauthenticate thread/process and nonwrapping serials, and retain the exact\noriginal creation output before canonical Runtime transfer. Refuse copied\ncreation/use holders, stale serials, saturation and reissue from the same\nstill-retained receive. Local same-thread uses pin only this lifetime; the\nsingle paid use slot admits no worker, nested or multi-vCPU cohort. Identity\nand use returns consume only on zero under the registry mutex and preserve\nall holders on every negative. Returning local delivery leaves the received\nrequest, module payload epoch and publisher/peer obligations retained.\n\nExercise literal receive/delivery bodies with an actual registered C reader,\nreal mutex/thread/process/runtime storage, and explicit modeled member and\nstanding boundary inputs. These component controls issue no action Original,\nmodule payload ownership, ACK, ActionReturn, Source/CPU activation or launched\nlifecycle qualification. Preserve the mandatory launched-lifecycle refusal.\n\nFirst-bind module payload claim/release with member v3 to the genuine retained\ncomplete child. Keep v2 explicitly payload-unavailable. Journal the exact paid\nSource field, module-local serial and real transition before the masked callback\noutside Source's mutex. Retain every born pair and uncertainty independently of\ncallback status and physical post; refuse local identity return with actual\npayload, borrowers or transition debt. No standing/Original query is inferred.\nSave genuine release destruction/nulling before independent post so a negative\npost cannot resurrect payload debt. Preserve the first release diagnostic even\nwhen a later actual retry consumes; pure local return independently records the\nclosed delivery lifetime. Parent receive and publisher/peer obligations remain.\n\nExercise literal v3 construction/transfer with a real C reader-deposited child\njournal, exact canonical claim and destruction, actual journal-lock borrowers,\nborn-negative custody, half-pair/duplicate binding refusals, copied field/serial\nrefusals, reentrant transition exclusion, partial/contradictory output retention,\nand consumed-before-negative-post cleanup. Installation and standing inputs are\nexplicitly modeled; this is no production Rust child, operational payload use,\naction Original, ACK, ActionReturn, Source activation or VM qualification.";
  commit = "78ca20b4207da90eb2be96e1b1197c72a2135fb7";
  tree = "6ddc7e56a54033cfeba32e0bde421e235715fece";
  catalogName = "crucible-deterministic-qemu-integration";
  class = "F";
  enforces = "DET-1,DET-35,HFORK-4,HFORK-22,CPERF-5,PATCH-39,QEMU-43,PKG-9";
  capability = "one atomic, reconstructible QEMU 11.1.1 integration artifact provides the versioned Crucible plugin protocol, deterministic execution, exact checkpoint capture and restore, retained hot fork with asynchronous-worker quiescence, device fingerprints, and their build and test plumbing";

  branchRef = "dplecki/module-payload-custody";
  branchModel = "single-atomic-final-state-integration-commit";
  bundle = ./crucible-qemu-11.1.1.bundle;
  bundleSha256 = "9d2edb5dbc53255cbf47ab126db68805b59ca7e8c158e2bc37d9c5bcbebaebd4";
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
