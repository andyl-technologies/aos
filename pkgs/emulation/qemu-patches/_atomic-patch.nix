# Authoritative descriptor for the atomic QEMU patch artifact. The underscore
# keeps package discovery from treating this data file as a package derivation.
{
  qemuVersion = "11.1.1";
  qemuSourceHash = "sha256-B5/7/4pxEbvIkCIQfLq/O7/WFNX8nXzGdZkRlqyhJII=";
  qemuSourceUrl = "https://download.qemu.org/qemu-11.1.1.tar.xz";

  file = "crucible-qemu-11.1.1.patch";
  sha256 = "6403725e28593e96e7a3e2bc417d70fb2cc7d20b1fa03e9813832a8744e9e4e1";
  subject = "crucible: integrate deterministic QEMU execution";
  body = builtins.concatStringsSep "\n" [
    "Integrate Crucible's versioned GPL-side plugin protocol, exact checkpoint,"
    "retained hot fork, fault models, and device fingerprints as one atomic,"
    "reconstructible QEMU 11.1.1 source artifact."
    ""
    "Store converted QEMU_CLOCK_VIRTUAL deadlines internally in picoseconds"
    "for deterministic sim and ordinary TCG. Preserve generic TCG's long timer"
    "horizon, carry exact ns-plus-phase device state through migration, and"
    "ceil-project that state when crossing to a non-TCG accelerator."
    ""
    "Represent ordinary TCG shifts in picoseconds per instruction, retain the"
    "wide virtual clock horizon, and validate fixed and adaptive clock models"
    "before accepting migrated timer state. Preserve fractional virtual timer"
    "phase across adaptive migration and device deadlines."
    ""
    "Keep RISC-V instruction triggers tied to retired instruction counts when"
    "adaptive icount changes its picosecond shift. Exercise fixed and adaptive"
    "timers, migration rejection, and fractional device clocks in QEMU tests."
    ""
    "Model sim at 50 ps per retired instruction and carry exact phase through"
    "CPU budgeting, idle advance, fingerprints, fault events and results."
    "Project an authenticated 4 GHz x86 TSC and retain calendar clock epochs."
    ""
    "Reject malformed clock state and active PPC PMU migration before guest"
    "continuation. Preserve inactive and instruction-only PMU migration,"
    "ordinary-QEMU compatibility, and the GPL/Apache process boundary."
    ""
    "Keep a bottom half alive while a nested poll drains its owner, retain the"
    "hot-fork inventory row through callback accounting, preserve the ARM timer"
    "horizon in picosecond mode, and avoid fw_cfg device lookup when no deferred"
    "service is pending. Wait for NBD export deletion in the upstream iotest."
    ""
    "Yield a repeated x86 PAUSE at a partial RR turn while preserving the first"
    "post-handoff lock attempt and the serialized cursor. This gives contended"
    "firmware spin locks a deterministic handoff without lowering the normal"
    "4096-instruction quantum. Keep PAUSE in its translated block once no"
    "runnable peer remains, so the single-CPU and post-startup paths stay fast."
    ""
    "Commit the in-flight CPU retirement prefix before anchoring an idle"
    "picosecond bias. Keep an opt-in idle-stage and prefix trace so"
    "the exact boundary can be checked without changing replay state."
    ""
    "Represent Linux eventfd-id zero with a nonzero one-based token through"
    "the versioned hot-fork contracts, and reject token overflow. Exercise"
    "zero, positive, and overflowing identities in a QEMU unit test."
    ""
    "Report an unrepresentable armed virtual timer deadline as a distinct"
    "overflow status instead of absence. Keep the full QEMU timer horizon"
    "and exercise the plugin-facing signed projection with wide timers."
    ""
    "Bound long-TB instruction restoration scans with immutable code-owned"
    "checkpoints every 16 rows. Retain strict helper end boundaries and all"
    "target metadata words, reject malformed metadata without exposing partial"
    "outputs, and return the already authenticated TB from the private identity"
    "decoder without changing generic restoration or execution permissions."
    ""
    "Preserve the fractional TCG virtual clock origin when arming relative"
    "coroutine sleeps. Keep nonpositive sleeps immediately eligible, diagnose"
    "unrepresentable deadlines before parking, and exercise actual coroutine"
    "wakeup and timer dispatch with coherent fractional clock samples."
    ""
    "Preserve the exact virtual clock origin for VFIO INTx mmap timeout"
    "arming and pending rearming. Convert configured milliseconds with checked"
    "arithmetic and exercise the actual callbacks, notifier and timer dispatch"
    "with fractional clock samples and explicit IRQ/mmap hardware doubles."
    ""
    "Retain fractional virtual origins in VGA text cursor and blink display"
    "cache deadlines. Preserve the existing periods, mode-change resets and"
    "non-TCG millisecond policy, and exercise actual glyph rendering at exact"
    "fractional boundaries without changing serialized device state."
    ""
    "Preserve fractional CMOS RTC calendar origins and update/alarm deadlines."
    "Keep guest nanosecond interfaces and non-TCG policy, reusing the existing"
    "optional exact-clock migration fields with legacy zero-phase defaults."
    "Exercise actual RTC callbacks and serialized origin-phase round trips."
    ""
    "Preserve fractional NVMe timestamp and power-on elapsed origins."
    "Keep guest millisecond timestamp and whole-hour SMART units, retaining"
    "picosecond remainders until the final elapsed conversion. Add an optional"
    "phase migration subsection with legacy zero-phase defaults and exercise"
    "actual controller timestamp, SMART transfer and serialized phase checks."
    ""
    "Preserve fractional CXL timestamp elapsed origins."
    "Keep the guest unsigned-nanosecond timestamp ABI while retaining the"
    "internal picosecond remainder until the final elapsed conversion."
    "Migrate timestamp state through an optional subsection with legacy"
    "unset defaults and reject malformed sub-nanosecond phases."
  ];
  commit = "71883e595f69dbf9839466b9afdd60340abeb972";
  tree = "d11a7ac8e73ec93541046d96faa10ba13382dc30";
  catalogName = "crucible-deterministic-qemu-integration";
  class = "F";
  enforces = "DET-1,DET-35,HFORK-4,HFORK-22,CPERF-5,PATCH-39,QEMU-43,PKG-9";
  capability = "one atomic, reconstructible QEMU 11.1.1 integration artifact provides the versioned Crucible plugin protocol, deterministic execution, exact checkpoint capture and restore, retained hot fork with asynchronous-worker quiescence, device fingerprints, and their build and test plumbing";

  branchRef = "crucible/qemu-11.1.1";
  branchModel = "single-atomic-final-state-integration-commit";
  bundle = ./crucible-qemu-11.1.1.bundle;
  bundleSha256 = "871a811226b07f8a74de4804e4deab0a7600f5e42e040fccd602ebc08c5e6204";
  baseCommit = "1ed046750938db278a12dc55c6a7934d5fc68c14";
  baseTree = "c08cc386be14139bc835ab077baa0e72ef7ba7ef";
  deterministicAuthorName = "Dylan Plecki";
  deterministicAuthorEmail = "dylan@andyl.com";
  deterministicBaseDate = "2001-01-01T00:00:00Z";
  deterministicPatchDate = "2001-01-01T00:00:01Z";

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
