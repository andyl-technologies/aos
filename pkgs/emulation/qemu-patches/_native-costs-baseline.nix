# Pins the original native bodies used by the round-two differential proofs.
# The reconstruction patch retains the licenses of its target QEMU files.
# Its exact generic-atfork addition is reversed only for the original baseline;
# the configured production source retains the reviewed lifecycle repair.
{
  revision = "33343f63cb5e8749caadcb251c6b8a90ed0482cf";
  tree = "4f24df196ef8364bf75a61fd22b7f6e054f9fa4c";
  patch = ./_fixtures/native-costs-baseline-reconstruction.patch;
  patchSha256 = "24a6877b4dc4c36c8e5891407a18c083aa30b56a42f32249d4b205f0fb61a9e2";
  # Reconstruct the same frozen baseline after the signed root-census additions.
  # Only this prototype may differ between the two compiled header sets.
  reviewedAdaptation = {
    revision = "d30f55c938098ba47c94d9ebb30634a1b5412781";
    tree = "eb054f43cad8e39fdeac139adc357800d0673e7c";
    files = {
      "include/qemu/crucible-fault.h" = "6812bb0bdec6267f6c5016194cab967933c6ac75e64d1bc53af38826b61dca18";
      "plugins/crucible-fault-clock.c" = "423fb54eb8ed0fa15449e4b0eac0a59a47f5803f3a891b37d340e4c6879ba272";
    };
    headerAddition = "/* Source-only original disabled wander callback/payload lifetime enrollment. */\nint qemu_crucible_fault_clock_root_dormant_enroll(void);\n";
  };
  clockReference = {
    revision = "79a6ab2419c6bd4f1c8e44a23a43c171b9a3fd22";
    tree = "0bb49a2b3855c2b47f519b78da1450a4ec9b40d8";
    sha256 = "878f8fe9cc0d66652a2aa8f1ee79d5714352bcd87f124b4816f7fc031c080cb8";
  };
  files = {
    "include/qemu/crucible-fault.h" = "87c0fa259bb474c76df379449565c1e3c851cae677634f73898eccf1cdad9edf";
    "plugins/crucible-fault-clock.c" = "878f8fe9cc0d66652a2aa8f1ee79d5714352bcd87f124b4816f7fc031c080cb8";
    "include/qemu/qtree.h" = "b48246fba9dc199cfc3c77678ed7421d75c4f4c267c6ff42d669110b54ed871b";
    "include/qemu/compiler.h" = "9640b9e818058e7872f42dbdba89b2605a6c66b7ccb7ce0a3836d1a902787f24";
    "accel/tcg/tb-internal.h" = "0d437053278e699d6922d3857414427d5c896ed287ea41e25baf91bef3f1618b";
    "util/qemu-thread-posix.c" = "57c849f96643df51e8c2fe86bde167331f0e51b9cc6b9dbdf1467d84d7d1a4e2";
    "accel/tcg/tb-maint.c" = "4ad4642f875eb795ee474cc5f15c67cc9a3b76e14bf74818061218301965ff51";
    "include/exec/translation-block.h" = "2ba7a971c8b362fa177d8bc0c75c8c56bd88971c101c852801346a3bf4624d5b";
  };
}
