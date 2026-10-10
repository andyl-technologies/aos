# Pins the original paged-RAM native bodies used by the differential proofs.
# The reconstruction patch retains the licenses of its target QEMU files.
{
  revision = "d3f2bdbb0ba4851e70c4c9ae9f19a6c88f268d6a";
  tree = "6fa9c59e6c52760b62ec2d1ba66ffc5392992646";
  patch = ./_fixtures/native-costs-baseline-reconstruction.patch;
  patchSha256 = "f7d75336f800ae63dba182dc9f66d313ddf930d0d986b6c55767fd2b7d1a2bd4";
  clockReference = {
    revision = "d3f2bdbb0ba4851e70c4c9ae9f19a6c88f268d6a";
    tree = "6fa9c59e6c52760b62ec2d1ba66ffc5392992646";
    sha256 = "878f8fe9cc0d66652a2aa8f1ee79d5714352bcd87f124b4816f7fc031c080cb8";
  };
  # Both body variants compile against the same current public declarations.
  # This header differs from d3f2 only by the reset-pending prototype;
  # historical implementation bodies and the reconstruction stay exact.
  sharedDeclarations = {
    "include/qemu/crucible-fault.h" = "7298cd0a967fd6f9c78598bec6526c5139991b22489b8137ddab6d893012425b";
  };
  files = {
    "plugins/crucible-fault-clock.c" = "878f8fe9cc0d66652a2aa8f1ee79d5714352bcd87f124b4816f7fc031c080cb8";
    "include/qemu/qtree.h" = "b48246fba9dc199cfc3c77678ed7421d75c4f4c267c6ff42d669110b54ed871b";
    "include/qemu/compiler.h" = "9640b9e818058e7872f42dbdba89b2605a6c66b7ccb7ce0a3836d1a902787f24";
    "accel/tcg/tb-internal.h" = "0d437053278e699d6922d3857414427d5c896ed287ea41e25baf91bef3f1618b";
    "util/qemu-thread-posix.c" = "f4d891068fe1bed1dd047ca00dc50db4e28844c919b6ffc016d15aa9af3b4e79";
    "accel/tcg/tb-maint.c" = "4ad4642f875eb795ee474cc5f15c67cc9a3b76e14bf74818061218301965ff51";
    "include/exec/translation-block.h" = "2ba7a971c8b362fa177d8bc0c75c8c56bd88971c101c852801346a3bf4624d5b";
  };
}
