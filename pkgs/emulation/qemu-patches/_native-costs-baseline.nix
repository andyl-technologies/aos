# Pins the original native bodies used by the round-two differential proofs.
# The reconstruction patch retains the licenses of its target QEMU files.
{
  revision = "33343f63cb5e8749caadcb251c6b8a90ed0482cf";
  tree = "4f24df196ef8364bf75a61fd22b7f6e054f9fa4c";
  patch = ./native-costs-baseline-reconstruction.patch;
  patchSha256 = "233da2c0995e013c411d6d36f702376de61a48efcff3bcb65c335dfeb7d88e96";
  files = {
    "include/qemu/qtree.h" = "b48246fba9dc199cfc3c77678ed7421d75c4f4c267c6ff42d669110b54ed871b";
    "include/qemu/compiler.h" = "9640b9e818058e7872f42dbdba89b2605a6c66b7ccb7ce0a3836d1a902787f24";
    "accel/tcg/tb-internal.h" = "0d437053278e699d6922d3857414427d5c896ed287ea41e25baf91bef3f1618b";
    "util/qemu-thread-posix.c" = "57c849f96643df51e8c2fe86bde167331f0e51b9cc6b9dbdf1467d84d7d1a4e2";
    "accel/tcg/tb-maint.c" = "4ad4642f875eb795ee474cc5f15c67cc9a3b76e14bf74818061218301965ff51";
    "include/exec/translation-block.h" = "2ba7a971c8b362fa177d8bc0c75c8c56bd88971c101c852801346a3bf4624d5b";
  };
}
