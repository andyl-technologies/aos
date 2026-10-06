# Pins the original native bodies used by the round-two differential proofs.
# The reconstruction patch retains the licenses of its target QEMU files.
{
  revision = "33343f63cb5e8749caadcb251c6b8a90ed0482cf";
  tree = "4f24df196ef8364bf75a61fd22b7f6e054f9fa4c";
  patch = ./native-costs-baseline-reconstruction.patch;
  patchSha256 = "7f0700ab3e385707c26c82ace313e08034b55f3dc1b3ef3285a33ae43a986b62";
  files = {
    "util/qemu-thread-posix.c" = "57c849f96643df51e8c2fe86bde167331f0e51b9cc6b9dbdf1467d84d7d1a4e2";
    "accel/tcg/tb-maint.c" = "4ad4642f875eb795ee474cc5f15c67cc9a3b76e14bf74818061218301965ff51";
    "include/exec/translation-block.h" = "2ba7a971c8b362fa177d8bc0c75c8c56bd88971c101c852801346a3bf4624d5b";
  };
}
