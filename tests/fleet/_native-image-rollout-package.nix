##! Retains exact image dependency roles for a checked-in native scenario module.
{
  pkgs,
  image,
}:
pkgs.mkDerivation {
  pname = "aos-image-qualification";
  version = "1";
  src = ../../pkgs/tests/_aos-image-qualification;
  module = ../../pkgs/tests/_aos-image-qualification;
  moduleDeps = [pkgs.aos];
  runtimeDeps = {
    coreutils = pkgs.coreutils;
    predecessorToplevel = image.predecessorTop;
    predecessorContract = image.predecessorBootContract;
    predecessorExecutor = pkgs.aos.packageRuntime;
    candidateToplevel = image.candidateTop;
    candidateContract = image.candidateBootContract;
    candidateExecutor = image.candidatePackageRuntime;
  };
  phases = [
    {
      name = "install";
      script = ''
        mkdir -p "$out/share/aos-image-qualification"
        cp ${../../pkgs/tests/_aos-image-qualification/module.nix} "$out/share/aos-image-qualification/module.nix"
      '';
    }
  ];
  meta = {
    description = "Retained native image qualification scenario inputs";
    license = "Apache-2.0";
  };
}
