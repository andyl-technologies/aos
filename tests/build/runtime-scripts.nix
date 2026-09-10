##! Checks runtime interpreter fixups using the real bootstrap shell interface.
{pkgs}:
pkgs.mkDerivation {
  pname = "aos-runtime-script-fixups";
  version = "1";
  src = null;
  buildDeps = [pkgs.python3];
  phases = [
    {
      name = "check";
      script = ''
        mkdir -p modules "$out"
        cp ${./test_runtime_scripts.py} modules/test_runtime_scripts.py
        export AOS_TEST_SHELL="${pkgs.stdenv.bootstrap.bash}/bin/bash"
        export AOS_TEST_TOOLS="${pkgs.stdenv.bootstrap.coreutils}/bin:${pkgs.stdenv.bootstrap.findutils}/bin:${pkgs.stdenv.bootstrap.sed}/bin:${pkgs.stdenv.bootstrap.grep}/bin:${pkgs.stdenv.bootstrap.bash}/bin"
        export AOS_TEST_SETUP="${../../stdenv/setup.sh}"
        export AOS_TEST_RUNTIME_PATCHER="${../../stdenv/runtime-scripts.sh}"
        ${pkgs.python3}/bin/python3 -m unittest discover -s modules -v
        echo PASS > "$out/result"
      '';
    }
  ];
}
