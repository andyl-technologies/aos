{pkgs}:
pkgs.mkDerivation {
  pname = "crucible-campaign-mode-libtest-check";
  version = "0";
  src = null;
  buildDeps = [pkgs.python3 pkgs.rust pkgs.rust.dev];
  phases = [
    {
      name = "check";
      script = ''
        cp ${./_phase9-campaign-mode-libtest.py} _phase9-campaign-mode-libtest.py
        cp ${./test_campaign_mode_libtest.py} test_campaign_mode_libtest.py
        RUSTC=${pkgs.rust}/bin/rustc \
          ${pkgs.python3}/bin/python3 -m unittest -v test_campaign_mode_libtest
        mkdir -p "$out"
        printf '%s\n' PASS > "$out/result"
      '';
    }
  ];
}
