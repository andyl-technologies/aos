# Requires the original complete ABI outcome of the matching bounded libc.
{pkgs}:
pkgs.mkDerivation {
  pname = "glibc-crucible-abi-conformance";
  version = "2.39";
  src = null;
  buildDeps = [pkgs.glibc-crucible];
  phases = [
    {
      name = "qualify-complete-abi";
      script = ''
        qualification="${pkgs.glibc-crucible}/share/glibc-crucible/qualification"
        cat "$qualification/check-abi.log"
        test "$(cat "$qualification/check-abi.status")" = 0
        mkdir -p "$out"
        cp "$qualification/check-abi.log" "$out/check-abi.log"
        printf 'PASS\n' > "$out/result"
      '';
    }
  ];
}
