##! Qualifies source patch policy and the Rustix compiler-probe cleanup.
{pkgs}: let
  root = ../..;
  inherit (pkgs) lib;
  policy = builtins.fromJSON (builtins.readFile ../../third_party/rust/source-patches.json);
  original = policy.packages.rustix."1.1.4";
  changed = value: policy // {packages = policy.packages // {rustix = policy.packages.rustix // {"1.1.4" = value;};};};
  sourcesFor = value:
    import ../../pkgs/build-support/_bazel/rust-sources.nix {
      inherit pkgs lib root;
      family = "qemu-host";
      sourcePatchPolicyFile = builtins.toFile "rust-source-patch-policy.json" (builtins.toJSON value);
    };
  rejects = value: !(builtins.tryEval (builtins.deepSeq (toString (sourcesFor value)."aos_qemu_host_crates__rustix-1.1.4") true)).success;
  patch = builtins.head original.patches;
  zeroHash = builtins.concatStringsSep "" (builtins.genList (_: "0") 64);
  rejected = {
    archive = rejects (changed (original // {archive_sha256 = zeroHash;}));
    hash = rejects (changed (original // {patches = [(patch // {sha256 = zeroHash;})];}));
    path = rejects (changed (original // {patches = [(patch // {path = "../outside.patch";})];}));
    strip = rejects (changed (original // {patches = [(patch // {strip = 0;})];}));
    duplicate = rejects (changed (original // {patches = [patch patch];}));
    version = rejects (policy // {packages = {rustix = builtins.removeAttrs policy.packages.rustix ["1.1.4"];};});
    schema = rejects (policy // {schema_version = 2;});
  };
  evaluation = assert builtins.all (value: value) (builtins.attrValues rejected);
    builtins.toFile "rust-source-patch-rejections.json" (builtins.toJSON rejected);
  baseline =
    (sourcesFor {
      schema_version = 1;
      packages = {};
    })."aos_qemu_host_crates__rustix-1.1.4";
  patched = pkgs.aosBazelRustRepositories.qemu-host."aos_qemu_host_crates__rustix-1.1.4";
  upstreamFixed = pkgs.aosBazelRustRepositories.accache."aos_accache_crates__rustix-1.1.5";
in {
  inherit baseline patched upstreamFixed;
  all =
    pkgs.runCommand "aos-bazel-rust-source-patch-checks" {
      buildDeps = [pkgs.python3 pkgs.rust];
    } ''
      mkdir -p "$out"
      cat > "$TMPDIR/unsupported-rustc" <<'SH'
      #!${pkgs.bash}/bin/bash
      while [ "$#" -gt 0 ]; do
        if [ "$1" = -o ]; then
          shift
          printf 'unsupported probe\n' > "$1"
        fi
        shift
      done
      cat > /dev/null
      exit 1
      SH
      chmod +x "$TMPDIR/unsupported-rustc"
      PYTHONDONTWRITEBYTECODE=1 ${pkgs.python3}/bin/python3 \
        ${../../tools/bazel/tests/verify_rust_source_patches.py} \
        --baseline ${baseline} --patched ${patched} --provenance ${patched.patches} \
        --upstream-fixed ${upstreamFixed} --policy ${../../third_party/rust/source-patches.json} \
        --rustc ${pkgs.rust}/bin/rustc --unsupported-rustc "$TMPDIR/unsupported-rustc" \
        --target ${pkgs.stdenv.hostPlatform.config} --output "$out"
      cp ${evaluation} "$out/rejected-policy-mutations.json"
      printf 'PASS\n' > "$out/result"
    '';
}
