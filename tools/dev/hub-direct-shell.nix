# Local Direct integration tools, without the packaged CLI or fleet images.
let
  aos = import ../.. {};
  cargo = import ../../cargo-shell.nix;
  inherit (aos) pkgs;
  tools = [pkgs.nodejs pkgs.python3 pkgs.workerd-source pkgs.wasm-bindgen-cli pkgs.esbuild];
  source = pkgs.aos-hub-direct-guard-e2e.passthru.workerDist.src;
in
  builtins.derivation {
    name = "aos-hub-direct-dev";
    inherit (cargo) system builder args;
    outputs = ["out"];
    shellHook =
      cargo.shellHook
      + ''
        # An enclosing development shell can leave linker flags for another
        # compiler wrapper. This shell supplies its own AOS tools and libraries.
        unset NIX_CFLAGS_COMPILE NIX_CFLAGS_LINK NIX_LDFLAGS
        export PATH="${builtins.concatStringsSep ":" (map (tool: "${tool}/bin") tools)}:$PATH"
        export AOS_COPY_WORKER_SOURCE_PATH="${source}"
        export AOS_DIRECT_MINIFLARE="${pkgs.miniflare}/lib/node_modules/wrangler/node_modules/miniflare"
      '';
  }
