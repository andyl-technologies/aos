##! worker-build — Cloudflare Workers build command for workers-rs projects
##!
##! Built from the cloudflare/workers-rs `v0.4.2` tag, matching the `worker`
##! crate generation the worker compiles against (see `crates/Cargo.lock`:
##! `worker` 0.4.2). worker-build bundles the JS shims and event-handler glue
##! for that generation, so it is pinned to the same release line. The actual
##! wasm-bindgen invocation is delegated to wasm-bindgen-cli, which is
##! version-locked separately to the `wasm-bindgen` crate.
{
  mkCargoPackage,
  fetchurl,
  fetchCargoDeps,
}: let
  # workers-rs release tag; the in-tree `worker-build` crate version at this
  # tag is 0.1.0 and pairs with `worker` 0.4.2.
  version = "0.4.2";
  src = fetchurl {
    urls = [
      "https://github.com/cloudflare/workers-rs/archive/refs/tags/v${version}.tar.gz"
    ];
    hash = "sha256-nD4dnn8KIlBJCouJO7t685p95j6Q1UEbZBUhct98D2s=";
  };

  # `worker-kv`, a sibling member of the workers-rs workspace, pins a git fork
  # of `psutil`. worker-build itself does not depend on it, but cargo resolves
  # the whole workspace lockfile under `--frozen --offline`, so the git source
  # must still be vendored. `fetchCargoDeps` only handles crates.io by default;
  # list the git source here so it is fetched and source-replaced.
  gitDeps = [
    {
      url = "https://github.com/mygnu/rust-psutil";
      rev = "c065bcc2a604d8ca0cd7ec481f2fc66cbdf819d0";
      crate = "psutil";
    }
  ];
in
  mkCargoPackage {
    pname = "worker-build";
    inherit version src;

    cargoDeps = fetchCargoDeps {
      inherit src gitDeps;
      hash = "sha256-f8FpqlY4QiA7ePrfz/G19mHqafs/8bZGopWwfd9xV0k=";
    };

    # Source-replace the git fork at build time too (cargoPhases reads this).
    inherit gitDeps;

    # The lockfile and worker-kv's manifest reference the psutil fork with a
    # `?branch=update-dependencies` query. cargoPhases generates a vendored
    # source replacement keyed on the bare git URL (no branch query), so strip
    # the branch from both the lockfile source id and the manifest dependency
    # to make the two match. The vendored revision is identical either way.
    postPatch = ''
      sed -i 's|?branch=update-dependencies||g' Cargo.lock
      sed -i 's|, branch = "update-dependencies"||g' worker-kv/Cargo.toml
    '';

    # Build only the worker-build member of the workspace, not the example
    # workers or the sandbox.
    cargoFlags = "-p worker-build";

    doCheck = false;

    meta = {
      description = "Custom build command for a Cloudflare Workers workers-rs project";
      homepage = "https://github.com/cloudflare/workers-rs";
      license = "Apache-2.0";
      mainProgram = "worker-build";
    };
  }
