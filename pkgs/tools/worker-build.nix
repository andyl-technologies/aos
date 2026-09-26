##! worker-build — Cloudflare Workers build command for workers-rs projects
##!
##! Built from the cloudflare/workers-rs `v0.4.2` tag, matching the `worker`
##! crate generation the worker compiles against (see `crates/Cargo.lock`:
##! `worker` 0.4.2). worker-build bundles the JS shims and event-handler glue
##! for that generation, so it is pinned to the same release line. The actual
##! wasm-bindgen invocation is delegated to wasm-bindgen-cli, which is
##! version-locked separately to the `wasm-bindgen` crate.
{
  lib,
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
      sourceArchive = fetchurl {
        urls = [
          "https://github.com/mygnu/rust-psutil/archive/c065bcc2a604d8ca0cd7ec481f2fc66cbdf819d0.tar.gz"
        ];
        hash = "sha256-gEfJ7GrfCLtcD/LprF4HOolsaBAhpRoRNEqEMjWJ0iM=";
      };
    }
  ];
in
  mkCargoPackage {
    platformSupport = {
      build = [{abi = ["gnu"]; os = ["linux"];}];
      host = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];} {abi = ["darwin"]; cpu = ["x86_64" "aarch64"]; os = ["darwin"];}];
      target = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];} {abi = ["darwin"]; cpu = ["x86_64" "aarch64"]; os = ["darwin"];}];
      role = "public-package";
    };
    pname = "worker-build";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "Worker-build documents its build mode, target, output-directory, and TypeScript controls.";
        "files" = {};
        "input" = "A request for the worker build command's offline option contract.";
        "operation" = "Render the command help before inspecting or building a Rust project.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import subprocess\nresult = subprocess.run([\"@out@/bin/worker-build\", \"--no-typescript\", \"--help\"], capture_output=True, text=True)\noutput = result.stdout + result.stderr\nassert \"Usage:\" in output and \"--mode\" in output and \"--target\" in output and \"--out-dir\" in output\nprint(\"worker-build operation passed\")\n"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "worker-build operation passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "Worker-build rejects the unsupported mode value.";
        "files" = {};
        "input" = "A build mode outside worker-build's supported no-install, normal, and force values.";
        "operation" = "Validate the mode selector before resolving project dependencies.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import sys\nimport subprocess\nresult = subprocess.run([\"@out@/bin/worker-build\", \"--mode\", \"qualification-invalid\"], capture_output=True, text=True)\nassert result.returncode != 0 and \"invalid value\" in result.stderr.lower()\n\nsys.stderr.write(\"worker-build rejected invalid input\\n\")\nraise SystemExit(7)\n"
            ];
            "exit_code" = 7;
            "observes_rejection" = true;
            "stderr" = {
              "exact" = "worker-build rejected invalid input\n";
            };
            "stdout" = {
              "exact" = "";
            };
          }
        ];
      };
    };

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
