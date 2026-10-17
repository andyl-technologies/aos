##! qom-private-unwind — source-built private GNU frame observer for selected QOM
{
  mkDerivation,
  lib,
  stdenv,
  buildPackages,
  unwindContext ? null,
}: let
  # The context is produced by a separate source/configuration derivation.
  # A prepared host context or an installed libgcc archive cannot replace it.
  context =
    if unwindContext == null
    then throw "qom-private-unwind requires a source-built generated libgcc context"
    else if !(unwindContext ? source) || !(unwindContext ? passthru) || !(unwindContext.passthru ? compiler)
    then throw "qom-private-unwind context must expose matching source and compiler inputs"
    else if !stdenv.buildPlatform.isLinux || !stdenv.hostPlatform.isLinux || !(builtins.elem stdenv.hostPlatform.constraints.cpu ["x86_64" "aarch64"])
    then throw "the private observer requires supported Linux GNU build/host platforms"
    else unwindContext;
  compiler = context.passthru.compiler;
  compilerExecutable = context.passthru.compilerExecutable or (throw "private observer context must expose its actual compiler executable");
  inherit (buildPackages) python3 coreutils;
  # Native binutils may not support the host object's BFD target. The context
  # retains the actual build-executable target tools, without package splicing.
  targetBinutils = context.passthru.targetBinutils or (throw "private observer context must expose its target binutils");
  builder = ./build-qom-private-unwind.py;
in
  mkDerivation {
    # The generator tools execute on the qualified x86 GNU/Linux builder;
    # the private library follows the actual QEMU host object architecture.
    platformSupport = {
      build = [
        {
          abi = ["gnu"];
          cpu = ["x86_64"];
          os = ["linux"];
        }
      ];
      host = [
        {
          abi = ["gnu"];
          cpu = ["x86_64" "aarch64"];
          os = ["linux"];
        }
      ];
      target = [];
      role = "build-input";
    };

    pname = "qom-private-unwind";
    version = "16.2.0-2";
    outputs = ["out" "source"];
    src = context.source;
    buildDeps = [python3 coreutils];
    # Exact source/context and build-executable target compiler are retained by
    # their actual command paths below, not spliced as native package aliases.
    runtimeDeps = [];
    propagatedDeps = [];
    dontStrip = true;
    phases = [
      {
        name = "build";
        script = ''
          ${python3}/bin/python3 -I -B ${builder} \
            --context ${context}/share/qom-private-unwind/context.json \
            --context-root ${context} \
            --source-root ${context.source} \
            --compiler ${compilerExecutable} \
            --binutils ${targetBinutils}/bin \
            --output "$TMPDIR/qom-private-unwind"
        '';
      }
      {
        name = "install";
        script = ''
          mkdir -p "$out/lib/pkgconfig" "$out/share/qom-private-unwind" "$out/nix-support"
          cp "$TMPDIR/qom-private-unwind/libcrucible-qom-unwind.a" "$out/lib/"
          cat > "$out/lib/pkgconfig/crucible-qom-private-unwind.pc" <<'PC_EOF'
          prefix=@provider-prefix@
          libdir=''${prefix}/lib

          Name: crucible-qom-private-unwind
          Description: Source-built private GNU frame observer for QOM
          Version: 16.2.0
          Libs: -Wl,--push-state,--whole-archive,''${libdir}/libcrucible-qom-unwind.a,--no-whole-archive,--pop-state,--exclude-libs,libcrucible-qom-unwind.a
          PC_EOF
          ${python3}/bin/python3 -I -B - "$out/lib/pkgconfig/crucible-qom-private-unwind.pc" "$out" <<'PC_PREFIX_EOF'
          import pathlib
          import sys
          path = pathlib.Path(sys.argv[1])
          body = path.read_text()
          if body.count("@provider-prefix@") != 1:
              raise ValueError("private observer pkg-config prefix marker changed")
          path.write_text(body.replace("@provider-prefix@", sys.argv[2]))
          PC_PREFIX_EOF
          cp "$TMPDIR/qom-private-unwind/build-manifest.json" "$out/share/qom-private-unwind/"
          printf '%s\n' "$source" > "$out/nix-support/corresponding-source"

          mkdir -p "$source/native-context" "$source/recipe" "$source/member-build"
          cp -a ${context.source}/. "$source/native-context/"
          cp -a ${context}/. "$source/generated-context/"
          cp ${./qom-private-unwind.nix} "$source/recipe/"
          cp ${builder} "$source/recipe/"
          # Keep reconstruction inputs and command/dependency records in
          # source. Compiled objects/archive remain binary-output artifacts.
          cp "$TMPDIR/qom-private-unwind/"*.symbols "$source/member-build/"
          cp "$TMPDIR/qom-private-unwind/"*.d "$source/member-build/"
          cp "$TMPDIR/qom-private-unwind/"*.dependencies.json "$source/member-build/"
          cp "$TMPDIR/qom-private-unwind/build-manifest.json" "$source/member-build/"
          cp "$TMPDIR/qom-private-unwind/command-receipts.json" "$source/member-build/"
        '';
      }
    ];
    meta = {
      description = "Private GNU observer with separately qualified source/configuration inputs";
      license = "GPL-3.0-or-later WITH GCC-exception-3.1";
    };
  }
