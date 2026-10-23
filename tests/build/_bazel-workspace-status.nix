##! Proves Bazel workspace status executes the source-built POSIX command shell.
{pkgs}: let
  moduleFlags =
    pkgs.lib.mapAttrsToList
    (name: path: "--override_module=${name}=${path}")
    pkgs.aosBazelModules;
in
  pkgs.runCommand "aos-bazel-workspace-status-check" {
    buildDeps = [pkgs.bazel pkgs.bash pkgs.grep];
  } ''
      mkdir -p "$out" workspace registry
      printf '{}\n' > registry/bazel_registry.json
      cat > workspace/MODULE.bazel <<'MODULE'
    module(name = "aos_shell_check")
    bazel_dep(name = "rules_rust", version = "${pkgs.aosBazelModules.rules_rust.version}")
    MODULE
      cat > workspace/status.bzl <<'BZL'
    def _status_impl(ctx):
        output = ctx.actions.declare_file("status.txt")
        ctx.actions.symlink(output = output, target_file = ctx.info_file)
        return [DefaultInfo(files = depset([output]))]

    status = rule(implementation = _status_impl)
    BZL
      cat > workspace/BUILD.bazel <<'BUILD'
    load(":status.bzl", "status")
    status(name = "status")
    BUILD
      export HOME="$TMPDIR/home"
      mkdir -p "$HOME"
      registry="$PWD/registry"
      cd workspace
      # This command tests the Bazel package itself, including the command-shell
      # path used independently of the first-party launcher's rule-shell policy.
      ${pkgs.bazel}/bin/bazel --batch --ignore_all_rc_files \
        --output_user_root="$TMPDIR/bazel" build //:status \
        --repository_disable_download --registry="file://$registry" \
        ${pkgs.lib.escapeShellArgs moduleFlags} \
        --workspace_status_command='printf "STABLE_AOS_COMMAND_SHELL %s\n" "$BASH"'  \
        --shell_executable=${pkgs.bash}/bin/bash --jobs="$NIX_BUILD_CORES"
      ${pkgs.grep}/bin/grep -Fx 'STABLE_AOS_COMMAND_SHELL ${pkgs.bash}/bin/bash' bazel-bin/status.txt
      cp bazel-bin/status.txt "$out/status.txt"
  ''
