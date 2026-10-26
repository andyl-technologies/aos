##! Installs an explicitly selected Bazel package through ordinary AOS fixup.
{
  pkgs,
  lib,
}: {
  pname,
  version,
  build,
  packageLabel,
  runtimeDeps ? [],
  nukeRefsKeep ? [],
  platformSupport ? null,
  passthru ? {},
  meta ? {},
}:
pkgs.mkDerivation ({
    inherit pname version runtimeDeps meta platformSupport;
    src = null;
    sharedBuildCache = false;
    buildDeps = [pkgs.python3];
    passthru = passthru // {bazelBuild = build;};
    phases = [
      {
        name = "install";
        script = ''
          ${pkgs.python3}/bin/python3 ${../../../tools/bazel/metadata/install_package.py} \
            --build ${build} --label ${lib.escapeShellArg packageLabel} \
            --name ${lib.escapeShellArg pname} --version ${lib.escapeShellArg version} \
            --output "$out"
        '';
      }
    ];
  }
  # Avoid adding an empty attribute to existing production derivation identities.
  // lib.optionalAttrs (nukeRefsKeep != []) {inherit nukeRefsKeep;})
