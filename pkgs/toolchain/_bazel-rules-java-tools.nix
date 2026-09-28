##! Selects source-built Java execution tools before Bazel repository resolution.
{buildPackages}: {
  source,
  version,
}:
buildPackages.mkDerivation {
  pname = "bazel-rules-java-source-tools";
  inherit version;
  src = source;
  buildDeps = [buildPackages.python3];
  runtimeDeps = [];

  phases = [
    {
      name = "unpack";
      script = ''
        mkdir rules-java-source
        cp -a "$src"/. rules-java-source/
        chmod -R u+w rules-java-source
        cd rules-java-source
      '';
    }
    {
      name = "build";
      script = ''
        python3 - <<'PY'
        from pathlib import Path

        build = Path("toolchains/BUILD")
        contents = build.read_text()
        replacements = {
            ':ijar_prebuilt_binary_or_cc_binary': '@remote_java_tools//:ijar_cc_binary',
            ':singlejar_prebuilt_or_cc_binary': '@remote_java_tools//:singlejar_local',
            ':one_version_prebuilt_or_cc_binary': '@remote_java_tools//:one_version_cc_bin',
            ':turbine_direct_graal_or_java': '@remote_java_tools//:TurbineDirect',
        }

        # Keep the full local singlejar, including desugaring checks. Turbine's
        # upstream Java backend uses our source-built JAR and native JDK;
        # the optional explicit Graal targets retain their upstream definitions.
        for original, replacement in replacements.items():
            expected = f'actual = "{original}"'
            if contents.count(expected) != 1:
                raise SystemExit(f"unexpected Java tool alias layout: {original}")
            contents = contents.replace(expected, f'actual = "{replacement}"')

        build.write_text(contents)

        # The default compilation runtime is separate from the command-line
        # runtime toolchain. Use the same native source-built JDK for both.
        toolchain = Path("toolchains/default_java_toolchain.bzl")
        contents = toolchain.read_text()
        expected = 'java_runtime = Label("//toolchains:remotejdk_21")'
        if contents.count(expected) != 1:
            raise SystemExit("unexpected default Java compilation runtime")
        toolchain.write_text(contents.replace(
            expected, 'java_runtime = Label("@local_jdk//:jdk")',
        ))
        PY
      '';
    }
    {
      name = "install";
      script = ''
        mkdir -p "$out"
        cp -a . "$out"/
      '';
    }
  ];
}
