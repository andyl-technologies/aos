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
        if "${version}" == "7.6.5":
            del replacements[':one_version_prebuilt_or_cc_binary']

        # Keep the full local singlejar, including desugaring checks. Turbine's
        # upstream Java backend uses our source-built JAR and native JDK;
        # the optional explicit Graal targets retain their upstream definitions.
        for original, replacement in replacements.items():
            expected = f'actual = "{original}"'
            if contents.count(expected) != 1:
                raise SystemExit(f"unexpected Java tool alias layout: {original}")
            contents = contents.replace(expected, f'actual = "{replacement}"')

        if "${version}" == "9.1.0":
            # These generated compiler toolchains override the base runtime.
            # Keep every language target and use the native AOS JDK here too.
            expected = 'configuration = DEFAULT_TOOLCHAIN_CONFIGURATION | {"java_runtime": ":remotejdk_25"}'
            if contents.count(expected) != 1:
                raise SystemExit("unexpected Java 9 compiler runtime configuration")
            contents = contents.replace(
                expected,
                'configuration = DEFAULT_TOOLCHAIN_CONFIGURATION | {"java_runtime": "@local_jdk//:jdk"}',
            )

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

        # Module overrides use this template directly, bypassing vendor path
        # substitutions. Java execution tools must launch with AOS-built Bash.
        launcher = Path("java/bazel/rules/java_stub_template.txt")
        if launcher.exists():
            contents = launcher.read_text()
            if not contents.startswith("#!/usr/bin/env bash\n"):
                raise SystemExit("unexpected Java launcher shebang")
            launcher.write_text(contents.replace(
                "#!/usr/bin/env bash\n", "#!${buildPackages.bash}/bin/bash\n", 1,
            ))

        if "${version}" == "7.6.5":
            # The release archive embeds zlib. Our tools use its separately
            # pinned source module, which must be visible to this extension.
            module = Path("MODULE.bazel")
            contents = module.read_text()
            if 'bazel_dep(name = "zlib"' in contents:
                raise SystemExit("unexpected Bazel 7 Java rules zlib dependency")
            module.write_text(contents + '\nbazel_dep(name = "zlib", version = "1.3.1.bcr.3")\n')
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
