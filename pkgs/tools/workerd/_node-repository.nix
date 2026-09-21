##! Bazel's Node repository interface backed by the AOS source-built runtime.
{
  mkDerivation,
  nodejs,
  bash,
}:
mkDerivation {
  pname = "workerd-node-repository";
  inherit (nodejs) version;
  runtimeDeps = [nodejs bash];
  phases = [
    {
      name = "install";
      script = ''
        mkdir -p "$out/bin"
        ln -s ${nodejs} "$out/bin/nodejs"
        ln -s ${nodejs}/bin/node "$out/bin/node"
        for command in npm npx; do
          {
            printf '%s\n' '#!${bash}/bin/bash'
            printf 'exec ${nodejs}/bin/node ${nodejs}/lib/node_modules/npm/bin/%s-cli.js "$@"\n' "$command"
          } > "$out/bin/$command"
          chmod +x "$out/bin/$command"
        done

        cat > "$out/BUILD.bazel" <<'BUILD'
        load("@rules_nodejs//nodejs:toolchain.bzl", "nodejs_toolchain")

        package(default_visibility = ["//visibility:public"])
        exports_files(["bin/node", "bin/npm", "bin/npx"])

        alias(name = "node_bin", actual = "bin/nodejs/bin/node")
        alias(name = "npm_bin", actual = "bin/nodejs/lib/node_modules/npm/bin/npm-cli.js")
        alias(name = "npx_bin", actual = "bin/nodejs/lib/node_modules/npm/bin/npx-cli.js")
        alias(name = "node", actual = "bin/node")
        alias(name = "npm", actual = "bin/npm")
        alias(name = "npx", actual = "bin/npx")

        filegroup(name = "node_files", srcs = [":node", ":node_bin"])
        filegroup(name = "npm_files", srcs = glob(["bin/nodejs/**"]) + [":node_files"])

        nodejs_toolchain(
            name = "toolchain",
            node = ":node_bin",
            npm = ":npm",
            npm_srcs = [":npm_files"],
        )
        alias(name = "node_toolchain", actual = ":toolchain")
        BUILD
        touch "$out/WORKSPACE.bazel"
      '';
    }
  ];
  meta = {
    description = "AOS Node toolchain repository for workerd's Bazel build";
    license = "Apache-2.0";
  };
}
