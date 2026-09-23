These test inputs are the unmodified outputs of rules_rust 0.71.2's
`crate_universe/test_data/serialized_configs/BUILD.bazel`, licensed under
Apache-2.0. The source archive is pinned in `../../_cargo-bazel.nix`.

Generate them from that archive with AOS-built Bazel:

```sh
bazel build //crate_universe/test_data/serialized_configs:serialized_configs
```

Copy `config.json` and `splicing_manifest.json` from
`bazel-bin/crate_universe/test_data/serialized_configs/`. Both outputs are
produced by Bazel's internal write actions, using upstream `compile_config`
and `compile_splicing_manifest`. Keeping the generated data here allows the
Cargo library tests to consume the same fixtures without introducing a
Bazel dependency into the generator's build.
