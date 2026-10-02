##! Linux release platforms deferred to a later edge release.
##!
##! The first public `andyl/experimental` edge releases ship `x86_64-linux`
##! and the Darwin package cells only. Realizing the aarch64-hosted toolchain
##! cells (the Rust bootstrap chain, OpenJDK, Go, Bazel, workerd and their
##! dependents) takes well over a day, and the release tooling closure installs
##! no `aarch64-linux` qualification executor, so nothing could qualify those
##! cells even once they were built.
##!
##! A deferred platform ships nothing: its image and container targets become
##! optional and carry no claims, its eligible package cells are blocked with
##! `platform-release-deferred`, and release planning rejects any artifact on
##! it. Profiles that require a complete matrix reject the deferral outright.
##!
##! This list is the single source of truth for both the qualification
##! contract (`qualification.deferredPlatforms`) and the package inventory
##! (`pkgs/_platform-support.nix`). `aarch64-linux` returns in a later edge
##! release by emptying the list in a reviewed change.
["aarch64-linux"]
