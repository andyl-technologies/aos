##! Linux release platforms deferred to a later edge release.
##!
##! A deferred platform ships nothing: its image and container targets become
##! optional and carry no claims, its eligible package cells are blocked with
##! `platform-release-deferred`, the coordinated container index omits it, and
##! release planning rejects any artifact on it. Profiles that require a
##! complete matrix reject the deferral outright.
##!
##! This list is the single source of truth for the qualification contract
##! (`qualification.deferredPlatforms`), the package inventory
##! (`pkgs/_target-policy.nix`), and the container coordinator
##! (`flake.nix`). Nothing is deferred today: the first public
##! `andyl/experimental` edge release ships both Linux platforms, and the
##! release tooling closure installs the hosted `aarch64-linux` qualification
##! executor next to the native `x86_64-linux` one. Defer a platform again by
##! listing it here in a reviewed change.
[]
