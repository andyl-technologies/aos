"""Binds the graph to an immutable Nix-built toolchain repository."""

def _aos_tools_repository_impl(repository_ctx):
    fail("Use aos-dev bazel or mkAosBazelBuild; @aos_tools must be supplied by Nix")

aos_tools_repository = repository_rule(
    implementation = _aos_tools_repository_impl,
    local = True,
)
