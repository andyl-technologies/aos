These lockfiles reproduce the Helm library replacement in the Dockerfile of
`k3s-io/klipper-helm` at `v0.9.14-build20260210`.

For `k3s-io/helm-set-status` at `v0.3.0` and `helm/helm-mapkubeapis` at `v0.6.1`,
the upstream build runs `go mod edit --replace helm.sh/helm/v3=helm.sh/helm/v3@v3.19.5`
followed by `go mod tidy`. The checked-in results keep that resolution outside
the offline package build. Regenerate both files together when updating the
Helm job, then update the module-cache hashes and validate both plugins.
