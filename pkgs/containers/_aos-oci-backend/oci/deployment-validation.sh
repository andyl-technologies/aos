# Checks the OCI-owned envelope before the generic native graph preflight.
validate_deployment_artifact() {
  deployment_document="$1"
  deployment_checker="$2"
  deployment_jq="$3"

  "$deployment_jq" -e '
    (keys == ["artifactClass","executionStage","platforms","schema"])
    and .schema == "aos.artifact.deployment/v1"
    and (.artifactClass == "container" or .artifactClass == "bootable")
    and (.executionStage == null or .executionStage == "host" or .executionStage == "initrd")
    and (.platforms | length > 0)
    and all(.platforms[];
      (keys == ["documentation","packages","platform","transaction"])
      and (.platform | keys == ["architecture","os"] or keys == ["architecture","os","variant"])
      and (.platform.os | type == "string")
      and (.platform.architecture | type == "string")
      and (.platform.variant == null or (.platform.variant | type == "string")))
    and ([.platforms[].platform | [.os,.architecture,.variant // ""]]
      == ([.platforms[].platform | [.os,.architecture,.variant // ""]] | sort | unique))
  ' "$deployment_document" >/dev/null || return 1

  "$deployment_jq" -c '.platforms[] | {packages,transaction,documentation}' "$deployment_document" |
  while IFS= read -r native_context; do
    printf '%s\n' "$native_context" | "$deployment_checker" || exit 1
  done
}
