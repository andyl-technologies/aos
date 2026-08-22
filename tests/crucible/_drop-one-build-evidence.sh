# Shared fail-closed validator for drop-one compiler/linker attribution.

validate_drop_one_build_evidence() {
  evidence_path=$1
  full_exports_path=$2
  expected_symbols=$3

  test -s "$evidence_path" || return 1
  while IFS="$(printf '\t')" read -r evidence_kind evidence_symbol; do
    test "$evidence_kind" = symbol || return 1
    expected_match=false
    for expected_symbol in $expected_symbols; do
      if test "$evidence_symbol" = "$expected_symbol"; then
        expected_match=true
        break
      fi
    done
    test "$expected_match" = true || return 1
    grep -Fqx "$evidence_symbol" "$full_exports_path" || return 1
  done < "$evidence_path"
}
