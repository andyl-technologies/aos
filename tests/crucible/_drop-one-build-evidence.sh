# Shared fail-closed parser and validator for drop-one compiler/linker attribution.

extract_drop_one_build_evidence() {
  build_log_path=$1
  evidence_path=$2
  diagnostics_path=$3

  : > "$diagnostics_path"
  grep -E "^([^:]+:[0-9]+(:[0-9]+)?|[^:]+):[[:space:]]*(fatal[[:space:]]+)?error:.*(implicit declaration of function '[A-Za-z_][A-Za-z0-9_]*'|'[A-Za-z_][A-Za-z0-9_]*' undeclared|unknown type name '[A-Za-z_][A-Za-z0-9_]*')" \
    "$build_log_path" >> "$diagnostics_path" || true
  if grep -Eq '^collect2:[[:space:]]+error:[[:space:]]+ld returned [1-9][0-9]* exit status$' \
    "$build_log_path"; then
    grep -E "^[[:space:]]*[^[:space:]].*:[[:space:]]+undefined reference to .[A-Za-z_][A-Za-z0-9_]*'" \
      "$build_log_path" \
      | grep -Ev '(^|:[[:space:]]*)warning:' \
      >> "$diagnostics_path" || true
  fi
  : > "$evidence_path"
  grep -oE "undefined reference to .[A-Za-z_][A-Za-z0-9_]*'" "$diagnostics_path" \
    | sed -E "s/.*to .([A-Za-z_][A-Za-z0-9_]*)'/symbol\\t\\1/" \
    >> "$evidence_path" || true
  grep -oE "(fatal )?error:.*implicit declaration of function '[A-Za-z_][A-Za-z0-9_]*'" \
    "$diagnostics_path" \
    | sed -E "s/.*'([A-Za-z_][A-Za-z0-9_]*)'/symbol\\t\\1/" \
    >> "$evidence_path" || true
  grep -oE "(fatal )?error:.*'[A-Za-z_][A-Za-z0-9_]*' undeclared" \
    "$diagnostics_path" \
    | sed -E "s/.*'([A-Za-z_][A-Za-z0-9_]*)' undeclared/symbol\\t\\1/" \
    >> "$evidence_path" || true
  grep -oE "(fatal )?error:.*unknown type name '[A-Za-z_][A-Za-z0-9_]*'" \
    "$diagnostics_path" \
    | sed -E "s/.*'([A-Za-z_][A-Za-z0-9_]*)'/symbol\\t\\1/" \
    >> "$evidence_path" || true
  LC_ALL=C sort -u "$evidence_path" -o "$evidence_path"
}

validate_drop_one_build_evidence() {
  evidence_path=$1
  full_exports_path=$2
  expected_exported_symbols=$3
  expected_internal_identifiers=$4

  test -s "$evidence_path" || return 1
  while IFS="$(printf '\t')" read -r evidence_kind evidence_symbol \
    || test -n "$evidence_kind$evidence_symbol"; do
    test "$evidence_kind" = symbol || return 1
    expected_match=false
    for expected_symbol in $expected_exported_symbols; do
      if test "$evidence_symbol" = "$expected_symbol"; then
        grep -Fqx "$evidence_symbol" "$full_exports_path" || return 1
        expected_match=true
        break
      fi
    done
    for expected_identifier in $expected_internal_identifiers; do
      if test "$evidence_symbol" = "$expected_identifier"; then
        expected_match=true
        break
      fi
    done
    test "$expected_match" = true || return 1
  done < "$evidence_path"
}
