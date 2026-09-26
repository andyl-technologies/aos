# shellcheck shell=sh

extract_campaign_mode_frame() {
  source_file="$1"
  begin_marker="$2"
  end_marker="$3"
  expected_payload_lines="$4"
  destination="$5"

  test "$(grep -Fxc "$begin_marker" "$source_file")" -eq 1 || return 1
  test "$(grep -Fxc "$end_marker" "$source_file")" -eq 1 || return 1
  awk \
    -v begin_marker="$begin_marker" \
    -v end_marker="$end_marker" \
    -v expected_payload_lines="$expected_payload_lines" '
      $0 == begin_marker {
        if (state != 0) exit 1
        state = 1
        next
      }
      $0 == end_marker {
        if (state != 1 || payload_lines != expected_payload_lines) exit 1
        state = 2
        next
      }
      state == 1 {
        print
        payload_lines += 1
      }
      END {
        if (state != 2) exit 1
      }
    ' "$source_file" > "$destination"
}

extract_campaign_mode_result_frame() {
  source_file="$1"
  begin_marker="$2"
  end_marker="$3"
  destination="$4"

  test "$(grep -Fxc "$begin_marker" "$source_file")" -eq 1 || return 1
  test "$(grep -Fxc "$end_marker" "$source_file")" -eq 1 || return 1
  awk \
    -v begin_marker="$begin_marker" \
    -v end_marker="$end_marker" '
      $0 == begin_marker {
        if (state != 0) exit 1
        state = 1
        next
      }
      $0 == end_marker {
        if (state != 1 || payload_lines == 0) exit 1
        state = 2
        next
      }
      state == 1 {
        print
        payload_lines += 1
      }
      END {
        if (state != 2) exit 1
      }
    ' "$source_file" > "$destination"
}
