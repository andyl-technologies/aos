{sourceGate}:
# Registration precedes the implementation; requesting this image fails until
# its hermetic compilation and executable validation are implemented.
sourceGate "native-sdk-test-image" ''
  printf '%s\n' 'Native SDK test image: pending implementation' >&2
  exit 1
''
