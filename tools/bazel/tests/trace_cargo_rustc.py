"""Retains Cargo's compiler invocations without changing compiler behavior.

The temporary migration oracle uses this executable as RUSTC_WRAPPER. Each
invocation appends one record before replacing itself with the real compiler.
Only compiler-facing Cargo metadata is retained; unrelated environment values
are deliberately absent from the trace.
"""

import json
import os
import sys


def main():
    """Records a complete invocation and delegates its arguments and exit status."""
    record = {
        "schema_version": 1,
        "directory": os.getcwd(),
        "arguments": sys.argv[1:],
        "environment": {
            name: value for name, value in os.environ.items()
            if name.startswith(("CARGO_PKG_", "CARGO_FEATURE_"))
            or name in {"CARGO_MANIFEST_DIR", "OUT_DIR", "OPT_LEVEL", "DEBUG", "HOST", "TARGET",
                        "AOS_ZFS_VERSION", "AOS_NFT_EXECUTABLE"}
        },
    }
    data = (json.dumps(record, sort_keys=True) + "\n").encode()
    descriptor = os.open(os.environ["AOS_CARGO_RUSTC_TRACE"], os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    try:
        # One append write keeps concurrent Cargo jobs' records independent.
        if os.write(descriptor, data) != len(data):
            raise OSError("incomplete compiler trace record")
    finally:
        os.close(descriptor)

    os.execvp(sys.argv[1], sys.argv[1:])


if __name__ == "__main__":
    main()
