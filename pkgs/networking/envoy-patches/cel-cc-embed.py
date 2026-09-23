"""Render CEL descriptor bytes as the C++ initializer expected by Envoy."""

from argparse import ArgumentParser
from pathlib import Path


def main() -> None:
    parser = ArgumentParser()
    parser.add_argument("--in", dest="input_path", required=True)
    parser.add_argument("--out", dest="output_path", required=True)
    arguments = parser.parse_args()

    source_bytes = Path(arguments.input_path).read_bytes()
    initializer = "".join(f"0x{byte:02x}, " for byte in source_bytes)
    if initializer:
        initializer = f"{initializer[:-1]}\n"

    Path(arguments.output_path).write_bytes(initializer.encode("ascii"))


if __name__ == "__main__":
    main()
