"""Installs actual worker transport proof bytes through checked Cargo discovery."""

from structural_mapping_image import main


if __name__ == "__main__":
    main(example="worker_channel_fixture", executable_name="worker-channel-fixture",
         scope="Authenticated worker transport component; no production FUSE acceptance",
         features=("native-test-fixtures", "surface-fuse", "tokio"))
