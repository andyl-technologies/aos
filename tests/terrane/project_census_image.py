"""Installs the actual project-census fixture through checked Cargo discovery."""

from structural_mapping_image import main


if __name__ == "__main__":
    main(example="project_census_fixture", executable_name="project-census-fixture",
         scope="Native excluded-inode project census; no exposure release authority")
