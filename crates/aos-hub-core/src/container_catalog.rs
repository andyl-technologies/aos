//! Defines the base-image admission policy shared by indexing and publication.

/// Admits the server base image through its canonical definition or alias.
pub(crate) fn admits_base_image_definition(package: &str, image: &str, attribute: &str) -> bool {
    // Both attributes resolve to the same image. Keep the allowlist explicit so
    // new per-system artifacts do not automatically widen the admitted catalog.
    package == "aos"
        && image == "aos"
        && matches!(
            attribute,
            "containerImages.aos" | "systems.server.build.containers.aos"
        )
}

#[cfg(test)]
mod tests {
    use super::admits_base_image_definition;

    #[test]
    fn accepts_canonical_definition_and_alias() {
        for attribute in ["containerImages.aos", "systems.server.build.containers.aos"] {
            assert!(admits_base_image_definition("aos", "aos", attribute));
        }
    }

    #[test]
    fn rejects_other_definitions_and_identities() {
        for attribute in [
            "systems.aos-testing.build.containers.aos",
            "systems.server.build.containers.other",
            "containerImages.other",
            "",
        ] {
            assert!(!admits_base_image_definition("aos", "aos", attribute));
        }

        let canonical = "systems.server.build.containers.aos";
        assert!(!admits_base_image_definition("other", "aos", canonical));
        assert!(!admits_base_image_definition("aos", "other", canonical));
    }
}
