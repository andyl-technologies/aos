//! Checks the repository-wide contributor-authorization policy.

use std::error::Error;
use std::fs;
use std::path::Path;

use super::workspace_crates_dir;

#[test]
fn contributor_authorization_policy_is_explicit_and_fail_closed() -> Result<(), Box<dyn Error>> {
    let root = workspace_crates_dir()?
        .parent()
        .map(Path::to_path_buf)
        .ok_or("crates/ must be inside the repository")?;
    let contributing = fs::read_to_string(root.join("CONTRIBUTING.md"))?;
    let agreement = fs::read_to_string(root.join("CONTRIBUTOR_LICENSE_AGREEMENT.md"))?;
    let licensing = fs::read_to_string(root.join("LICENSING.md"))?;
    let agents = fs::read_to_string(root.join("AGENTS.md"))?;
    let maintainer = fs::read_to_string(root.join("docs/maintainers/contributor-licensing.md"))?;
    let maintainer_index = fs::read_to_string(root.join("docs/maintainers/README.md"))?;
    let readme = fs::read_to_string(root.join("README.md"))?;

    for marker in [
        "AOS External Contributor License Agreement",
        "Version 1.0",
        "Andyl, Inc., a Delaware corporation",
        "https://cla.andyl.org/aos",
        "Confidential Information and Invention Assignment",
        "Agreement (CIAA)",
        "authenticated stable GitHub user ID",
        "agreement content",
        "digest and an archived copy",
    ] {
        assert!(
            agreement.contains(marker),
            "external contributor agreement must contain `{marker}`"
        );
    }

    for (name, document) in [
        ("CONTRIBUTOR_LICENSE_AGREEMENT.md", agreement.as_str()),
        ("CONTRIBUTING.md", contributing.as_str()),
        (
            "docs/maintainers/contributor-licensing.md",
            maintainer.as_str(),
        ),
    ] {
        assert!(
            document.contains("https://cla.andyl.org/aos"),
            "{name} must point to the canonical contribution frontend"
        );
    }
    assert_eq!(
        [
            agreement.as_str(),
            contributing.as_str(),
            maintainer.as_str(),
        ]
        .into_iter()
        .map(|document| document.matches("https://cla.andyl.org/aos").count())
        .sum::<usize>(),
        3,
        "the canonical contribution frontend must appear exactly once in each policy document"
    );
    assert!(
        contributing.contains("service implementation and deployment")
            && contributing.contains("separate from this repository"),
        "CONTRIBUTING.md must keep the acceptance service separate from this repository"
    );
    assert!(
        maintainer.contains("implemented and deployed outside")
            && maintainer.contains("details remain outside this repository"),
        "maintainer policy must keep the acceptance service separate from AOS"
    );

    for (name, document, markers) in [
        (
            "CONTRIBUTING.md",
            contributing.as_str(),
            [
                "Every external human contributor",
                "Current Andyl, Inc. employees",
                "must fail closed",
            ],
        ),
        (
            "LICENSING.md",
            licensing.as_str(),
            [
                "External AOS",
                "Andyl's standard CIAA",
                "Certificate of Origin `Signed-off-by`",
            ],
        ),
        (
            "AGENTS.md",
            agents.as_str(),
            [
                "Every external human contributor",
                "covered by Andyl's standard CIAA",
                "authorization check fails closed",
            ],
        ),
        (
            "docs/maintainers/contributor-licensing.md",
            maintainer.as_str(),
            [
                "stable GitHub numeric user ID",
                "may be merged only when",
                "Do not bypass the check manually",
            ],
        ),
    ] {
        for marker in markers {
            assert!(document.contains(marker), "{name} must contain `{marker}`");
        }
    }

    let public_policy_documents = [
        ("AGENTS.md", agents.as_str()),
        ("CONTRIBUTING.md", contributing.as_str()),
        ("CONTRIBUTOR_LICENSE_AGREEMENT.md", agreement.as_str()),
        ("LICENSING.md", licensing.as_str()),
        ("README.md", readme.as_str()),
        ("docs/maintainers/README.md", maintainer_index.as_str()),
        (
            "docs/maintainers/contributor-licensing.md",
            maintainer.as_str(),
        ),
    ];
    for obsolete in [
        "legal person or entity identified by the AOS",
        "Before this agreement is used for signatures",
        "separate corporate agreement",
        "mailto:",
        "Notice address:",
        "Mailing address:",
    ] {
        for (name, document) in public_policy_documents {
            assert!(
                !document.contains(obsolete),
                "{name} must not retain private or obsolete text `{obsolete}`"
            );
        }
    }
    for (name, document) in public_policy_documents {
        for token in document
            .split_whitespace()
            .filter(|token| token.contains('@'))
        {
            assert!(
                !token.to_ascii_lowercase().contains("andyl"),
                "{name} must not publish an Andyl mailbox"
            );
        }
        for token in document.split_whitespace().filter(|token| {
            let lowercase = token.to_ascii_lowercase();
            lowercase.contains("://") && lowercase.contains("cla")
        }) {
            let url = token.trim_matches(|character: char| {
                matches!(
                    character,
                    '<' | '>' | '(' | ')' | '[' | ']' | ',' | '.' | ';' | '"' | '\''
                )
            });
            assert_eq!(
                url, "https://cla.andyl.org/aos",
                "{name} contains a competing CLA frontend `{url}`"
            );
        }
    }
    Ok(())
}
