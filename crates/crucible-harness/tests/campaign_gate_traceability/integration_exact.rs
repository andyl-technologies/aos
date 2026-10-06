//! Exact integration-selector source and Nix-contract validation.

use super::*;

pub(super) fn integration_exact_target_failures(
    root: &Path,
    gate: &str,
    target: &crucible_harness::campaign_gates::CampaignGateTarget,
) -> Vec<String> {
    let CampaignGateTargetKind::IntegrationExact {
        test_target,
        selectors,
        nix_sources,
        runner,
        evidence,
        ignored,
    } = target.kind
    else {
        return vec![format!("{gate}: target is not an exact integration test")];
    };
    let package = target.package;
    let mut failures = Vec::new();
    let manifest = root.join("crates").join(package).join("Cargo.toml");
    if !manifest.is_file() {
        failures.push(format!(
            "{gate}: integration package manifest {} is missing",
            manifest.display()
        ));
    }
    let test_path = root
        .join("crates")
        .join(package)
        .join("tests")
        .join(format!("{test_target}.rs"));
    if !test_path.is_file() {
        failures.push(format!(
            "{gate}: integration target source {} is missing",
            test_path.display()
        ));
    }
    if selectors.is_empty() {
        failures.push(format!("{gate}: integration exact selector set is empty"));
    }

    let mut unique_selectors = BTreeSet::new();
    for selector in selectors {
        if !unique_selectors.insert(selector.name) {
            failures.push(format!(
                "{gate}: duplicate integration exact selector {}",
                selector.name
            ));
        }
        let source_path = root.join(selector.source);
        match fs::read_to_string(&source_path) {
            Ok(source) => failures.extend(exact_selector_source_failures(
                gate,
                selector.source,
                selector.name,
                &source,
                ignored,
            )),
            Err(_) => failures.push(format!(
                "{gate}: integration selector source {} is missing",
                source_path.display()
            )),
        }
    }

    let mut nix = String::new();
    for source in nix_sources {
        let source_path = root.join(source);
        match fs::read_to_string(&source_path) {
            Ok(contents) => nix.push_str(&contents),
            Err(_) => failures.push(format!(
                "{gate}: integration selector Nix source {} is missing",
                source_path.display()
            )),
        }
    }
    failures.extend(integration_selector_nix_failures(IntegrationNixContract {
        gate,
        package,
        test_target,
        selectors,
        runner,
        evidence,
        nix: &nix,
        ignored,
    }));

    failures
}

pub(super) struct IntegrationNixContract<'a> {
    pub(super) gate: &'a str,
    pub(super) package: &'a str,
    pub(super) test_target: &'a str,
    pub(super) selectors: &'a [ExactSelector],
    pub(super) runner: &'a str,
    pub(super) evidence: &'a [&'a str],
    pub(super) nix: &'a str,
    pub(super) ignored: bool,
}

pub(super) fn integration_selector_nix_failures(
    contract: IntegrationNixContract<'_>,
) -> Vec<String> {
    let IntegrationNixContract {
        gate,
        package,
        test_target,
        selectors,
        runner,
        evidence,
        nix,
        ignored,
    } = contract;
    let mut failures = Vec::new();
    if !contains_word_sequence(nix, &["-p", package])
        || !contains_word_sequence(nix, &["--test", test_target])
    {
        failures.push(format!(
            "{gate}: integration Nix flight does not build {package} --test {test_target}"
        ));
    }
    if !nix.contains(&format!("/bin/{runner}")) {
        failures.push(format!(
            "{gate}: integration Nix flight does not run {runner}"
        ));
    }
    if !nix.contains("--exact") {
        failures.push(format!(
            "{gate}: integration Nix flight lacks exact-selector execution"
        ));
    }
    if ignored && !nix.contains("--ignored --exact") {
        failures.push(format!(
            "{gate}: integration Nix flight lacks --ignored --exact execution"
        ));
    }
    if ignored && !nix.contains("test result: ok. 1 passed; 0 failed; 0 ignored;") {
        failures.push(format!(
            "{gate}: integration Nix flight lacks the exact one-passed assertion"
        ));
    }
    for selector in selectors {
        if !nix.contains(selector.name) {
            failures.push(format!(
                "{gate}: integration Nix flight omits selector {}",
                selector.name
            ));
        }
    }
    for line in evidence {
        if !nix.contains(line) {
            failures.push(format!(
                "{gate}: integration Nix flight omits evidence {line}"
            ));
        }
    }

    failures
}
