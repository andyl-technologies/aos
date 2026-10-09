//! Recovers independently selected module roots from a retained dependency graph.
//!
//! Implicit dependencies must remain eligible for compatible reselection. Source
//! strongly connected components identify the minimal roots retaining the same
//! closure, including cycles and moduleless aggregators. Explicit payload roots
//! remain the caller's separate policy and may add roots to this set.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Result, ensure};

use crate::deployment::model::Envelope;

/// Returns deterministic representatives of dependency components without parents.
///
/// # Errors
/// Returns an error for ambiguous package identities or an incomplete closure.
pub(crate) fn root_names(envelopes: &[Envelope]) -> Result<BTreeSet<String>> {
    let mut packages = BTreeMap::new();
    for envelope in envelopes {
        if let Some(previous) = packages.insert(envelope.package.name.clone(), envelope) {
            ensure!(
                super::same_package_context(previous, envelope),
                "retained module root has conflicting identities: {}",
                envelope.package.name
            );
        }
    }
    let names = packages.keys().cloned().collect::<Vec<_>>();
    let indices = names
        .iter()
        .enumerate()
        .map(|(index, name)| (name, index))
        .collect::<BTreeMap<_, _>>();
    let mut outgoing = vec![Vec::new(); names.len()];
    let mut incoming = vec![Vec::new(); names.len()];
    for (index, package) in packages.values().enumerate() {
        for dependency in &package.module_dependencies {
            let target = indices.get(&dependency.seed().name);
            ensure!(
                target.is_some(),
                "retained module dependency {} is absent",
                dependency.seed().name
            );
            if let Some(&target) = target {
                outgoing[index].push(target);
                incoming[target].push(index);
            }
        }
    }

    // Iterative Kosaraju traversal bounds stack use independently of package
    // graph depth. Finishing order identifies each component in the transpose.
    let mut finished = Vec::new();
    let mut seen = vec![false; names.len()];
    for start in 0..names.len() {
        let mut pending = vec![(start, false)];
        while let Some((node, finish)) = pending.pop() {
            if finish {
                finished.push(node);
            } else if !seen[node] {
                seen[node] = true;
                pending.push((node, true));
                pending.extend(outgoing[node].iter().rev().map(|&child| (child, false)));
            }
        }
    }

    let mut components = vec![None; names.len()];
    let mut representatives = Vec::new();
    for start in finished.into_iter().rev() {
        if components[start].is_some() {
            continue;
        }
        let component = representatives.len();
        let mut representative = start;
        let mut pending = vec![start];
        while let Some(node) = pending.pop() {
            if components[node].is_some() {
                continue;
            }
            components[node] = Some(component);
            representative = representative.min(node);
            pending.extend(incoming[node].iter().copied());
        }
        representatives.push(representative);
    }

    let mut has_parent = vec![false; representatives.len()];
    for (source, targets) in outgoing.iter().enumerate() {
        for &target in targets {
            if components[source] != components[target] {
                if let Some(component) = components[target] {
                    has_parent[component] = true;
                }
            }
        }
    }
    Ok(representatives
        .into_iter()
        .enumerate()
        .filter(|(component, _)| !has_parent[*component])
        .map(|(_, representative)| names[representative].clone())
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::deployment::model::{Artifact, ModuleDependency, ModuleSource};

    fn package(name: &str, dependencies: &[&str]) -> Envelope {
        let source = |name: &str| ModuleSource {
            name: name.into(),
            version: "1.0.0".into(),
            source: format!("/nix/store/{}-{name}-module", "0".repeat(32)),
            entrypoint: "module.nix".into(),
        };
        let path = format!("/nix/store/{}-{name}", "0".repeat(32));
        Envelope {
            schema: "aos.package.deployment".into(),
            system: "x86_64-linux".into(),
            package: Artifact {
                name: name.into(),
                version: "1.0.0".into(),
                path: path.clone(),
                outputs: BTreeMap::from([("out".into(), path)]),
                main_program: None,
            },
            module: Some(source(name)),
            runtime_dependencies: BTreeMap::new(),
            version_requirement: None,
            os_version: None,
            module_dependencies: dependencies
                .iter()
                .map(|name| ModuleDependency::Exact(source(name)))
                .collect(),
        }
    }

    #[test]
    fn independent_handler_remains_a_root_while_interfaces_are_dependencies() {
        let packages = [
            package("application", &["interface"]),
            package("interface", &[]),
            package("handler", &[]),
        ];
        assert_eq!(
            root_names(&packages).unwrap(),
            BTreeSet::from(["application".into(), "handler".into()])
        );
    }

    #[test]
    fn source_cycles_have_one_root_and_downstream_cycles_have_none() {
        let packages = [
            package("z", &["y", "a"]),
            package("y", &["z"]),
            package("a", &["b"]),
            package("b", &["a"]),
        ];
        assert_eq!(root_names(&packages).unwrap(), BTreeSet::from(["y".into()]));
    }

    #[test]
    fn moduleless_requester_prevents_its_dependency_becoming_an_independent_root() {
        let mut aggregate = package("aggregate", &["interface"]);
        aggregate.module = None;
        assert_eq!(
            root_names(&[aggregate, package("interface", &[])]).unwrap(),
            BTreeSet::from(["aggregate".into()])
        );
    }

    #[test]
    fn closure_rejects_missing_dependencies_and_conflicting_same_name_packages() {
        assert!(root_names(&[package("application", &["missing"])]).is_err());
        let original = package("application", &[]);
        let mut conflicting = original.clone();
        conflicting.package.version = "2.0.0".into();
        assert!(root_names(&[original, conflicting]).is_err());
        assert!(root_names(&[]).unwrap().is_empty());
    }
}
