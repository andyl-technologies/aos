//! Tests campaign run, save, and resume CLI projection.

use super::*;

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use clap::Parser;
use crucible_api::ProductionVmLifecycleConfig;
use crucible_campaign::{
    AssertionViolationWitness, BooleanDomain, CampaignHash, ChoiceClassContext, ChoiceCoordinate,
    ChoiceDomain, ChoiceOpportunity, ChoiceSource, ChoiceValue, ObservationEventLogProof,
    ObservationQuantumBoundary, ObservationStopProof, SelectableDeclaration, Selection,
    SelectionOrigin,
};
use crucible_daemon::LinuxQemuAttemptHostConfig;
use crucible_daemon::qemu_campaign_lifecycle::{
    run_guarded_default_campaign_test_fixture_with_choice_offer,
    run_guarded_default_campaign_test_fixture_with_trace_and_choice_offer,
};
use tempfile::TempDir;

trait TestValue<T> {
    #[track_caller]
    fn or_panic(self, message: &str) -> T;
}

impl<T> TestValue<T> for Option<T> {
    #[track_caller]
    fn or_panic(self, message: &str) -> T {
        self.unwrap_or_else(|| panic!("{message}"))
    }
}

impl<T, E> TestValue<T> for Result<T, E>
where
    E: std::fmt::Debug,
{
    #[track_caller]
    fn or_panic(self, message: &str) -> T {
        self.unwrap_or_else(|error| panic!("{message}: {error:?}"))
    }
}

trait TestError<E> {
    #[track_caller]
    fn error_or_panic(self, message: &str) -> E;
}

impl<T, E> TestError<E> for Result<T, E> {
    #[track_caller]
    fn error_or_panic(self, message: &str) -> E {
        match self {
            Ok(_) => panic!("{message}"),
            Err(error) => error,
        }
    }
}

#[path = "tests/capacity.rs"]
mod capacity;
#[path = "tests/resume.rs"]
mod resume;
#[path = "tests/routes.rs"]
mod routes;
#[path = "tests/save_assertions.rs"]
mod save_assertions;
#[path = "tests/save_support.rs"]
mod save_support;
#[path = "tests/support.rs"]
mod support;

use save_assertions::*;
use save_support::*;
use support::*;
