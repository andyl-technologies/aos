//! Native process entry point for authorized provisioning evaluation.

use std::io::{self, Read as _, Write as _};

use anyhow::{Context as _, Result, ensure};
use aos_ability_model::ABILITY_LIMITS_V1;
use aos_ability_runtime::activation::{Action, Invocation};
use aos_ability_runtime::adapter::CancellationToken;
use serde_json::json;

use super::provisioning_evaluator::{self, EvaluationParameters};

/// Executes one bounded native evaluation invocation from process streams.
///
/// # Errors
/// Returns an error for invalid actions, oversized requests/results, changed
/// retained authorization or module sources, or failed pure evaluation.
pub async fn run_from_process() -> Result<()> {
    let arguments = std::env::args().skip(1).collect::<Vec<_>>();
    ensure!(
        arguments.len() == 1 && matches!(arguments[0].as_str(), "apply" | "remove" | "observe"),
        "expected one native invocation action"
    );
    let mut bytes = Vec::new();
    io::stdin()
        .take(ABILITY_LIMITS_V1.max_document_bytes + 1)
        .read_to_end(&mut bytes)?;
    ensure!(
        u64::try_from(bytes.len())? <= ABILITY_LIMITS_V1.max_document_bytes,
        "invocation exceeds the document bound"
    );
    let invocation: Invocation = serde_json::from_slice(&bytes)?;
    let action = arguments[0].as_str();
    ensure!(
        action == "observe"
            || matches!(
                (action, invocation.action),
                ("apply", Action::Apply) | ("remove", Action::Remove)
            ),
        "action differs from native invocation"
    );
    let result = match action {
        "remove" => json!({}),
        // Evaluation is pure and fresh inputs must be projected again after an
        // interrupted dispatch; no ambient file can establish completion.
        "observe" => {
            json!({"status":if invocation.action == Action::Remove {"absent"} else {"retry-safe"}})
        }
        _ => {
            let parameters: EvaluationParameters = serde_json::from_value(invocation.input)?;
            provisioning_evaluator::evaluate(
                parameters,
                invocation.effect.timeout_ms,
                &CancellationToken::default(),
            )?
        }
    };
    let output = serde_json::to_vec(&result)?;
    ensure!(
        output.len() <= 1024 * 1024,
        "native evaluator result exceeds the handler result bound"
    );
    io::stdout()
        .write_all(&output)
        .context("writing native evaluation result")
}
