//! Closed compact upstream custody cannot carry arbitrary provider response bodies.

use anyhow::Result;
use aos_assessment_runtime::provider::ProviderOperation;
use aos_assessment_runtime::source_chain::SourceChainCustodyV1;

#[test]
fn compact_chain_requires_exact_upstream_question_and_closed_bounded_shape() -> Result<()> {
    let chain = SourceChainCustodyV1 {
        schema: "aos.source-chain-custody/v1".into(),
        operation: ProviderOperation::ObserveGoReleases,
        sources: vec![],
    };
    let bytes = aos_contract::canonical::to_vec(&chain)?;
    assert_eq!(SourceChainCustodyV1::from_slice(&bytes)?, chain);
    let mut unsupported = chain.clone();
    unsupported.operation = ProviderOperation::RefreshKev { offset: 0 };
    assert!(
        SourceChainCustodyV1::from_slice(&aos_contract::canonical::to_vec(&unsupported)?).is_err()
    );
    let mut unknown = serde_json::to_value(&chain)?;
    unknown["providerBody"] = serde_json::json!("untrusted source response");
    assert!(SourceChainCustodyV1::from_slice(&aos_contract::canonical::to_vec(&unknown)?).is_err());
    assert!(SourceChainCustodyV1::from_slice(&vec![b' '; 262_145]).is_err());
    Ok(())
}
