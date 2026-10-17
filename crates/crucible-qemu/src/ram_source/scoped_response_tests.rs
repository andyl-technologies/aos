//! Verifies actual scoped consumption precedence and duplicate-effect refusal.

use super::*;
use std::cell::Cell;

use crate::qmp::checkpoint_paged_source_support::ImmutableBacking;

enum Delivery {
    None,
    FailBefore,
    Once,
    OnceThenFail,
    Twice,
}

struct AdversarialBacking {
    original: ImmutableBacking,
    delivery: Delivery,
}

impl QemuRamBacking for AdversarialBacking {
    fn root_object_id(&self) -> &str {
        self.original.root_object_id()
    }

    fn root_record(&self) -> &RootRecord {
        self.original.root_record()
    }

    fn with_page_response(
        &self,
        region: &str,
        index: u64,
        boundary: &mut QemuRamReadBoundary<'_>,
        consumer: &mut QemuRamResponseConsumer<'_>,
    ) -> Result<(), QemuRamSourceError> {
        match self.delivery {
            Delivery::None => return Ok(()),
            Delivery::FailBefore => {
                return Err(QemuRamSourceError::Backing("source-before".to_owned()));
            }
            _ => {}
        }
        self.original
            .with_page_response(region, index, boundary, consumer)?;
        match self.delivery {
            Delivery::OnceThenFail => Err(QemuRamSourceError::Backing("source-after".to_owned())),
            Delivery::Twice => self
                .original
                .with_page_response(region, index, boundary, consumer),
            _ => Ok(()),
        }
    }
}

fn backing(delivery: Delivery) -> Result<AdversarialBacking, Box<dyn std::error::Error>> {
    Ok(AdversarialBacking {
        original: ImmutableBacking::new(2)?,
        delivery,
    })
}

#[test]
fn successful_source_without_consumption_refuses_ownership()
-> Result<(), Box<dyn std::error::Error>> {
    let original = backing(Delivery::None)?;
    let effects = Cell::new(0);
    let error = consume_backing_page(&original, "machine.ram", 0, &mut || Ok(()), &mut |_, _| {
        effects.set(effects.get() + 1);
        Ok(())
    })
    .err()
    .ok_or("missing response was accepted")?;

    assert!(matches!(error, QemuRamSourceError::Ownership));
    assert_eq!(effects.get(), 0);
    Ok(())
}

#[test]
fn actual_source_failure_before_consumption_remains_first() -> Result<(), Box<dyn std::error::Error>>
{
    let original = backing(Delivery::FailBefore)?;
    let effects = Cell::new(0);
    let error = consume_backing_page(&original, "machine.ram", 0, &mut || Ok(()), &mut |_, _| {
        effects.set(effects.get() + 1);
        Ok(())
    })
    .err()
    .ok_or("source failure was accepted")?;

    assert!(matches!(error, QemuRamSourceError::Backing(ref source) if source == "source-before"));
    assert_eq!(effects.get(), 0);
    Ok(())
}

#[test]
fn swallowed_or_replaced_consumer_error_keeps_its_actual_source()
-> Result<(), Box<dyn std::error::Error>> {
    for delivery in [Delivery::Once, Delivery::OnceThenFail, Delivery::Twice] {
        let original = backing(delivery)?;
        let effects = Cell::new(0);
        let error =
            consume_backing_page(&original, "machine.ram", 0, &mut || Ok(()), &mut |_, _| {
                effects.set(effects.get() + 1);
                Err(io::Error::from_raw_os_error(42).into())
            })
            .err()
            .ok_or("consumer failure was erased")?;

        assert!(
            matches!(error, QemuRamSourceError::Io(ref cause) if cause.raw_os_error() == Some(42))
        );
        assert_eq!(effects.get(), 1);
    }
    Ok(())
}

#[test]
fn provider_failure_after_successful_consumption_is_retained()
-> Result<(), Box<dyn std::error::Error>> {
    let original = backing(Delivery::OnceThenFail)?;
    let effects = Cell::new(0);
    let error = consume_backing_page(&original, "machine.ram", 0, &mut || Ok(()), &mut |_, _| {
        effects.set(effects.get() + 1);
        Ok(())
    })
    .err()
    .ok_or("later provider failure was erased")?;

    assert!(matches!(error, QemuRamSourceError::Backing(ref source) if source == "source-after"));
    assert_eq!(effects.get(), 1);
    Ok(())
}

#[test]
fn double_delivery_cannot_repeat_the_original_page_publication()
-> Result<(), Box<dyn std::error::Error>> {
    use crucible_linux_resource::host_supervision::HostOperationBudgets;

    let original = backing(Delivery::Twice)?;
    let supervisor = HostOperationSupervisor::new(
        HostOperationBudgets::default(),
        Some(Duration::from_secs(5)),
    )?;
    let operation = supervisor.begin(HostOperationClass::PageIn)?;
    let (mut sender, mut receiver) = UnixStream::pair()?;
    let effects = Cell::new(0);
    let binding = RamPageBinding {
        session: [1; 16],
        owner_incarnation: [2; 16],
        source_generation: 1,
        root_digest: *original.root_record().digest().as_bytes(),
    };
    let error = consume_backing_page(
        &original,
        "machine.ram",
        0,
        &mut || Ok(()),
        &mut |response, _| {
            effects.set(effects.get() + 1);
            operation.wait_slice()?;
            response
                .proof()
                .verify(
                    response.bytes(),
                    original.root_record(),
                    original.root_record().digest(),
                )
                .map_err(|cause| QemuRamSourceError::Proof(cause.to_string()))?;
            send_response(
                &mut sender,
                &operation,
                RamPageResponse {
                    binding,
                    sequence: 1,
                    status: RamPageStatus::Page,
                    page: response.bytes(),
                    proof: response.encoded_proof(),
                },
            )?;
            operation.progress(1)?;
            operation.complete()?;
            Ok(())
        },
    )
    .err()
    .ok_or("second delivery was accepted")?;
    sender.shutdown(std::net::Shutdown::Write)?;
    let mut bytes = Vec::new();
    receiver.read_to_end(&mut bytes)?;
    let response = RamPageResponse::decode(&bytes)?;

    assert!(matches!(error, QemuRamSourceError::Ownership));
    assert_eq!(effects.get(), 1);
    assert_eq!(response.sequence, 1);
    assert_eq!(response.page, &[1; 4096]);
    assert!(operation.wait_slice().is_err());
    Ok(())
}
