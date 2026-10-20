//! Retains each reached normal startup check and independently owed native posts.

use std::path::Path;

use aos_sandbox_broker::immutable_image::{
    ImmutableExecutedFileOriginalV1, ImmutableFileRevalidationOriginalV1,
};
use aos_sandbox_broker::profile_data::images::ActualExecutableMappingsOriginalV1;
use aos_sandbox_broker::profile_data::status::CurrentProcessStatusOriginalV1;
use aos_sandbox_linux::selinux_policy::RetainedLiveSelinuxPolicyReadbackV1;

use super::*;

#[derive(Clone, Copy)]
enum Stage {
    Files(usize, usize),
    Executed(usize),
    Maps(usize),
    Status(usize),
    StatusPolicy(usize),
    Mac(usize),
    MacPolicy(usize),
    Order,
}

pub(super) struct CurrentOriginal {
    files: [Vec<ImmutableFileRevalidationOriginalV1>; 2],
    files_entered: usize,
    executed: [ImmutableExecutedFileOriginalV1; 4],
    executed_entered: usize,
    maps: [ActualExecutableMappingsOriginalV1; 2],
    maps_entered: bool,
    status: [CurrentProcessStatusOriginalV1; 2],
    status_entered: bool,
    status_policy: [Option<Result<(), super::super::super::RuntimeDeploymentStartupErrorV1>>; 2],
    mac: [RetainedLiveSelinuxPolicyReadbackV1; 2],
    mac_entered: bool,
    mac_policy: [Option<Result<(), RuntimeBootPreparationStartupClosedV1>>; 2],
    first: Option<Stage>,
    closed: RuntimeBootPreparationStartupClosedV1,
}

impl CurrentOriginal {
    fn new(files: usize) -> Self {
        Self {
            files: std::array::from_fn(|_| {
                (0..files)
                    .map(|_| ImmutableFileRevalidationOriginalV1::new())
                    .collect()
            }),
            files_entered: 0,
            executed: std::array::from_fn(|_| ImmutableExecutedFileOriginalV1::new()),
            executed_entered: 0,
            maps: std::array::from_fn(|_| ActualExecutableMappingsOriginalV1::new()),
            maps_entered: false,
            status: std::array::from_fn(|_| CurrentProcessStatusOriginalV1::new()),
            status_entered: false,
            status_policy: std::array::from_fn(|_| None),
            mac: std::array::from_fn(|_| RetainedLiveSelinuxPolicyReadbackV1::new()),
            mac_entered: false,
            mac_policy: std::array::from_fn(|_| None),
            first: None,
            closed: RuntimeBootPreparationStartupClosedV1,
        }
    }

    fn files(body: &Body) -> usize {
        4 + body.runtime.len() + body.evidence.len()
    }

    fn file(body: &Body, index: usize) -> Option<&RetainedImmutableFileV1> {
        match index {
            0 => body.profile.completed_measurement(),
            1 => body.pid1.completed_measurement(),
            2 => body.executable.completed_measurement(),
            3 => body.fragment.completed_measurement(),
            index => body
                .runtime
                .iter()
                .chain(&body.evidence)
                .nth(index.checked_sub(4)?),
        }
    }

    fn input_bound(body: &Body, index: usize) -> Option<u64> {
        Self::file(body, index)?.maximum_requested_read_bytes_v1()
    }

    fn demand(body: &Body) -> Option<ResourceVector> {
        let files = Self::files(body);
        let mut quote = ResourceVector::ZERO.with(
            D::MemoryBytes,
            u64::try_from(std::mem::size_of::<Self>().checked_mul(2)?).ok()?,
        );
        let file_owner = ImmutableFileRevalidationOriginalV1::receiving_demand_v1()?;
        // These two Vec planes are outside the inline Self. Each new member's
        // constructor and final resident destination coexist before native IO.
        let file_control = std::mem::size_of::<ImmutableFileRevalidationOriginalV1>();
        for index in 0..files {
            for _ in 0..2 {
                quote = quote
                    .checked_add(file_owner)
                    .ok()?
                    .checked_add(
                        ResourceVector::ZERO
                            .with(D::MemoryBytes, u64::try_from(file_control).ok()?)
                            .with(D::OutputBytes, Self::input_bound(body, index)?),
                    )
                    .ok()?;
            }
        }
        // Each executed-file probe owns one new actual proc executable OFD.
        // Its result carrier is inline; only the bounded path backing is added.
        quote = quote
            .checked_add(
                ResourceVector::ZERO
                    .with(D::MemoryBytes, 4 * 128)
                    .with(D::OpenFiles, 4)
                    .with(D::MetadataEntries, 8),
            )
            .ok()?;
        for _ in 0..2 {
            let maps = ActualExecutableMappingsOriginalV1::receiving_demand_v1(body.runtime.len())?;
            let status = CurrentProcessStatusOriginalV1::receiving_demand_v1()?;
            // Their inline constructor/result layouts are already in 2Self.
            let inline = std::mem::size_of::<ActualExecutableMappingsOriginalV1>()
                .checked_add(std::mem::size_of::<CurrentProcessStatusOriginalV1>())?
                .checked_mul(2)?;
            quote = quote
                .checked_add(maps)
                .ok()?
                .checked_add(status)
                .ok()?
                .checked_sub(ResourceVector::ZERO.with(D::MemoryBytes, u64::try_from(inline).ok()?))
                .ok()?;
            let live = RetainedLiveSelinuxPolicyReadbackV1::receiving_demand_v1();
            let inline =
                std::mem::size_of::<RetainedLiveSelinuxPolicyReadbackV1>().checked_mul(2)?;
            quote = quote
                .checked_add(
                    ResourceVector::ZERO
                        .with(
                            D::MemoryBytes,
                            u64::try_from(live.memory_bytes.checked_sub(inline)?).ok()?,
                        )
                        .with(D::OpenFiles, u64::try_from(live.open_files).ok()?)
                        .with(D::OutputBytes, live.input_bytes)
                        .with(
                            D::MetadataEntries,
                            u64::try_from(
                                Path::new(&body.model().ok()?.selinux_policy)
                                    .components()
                                    .count()
                                    .checked_add(
                                        Path::new("/sys/fs/selinux/policy").components().count(),
                                    )?
                                    .checked_add(
                                        Path::new("/sys/fs/selinux/enforce").components().count(),
                                    )?,
                            )
                            .ok()?,
                        ),
                )
                .ok()?;
        }
        Some(quote)
    }

    fn fail(&mut self, stage: Stage) -> RuntimeBootPreparationStartupClosedV1 {
        self.first.get_or_insert(stage);
        self.closed
    }

    fn body(&mut self, body: &Body) -> Result<(), RuntimeBootPreparationStartupClosedV1> {
        for index in 0..Self::files(body) {
            self.files_entered = index + 1;
            let file = Self::file(body, index).ok_or_else(|| self.fail(Stage::Order))?;
            if file
                .revalidate_retaining(&mut self.files[0][index])
                .is_err()
            {
                return Err(self.fail(Stage::Files(0, index)));
            }
        }
        for (index, pid) in [1, std::process::id()].into_iter().enumerate() {
            self.executed_entered = index + 1;
            let file = if index == 0 {
                body.pid1.completed_measurement()
            } else {
                body.executable.completed_measurement()
            }
            .ok_or_else(|| self.fail(Stage::Order))?;
            if file
                .require_executed_retaining_v1(pid, &mut self.executed[index])
                .is_err()
            {
                return Err(self.fail(Stage::Executed(index)));
            }
        }
        self.maps_entered = true;
        self.maps_once(body, 0)?;
        self.status_entered = true;
        self.status_once(0)?;
        self.mac_entered = true;
        self.mac_once(body, 0)
    }

    fn maps_once(
        &mut self,
        body: &Body,
        index: usize,
    ) -> Result<(), RuntimeBootPreparationStartupClosedV1> {
        let model = body.model()?;
        if self.maps[index]
            .observe_once_v1(
                &body.runtime,
                &[
                    &model.publisher.executable.path,
                    &model.publisher.loader.path,
                ],
            )
            .is_err()
        {
            return Err(self.fail(Stage::Maps(index)));
        }
        Ok(())
    }

    fn status_once(&mut self, index: usize) -> Result<(), RuntimeBootPreparationStartupClosedV1> {
        if self.status[index].observe_once_v1().is_err() {
            return Err(self.fail(Stage::Status(index)));
        }
        let bytes = self.status[index].bytes_v1().ok_or(self.closed)?;
        self.status_policy[index] = Some(super::super::require_status(bytes));
        if !matches!(self.status_policy[index], Some(Ok(()))) {
            return Err(self.fail(Stage::StatusPolicy(index)));
        }
        Ok(())
    }

    fn mac_once(
        &mut self,
        body: &Body,
        index: usize,
    ) -> Result<(), RuntimeBootPreparationStartupClosedV1> {
        let model = body.model()?;
        if self.mac[index].verify_once(&model.selinux_policy).is_err() {
            return Err(self.fail(Stage::Mac(index)));
        }
        self.mac_policy[index] = Some(
            if self.mac[index]
                .verified()
                .is_some_and(|policy| policy.digest() == model.publisher.canonical_policy.sha256)
            {
                Ok(())
            } else {
                Err(self.closed)
            },
        );
        if !matches!(self.mac_policy[index], Some(Ok(()))) {
            return Err(self.fail(Stage::MacPolicy(index)));
        }
        Ok(())
    }

    fn posts(&mut self, body: &Body) -> Result<(), RuntimeBootPreparationStartupClosedV1> {
        for index in 0..self.files_entered {
            if let Some(file) = Self::file(body, index) {
                if file
                    .revalidate_retaining(&mut self.files[1][index])
                    .is_err()
                {
                    self.fail(Stage::Files(1, index));
                }
            } else {
                self.fail(Stage::Order);
            }
        }
        for index in 0..self.executed_entered {
            let after = index + 2;
            let file = if index == 0 {
                body.pid1.completed_measurement()
            } else {
                body.executable.completed_measurement()
            };
            let pid = if index == 0 { 1 } else { std::process::id() };
            match file {
                Some(file)
                    if file
                        .require_executed_retaining_v1(pid, &mut self.executed[after])
                        .is_ok() => {}
                _ => {
                    self.fail(Stage::Executed(after));
                }
            }
        }
        // Every entered primary lane owns a distinct prepaid after. These run
        // without calling the Source healthy/debit gate after any body failure.
        if self.maps_entered {
            let _after = self.maps_once(body, 1);
        }
        if self.status_entered {
            let _after = self.status_once(1);
        }
        if self.mac_entered {
            let _after = self.mac_once(body, 1);
        }
        if self.first.is_some() {
            Err(self.closed)
        } else {
            Ok(())
        }
    }

    pub(super) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        match self.first? {
            Stage::Files(plane, index) => self.files.get(plane)?.get(index)?.failure(),
            Stage::Executed(index) => self.executed.get(index)?.failure(),
            Stage::Maps(index) => self.maps.get(index)?.failure_v1(),
            Stage::Status(index) => self.status.get(index)?.failure_v1(),
            Stage::StatusPolicy(index) => result_failure(self.status_policy.get(index)?),
            Stage::Mac(index) => self.mac.get(index)?.failure(),
            Stage::MacPolicy(index) => result_failure(self.mac_policy.get(index)?),
            Stage::Order => Some(&self.closed as &(dyn Error + 'static)),
        }
        .or(Some(&self.closed))
    }
}

impl RuntimeBootPreparationStartupOriginalV1 {
    // The actual normal Origins bracket reserves this distinct after before
    // credential entry. Its private index can only select this owner's lane.
    pub(in crate::runtime_deployment) fn prepare_current_owed_v1(
        &self,
    ) -> Result<usize, RuntimeBootPreparationStartupClosedV1> {
        if !self.admitted || self.first.get().is_some() || self.after_attempted.get() {
            return Err(self.closed);
        }
        let body = self.body.as_ref().ok_or(self.closed)?;
        self.fund_additional(CurrentOriginal::demand(body))?;
        let mut current = self.current.try_borrow_mut().map_err(|_| self.fail(First::Order))?;
        let mut allocation = self.allocation.try_borrow_mut().map_err(|_| self.fail(First::Order))?;
        *allocation = Some(current.try_reserve_exact(1));
        if !matches!(*allocation, Some(Ok(()))) { return Err(self.fail(First::Allocation)); }
        drop(allocation);
        let index = current.len();
        current.push(CurrentOriginal::new(CurrentOriginal::files(body)));
        Ok(index)
    }

    // This is an owed native observation, never a positive startup loan. It
    // consumes only the separately prepaid, still-unentered original lane and
    // runs both native planes despite an earlier Source/credential refusal.
    pub(in crate::runtime_deployment) fn observe_current_owed_once_v1(
        &self, index: usize,
    ) -> Result<(), RuntimeBootPreparationStartupClosedV1> {
        if self.after_attempted.get() { return Err(self.fail(First::Order)); }
        let body = self.body.as_ref().ok_or(self.closed)?;
        let mut current = self.current.try_borrow_mut().map_err(|_| self.fail(First::Order))?;
        let lane = current.get_mut(index).ok_or_else(|| self.fail(First::Order))?;
        // Interrupted native entry already retained its reached primary
        // originals. Resume only its separate posts; the lower originals'
        // one-shot latches prevent repeating any entered post observation.
        let primary = if lane.files_entered == 0 && lane.first.is_none() {
            lane.body(body)
        } else {
            Err(self.closed)
        };
        if primary.is_err() { self.fail(First::Current(index)); }
        let posts = lane.posts(body);
        if posts.is_err() { self.fail(First::Current(index)); }
        if self.first.get().is_some() { Err(self.closed) } else { Ok(()) }
    }

    /// Rechecks the same positive startup under its actual unfinished Source.
    ///
    /// Every new native destination and its independent post is admitted from
    /// this original's remaining ledger before growth. Prior observations stay
    /// resident; a failure permanently prevents another positive startup loan.
    ///
    /// # Errors
    /// Refuses absent admission, closed Source/identity, geometry/allocation,
    /// original file/image/mapping/status/MAC drift or any independently owed
    /// post. The first actual native/financial cause remains selected.
    pub fn require_current_v1(&self) -> Result<(), RuntimeBootPreparationStartupClosedV1> {
        if !self.admitted || self.first.get().is_some() || self.after_attempted.get() {
            return Err(self.closed);
        }
        let origin = self.origin.ok_or(self.closed)?;
        if self
            .source
            .try_borrow()
            .map_err(|_| self.fail(First::Order))?
            .require_same_origin_current_v1(&origin)
            .is_err()
        {
            return Err(self.fail(First::Source));
        }
        let body = self.body.as_ref().ok_or(self.closed)?;
        self.fund_additional(CurrentOriginal::demand(body))?;
        let mut current = self
            .current
            .try_borrow_mut()
            .map_err(|_| self.fail(First::Order))?;
        let mut allocation = self
            .allocation
            .try_borrow_mut()
            .map_err(|_| self.fail(First::Order))?;
        *allocation = Some(current.try_reserve_exact(1));
        if !matches!(*allocation, Some(Ok(()))) {
            return Err(self.fail(First::Allocation));
        }
        drop(allocation);
        let index = current.len();
        current.push(CurrentOriginal::new(CurrentOriginal::files(body)));
        let lane = current.last_mut().ok_or(self.closed)?;
        let primary = lane.body(body);
        if primary.is_err() {
            self.fail(First::Current(index));
        }
        let posts = lane.posts(body);
        if posts.is_err() {
            self.fail(First::Current(index));
        }
        // This comparison issues no new Source or deadline. It is independent
        // of the body marker, and the outer actual Source native after is still
        // owed by the main publisher once all 055/publication work finishes.
        let source_after = self
            .source
            .try_borrow()
            .map_err(|_| self.fail(First::Order))?
            .require_same_origin_current_v1(&origin);
        if source_after.is_err() {
            self.fail(First::Source);
        }
        if self.first.get().is_some() {
            Err(self.closed)
        } else {
            Ok(())
        }
    }
}
