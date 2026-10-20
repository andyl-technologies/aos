//! Shares the original Manager subscription, stream and task constructor.
//!
//! Local and retained destinations preserve one call and property recipe.
//! Only the retained destination parks partial setup and joins selected tasks.

// Both dispositions use the original constructor/Subscribe/stream/task recipe.
// Retained slots park actual SDK objects before each later fallible await.
macro_rules! setup_slot {
    (Local, park, $s:ident, $v:ident, $field:ident) => {};
    (Retained, park, $s:ident, $v:ident, $field:ident) => { $s.$field = Some($v); };
    (Local, borrow, $s:ident, $v:ident, $field:ident) => { $v };
    (Retained, borrow, $s:ident, $v:ident, $field:ident) => {
        $s.$field.as_ref().ok_or(Error::Zbus(zbus::Error::InvalidReply))?
    };
    (Local, take, $s:ident, $v:ident, $field:ident) => { $v };
    (Retained, take, $s:ident, $v:ident, $field:ident) => {{
        let Some(value) = $s.$field.take() else { std::process::abort() };
        value
    }};
    (Local, native, $s:ident) => { None };
    (Retained, native, $s:ident) => { Some(Arc::clone(&$s.disposition)) };
}

macro_rules! setup_task_stop_v2 {
    (Local, $state:ident) => { () };
    (Retained, $state:ident) => {{
        let (sender, receiver) = oneshot::channel();
        let mut original = $state.disposition.lock()
            .map_err(|_| Error::HostLaunchRetained("task stop destination borrowed"))?;
        original.stops.push(sender);
        receiver
    }};
}

macro_rules! next_setup_signal_v2 {
    (Local, $stream:ident, $stop:ident) => { $stream.next().await };
    (Retained, $stream:ident, $stop:ident) => {
        tokio::select! {
            _ = &mut $stop => None,
            signal = $stream.next() => signal,
        }
    };
}

macro_rules! dispose_setup_signal_v2 {
    (Local, $stream:ident) => {};
    (Retained, $stream:ident) => { zbus::AsyncDrop::async_drop($stream).await; };
}

macro_rules! setup_task_v2 {
    (Local, $state:ident, $tasks:ident, $task:expr) => { $tasks.push($task); };
    (Retained, $state:ident, $tasks:ident, $task:expr) => {{
        let task = $task;
        let Ok(mut original) = $state.disposition.lock() else { std::process::abort() };
        let index = original.spawned_tasks;
        if index == 2 { std::process::abort(); }
        original.spawned_tasks += 1;
        let result = Arc::clone(&original.task_results[index]);
        let tasks = Arc::clone(&original.tasks);
        drop(original);
        let Ok(mut tasks) = tasks.try_lock() else { std::process::abort() };
        tasks.push(crate::client::host_launch::HostSystemdTaskV2 { handle: Some(task), result });
    }};
}

macro_rules! systemd_setup_recipe {
    ($mode:ident, $state:ident, $conn:ident, $manager:ident) => {{
        let conn = $conn;
        let manager = $manager;

        // MUST come before constructing any signal stream below. API-bus peers
        // receive NO JobNew/JobRemoved/Reloading until they call Subscribe();
        // direct (private-socket) peers are subscribed implicitly. systemd
        // source: src/core/dbus-manager.c:1376-1410 (method_subscribe). Skip
        // this and the streams silently produce nothing — the JobRemoved
        // waiter then hangs/times out for the wrong reason, and tests can go
        // green for the wrong reason too.
        setup_slot!($mode, park, $state, conn, connection);
        setup_slot!($mode, park, $state, manager, manager);
        setup_slot!($mode, borrow, $state, manager, manager).subscribe().await?;

        let jobs = Arc::new(Mutex::new(JobRegistry::default()));
        let reloading = Arc::new(AtomicBool::new(false));
        let (event_tx, event_rx) = mpsc::unbounded_channel::<()>();

        setup_slot!($mode, park, $state, jobs, jobs);
        setup_slot!($mode, park, $state, reloading, reloading);
        setup_slot!($mode, park, $state, event_tx, event_tx);
        setup_slot!($mode, park, $state, event_rx, event_rx);

        // Build the streams AFTER Subscribe so we never miss an event for a
        // job submitted later in this process.
        let mut job_removed = setup_slot!($mode, borrow, $state, manager, manager).receive_job_removed().await?;
        setup_slot!($mode, park, $state, job_removed, job_removed);
        let mut reloading_stream = setup_slot!($mode, borrow, $state, manager, manager).receive_reloading().await?;
        setup_slot!($mode, park, $state, reloading_stream, reloading_stream);

        let jobs = setup_slot!($mode, take, $state, jobs, jobs);
        let reloading = setup_slot!($mode, take, $state, reloading, reloading);
        let event_tx = setup_slot!($mode, take, $state, event_tx, event_tx);
        let event_rx = setup_slot!($mode, take, $state, event_rx, event_rx);
        let mut job_removed = setup_slot!($mode, take, $state, job_removed, job_removed);
        let mut reloading_stream = setup_slot!($mode, take, $state, reloading_stream, reloading_stream);

        let mut tasks = Vec::with_capacity(2);

        // One task, double duty (see JobRegistry): route the result to any
        // waiter (or stash it in `completed`), AND tick the settle channel.
        let jobs_for_task = jobs.clone();
        let mut job_stop = setup_task_stop_v2!($mode, $state);
        setup_task_v2!($mode, $state, tasks, tokio::spawn(async move {
            while let Some(signal) = next_setup_signal_v2!($mode, job_removed, job_stop) {
                let Ok(args) = signal.args() else { continue };
                let path = args.job;
                let path_key = path.as_str().to_owned();
                let result = JobResult::from_systemd(&args.result);
                {
                    let mut reg = jobs_for_task.lock().unwrap();
                    if let Some(tx) = reg.waiters.remove(&path_key) {
                        // Fire-and-forget; if the awaiter dropped (caller timed
                        // out at a higher level), there's nothing to do.
                        let _ = tx.send(result);
                    } else {
                        reg.completed.insert(path_key, result);
                    }
                }
                let _ = event_tx.send(());
            }
            // Stream closed = bus connection died (e.g. we just restarted
            // dbus.service out from under our own connection). No more
            // JobRemoved will ever arrive, so flip `closed` and drop every
            // parked sender: each awaiting `await_job` then observes a closed
            // oneshot and returns `JobSenderDropped` instead of hanging
            // forever. Future `await_job` calls see `closed` and bail up front.
            {
                let mut reg = jobs_for_task.lock().unwrap();
                reg.closed = true;
                reg.waiters.clear();
            }
            dispose_setup_signal_v2!($mode, job_removed);
        }));

        let reloading_for_task = reloading.clone();
        let mut reload_stop = setup_task_stop_v2!($mode, $state);
        setup_task_v2!($mode, $state, tasks, tokio::spawn(async move {
            while let Some(signal) = next_setup_signal_v2!($mode, reloading_stream, reload_stop) {
                if let Ok(args) = signal.args() {
                    reloading_for_task.store(args.active, Ordering::SeqCst);
                }
            }
            dispose_setup_signal_v2!($mode, reloading_stream);
        }));

        Ok(SystemdClient {
            conn: setup_slot!($mode, take, $state, conn, connection),
            manager: setup_slot!($mode, take, $state, manager, manager),
            jobs,
            reloading,
            job_event_rx: AsyncMutex::new(event_rx),
            tasks,
            readonly_controller: false,
            #[cfg(target_os = "linux")]
            host_launch: setup_slot!($mode, native, $state),
        })
        }};
}

