//! The token-dedicated worker pool shared by the parallel scan and the
//! bulk reverse lookup: one runner instead of two hand-rolled `thread::scope`
//! spawn loops (the same live-token assignment, spawn-failure degradation
//! and exactly-one-report-per-worker collection for both callers).

use crate::github::TokenPool;
use std::sync::atomic::AtomicBool;
use std::sync::mpsc;
use std::sync::{Arc, Mutex};

/// How many workers scan the work items: one per available token, capped by
/// the number of items; an anonymous pool (no token) runs a single worker on
/// the shared anonymous quota.
pub(crate) fn worker_count(tokens: usize, items: usize) -> usize {
    tokens.max(1).min(items)
}

/// Spawns the token-dedicated worker pool over `work` and collects exactly
/// one report per worker.
///
/// Each worker is dedicated the next *live* token when any token is live
/// (see [`TokenPool::live_indices`]): a token the pool retired or parked
/// must not own a worker slot while healthy tokens sit beyond the worker
/// range — with fewer work items than tokens, every spawned worker could
/// otherwise own a dead token and abort the whole run without a single
/// request. When every token is dead (or the pool is anonymous) the
/// positional assignment is kept: the all-dead fallback still spawns the
/// documented worker count so the reduction fails loudly instead of
/// silently reporting an empty run, and the anonymous pool (no tokens at
/// all) keeps its single shared-quota worker.
///
/// A dedicated token the pool retired or parked never spawns a worker
/// doomed to a dead first request: the worker is told it starts dead
/// (`true` as the `start_dead` argument of `job`) so it can report the
/// death without pulling (and doomed-losing) a work item from the queue.
///
/// The OS refusing a thread creation must degrade to a reported failure,
/// not panic out of the crate's never-panic contract: the failing worker's
/// slot sends `failure_report(cause)` instead, so the reduction still
/// receives exactly one report per worker.
///
/// * `work` — the queued items; every item is sent once, then the sender is
///   dropped, so `recv` returns `None` once the queue is drained (the
///   workers' natural stop signal).
/// * `job` — the worker body: pulls work from the shared queue until it is
///   drained or another worker failed (via the `aborted` flag). The queue
///   is fully populated upfront, so `recv` never blocks long.
pub(crate) fn run_token_worker_pool<I, R>(
    tokens: &TokenPool,
    work: impl IntoIterator<Item = I>,
    // `failure_report` is only invoked from the spawning thread (the spawn
    // refusal branch and the never-reports fallback), so it carries no
    // cross-thread bound
    failure_report: impl Fn(&str) -> R,
    job: impl Fn(&Mutex<mpsc::Receiver<I>>, &AtomicBool, Option<&str>, bool) -> R + Sync,
) -> Vec<R>
where
    I: Send,
    R: Send,
{
    let items = work.into_iter().collect::<Vec<_>>();
    let live = tokens.live_indices();
    let workers = worker_count(
        if live.is_empty() {
            tokens.len()
        } else {
            live.len()
        },
        items.len(),
    );

    // work queue: every item is sent once, then the sender is dropped, so
    // `recv` returns `Err` once the queue is drained — the workers'
    // natural stop signal
    let (work_tx, work_rx) = mpsc::channel::<I>();
    for item in items {
        // the receiver lives in this same function, so the send cannot fail
        let _ = work_tx.send(item);
    }
    drop(work_tx);
    let work_rx = Arc::new(Mutex::new(work_rx));

    let (result_tx, result_rx) = mpsc::channel::<R>();
    // set as soon as a worker fails, so the others stop pulling work
    let aborted = AtomicBool::new(false);

    std::thread::scope(|scope| {
        // the shared state and the worker body are shared by reference
        // (`&J` is `Send` exactly when `J: Sync`): every thread calls the
        // same closure with its own arguments
        let job = &job;
        let work_rx = &work_rx;
        let aborted = &aborted;
        for worker in 0..workers {
            // the `worker`-th live token when any token is live; the
            // positional token otherwise (the all-dead fallback keeps the
            // loud all-workers-dead reduction). `None` is the anonymous
            // quota (no tokens at all)
            let assigned = live.get(worker).copied().unwrap_or(worker);
            let dedicated_token = tokens.dedicated_token(assigned);
            // a dedicated token the pool already retired or parked never
            // spawns a worker doomed to a dead first request: the worker
            // reports the death without pulling (and doomed-losing) a work
            // item from the queue. An anonymous quota the pool retired or
            // parked is guarded the same way (its worker owns no dedicated
            // token, so it must consult the shared anonymous index)
            let start_dead = match dedicated_token {
                Some(_) => tokens.is_exhausted(assigned),
                None => tokens.is_exhausted(crate::github::client::ANONYMOUS_INDEX),
            };
            let worker_tx = result_tx.clone();
            // `Builder::spawn_scoped` instead of `scope.spawn`: the OS
            // refusing the thread creation must degrade to a reported
            // failure, not panic out of the documented never-panic contract
            match std::thread::Builder::new().spawn_scoped(scope, move || {
                let report = job(work_rx, aborted, dedicated_token, start_dead);
                let _ = worker_tx.send(report);
            }) {
                Ok(_handle) => {}
                Err(_) => {
                    // no thread for this worker: report the prepared
                    // failure, so the reduction still receives exactly one
                    // report per worker instead of hanging on a missing one
                    let _ = result_tx.send(failure_report("the OS refused to spawn a worker"));
                }
            }
        }
    });
    drop(result_tx); // the scope joined every worker: no more reports

    // every worker sent exactly one report
    (0..workers)
        .map(|_| {
            result_rx
                .recv()
                .unwrap_or_else(|_| failure_report("a worker did not report"))
        })
        .collect()
}
