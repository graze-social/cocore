//! Per-engine admission gate.
//!
//! The advisor has no per-provider single-flight gate and the serve loop
//! runs every inbound job on its own blocking thread, so two jobs routed to
//! one machine in quick succession both reach the engine. What happens next
//! depends on the backend and none of the outcomes are acceptable:
//!
//!   * vllm-mlx's `SimpleEngine` fails the second admission ~20 s later with
//!     a bare `writing HTTP request body` — and the provider then published a
//!     billable receipt for a job that never ran (issue #202);
//!   * mei queues the second request FIFO with no bound, so it sits until our
//!     300 s first-token budget kills it while the server is still working;
//!   * a truly concurrent server would run both and thrash memory on a Mac
//!     that was sized for one.
//!
//! [`Gated`] wraps any [`Engine`] with an explicit slot count: `capacity`
//! generations may run at once (1 for every backend we ship) and up to
//! `max_queued` more may wait, in order, for a slot. Anything beyond that is
//! refused immediately with [`EngineRejection::Busy`] — before a single byte
//! reaches the backend — which the advisor path turns into a no-receipt
//! completion. `capacity + max_queued` is what the provider advertises as
//! `model_capacity` on the Register frame so the advisor can stop routing to
//! a saturated machine in the first place.

use anyhow::Result;
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use crate::engines::{DeltaChannel, Engine, EngineRejection, GenerateRequest, GenerateResponse};

/// How long a queued request waits for a running slot before it is refused
/// anyway. Bounded so a wedged generation (which the health loop will
/// eventually restart) cannot pin a queued job forever; sized at the
/// first-token budget the transport itself uses.
pub const QUEUE_WAIT_TIMEOUT: Duration = Duration::from_secs(300);

#[derive(Debug, Default)]
struct Slots {
    running: u32,
    queued: u32,
}

/// Counting gate shared by every call on one engine.
#[derive(Debug)]
pub struct AdmissionGate {
    capacity: u32,
    max_queued: u32,
    slots: Mutex<Slots>,
    freed: Condvar,
}

impl AdmissionGate {
    pub fn new(capacity: u32, max_queued: u32) -> Self {
        Self {
            capacity: capacity.max(1),
            max_queued,
            slots: Mutex::new(Slots::default()),
            freed: Condvar::new(),
        }
    }

    /// Running + queued slots — what the advisor should treat as this
    /// engine's per-model in-flight ceiling.
    pub fn advertised_capacity(&self) -> u32 {
        self.capacity + self.max_queued
    }

    /// Currently running + queued.
    pub fn in_flight(&self) -> u32 {
        let s = self.slots.lock().unwrap_or_else(|p| p.into_inner());
        s.running + s.queued
    }

    /// Take a running slot, waiting in the queue if one is free there;
    /// refuse when the queue is also full or the wait exceeds
    /// [`QUEUE_WAIT_TIMEOUT`].
    pub fn acquire(&self, model: &str) -> Result<Permit<'_>, EngineRejection> {
        let mut s = self.slots.lock().unwrap_or_else(|p| p.into_inner());
        if s.running < self.capacity {
            s.running += 1;
            return Ok(Permit { gate: self });
        }
        if s.queued >= self.max_queued {
            return Err(EngineRejection::Busy {
                model: model.to_string(),
                in_flight: s.running + s.queued,
                capacity: self.advertised_capacity(),
            });
        }
        s.queued += 1;
        let deadline = Instant::now() + QUEUE_WAIT_TIMEOUT;
        loop {
            if s.running < self.capacity {
                s.queued -= 1;
                s.running += 1;
                return Ok(Permit { gate: self });
            }
            let now = Instant::now();
            if now >= deadline {
                s.queued -= 1;
                return Err(EngineRejection::Busy {
                    model: model.to_string(),
                    in_flight: s.running + s.queued,
                    capacity: self.advertised_capacity(),
                });
            }
            let (guard, _) = self
                .freed
                .wait_timeout(s, deadline - now)
                .unwrap_or_else(|p| p.into_inner());
            s = guard;
        }
    }

    fn release(&self) {
        let mut s = self.slots.lock().unwrap_or_else(|p| p.into_inner());
        s.running = s.running.saturating_sub(1);
        drop(s);
        self.freed.notify_one();
    }
}

/// A held running slot; released on drop (including on panic/unwind).
pub struct Permit<'a> {
    gate: &'a AdmissionGate,
}

impl Drop for Permit<'_> {
    fn drop(&mut self) {
        self.gate.release();
    }
}

/// An [`Engine`] whose generate calls pass through an [`AdmissionGate`].
/// Everything else (readiness, restart, attestation facts) is forwarded
/// untouched, so wrapping an engine never changes what the machine attests.
pub struct Gated {
    inner: Arc<dyn Engine>,
    gate: AdmissionGate,
}

impl Gated {
    pub fn new(inner: Arc<dyn Engine>, capacity: u32, max_queued: u32) -> Self {
        Self {
            inner,
            gate: AdmissionGate::new(capacity, max_queued),
        }
    }

    /// Single-flight backend with one waiting slot — the shape every
    /// out-of-process engine we ship has.
    pub fn single_flight(inner: Arc<dyn Engine>) -> Self {
        Self::new(inner, 1, 1)
    }

    pub fn gate(&self) -> &AdmissionGate {
        &self.gate
    }

    pub fn inner(&self) -> &Arc<dyn Engine> {
        &self.inner
    }
}

impl Engine for Gated {
    fn name(&self) -> &'static str {
        self.inner.name()
    }
    fn ready(&self) -> bool {
        self.inner.ready()
    }
    fn restart(&self) -> Result<()> {
        self.inner.restart()
    }
    fn terminate(&self) {
        self.inner.terminate()
    }
    fn generate_once(&self, request: &GenerateRequest) -> Result<GenerateResponse> {
        let _permit = self.gate.acquire(&request.model)?;
        self.inner.generate_once(request)
    }
    fn generate_stream(
        &self,
        request: &GenerateRequest,
        on_delta: &mut dyn FnMut(DeltaChannel, &str) -> Result<()>,
    ) -> Result<GenerateResponse> {
        let _permit = self.gate.acquire(&request.model)?;
        self.inner.generate_stream(request, on_delta)
    }
    fn in_process(&self) -> bool {
        self.inner.in_process()
    }
    fn metallib_hash(&self) -> Option<String> {
        self.inner.metallib_hash()
    }
    fn engine_lib_hash(&self) -> Option<String> {
        self.inner.engine_lib_hash()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engines::{rejection_of, Message};
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::mpsc;

    fn req() -> GenerateRequest {
        GenerateRequest {
            model: "m".into(),
            messages: vec![Message::text("user", "hi")],
            max_tokens: 4,
            temperature: None,
            top_p: None,
            guided_json: None,
            tools: None,
            tool_choice: None,
        }
    }

    /// An engine whose generation blocks until told to finish, and counts
    /// how many generations are running at once.
    struct Blocking {
        release: Mutex<Option<mpsc::Receiver<()>>>,
        started: mpsc::Sender<()>,
        concurrent: AtomicU32,
        peak: AtomicU32,
    }

    impl Engine for Blocking {
        fn name(&self) -> &'static str {
            "blocking"
        }
        fn ready(&self) -> bool {
            true
        }
        fn generate_once(&self, _r: &GenerateRequest) -> Result<GenerateResponse> {
            let n = self.concurrent.fetch_add(1, Ordering::SeqCst) + 1;
            self.peak.fetch_max(n, Ordering::SeqCst);
            let _ = self.started.send(());
            if let Some(rx) = self.release.lock().unwrap().as_ref() {
                let _ = rx.recv();
            }
            self.concurrent.fetch_sub(1, Ordering::SeqCst);
            Ok(GenerateResponse {
                text: "done".into(),
                tokens_in: 1,
                tokens_out: 1,
            })
        }
    }

    #[test]
    fn third_request_is_refused_immediately_while_two_are_held() {
        let (release_tx, release_rx) = mpsc::channel::<()>();
        let (started_tx, started_rx) = mpsc::channel::<()>();
        let engine = Arc::new(Gated::single_flight(Arc::new(Blocking {
            release: Mutex::new(Some(release_rx)),
            started: started_tx,
            concurrent: AtomicU32::new(0),
            peak: AtomicU32::new(0),
        })));

        // Job A takes the running slot.
        let a = {
            let e = engine.clone();
            std::thread::spawn(move || e.generate_once(&req()))
        };
        started_rx.recv().unwrap();
        // Job B queues behind it.
        let b = {
            let e = engine.clone();
            std::thread::spawn(move || e.generate_once(&req()))
        };
        // Give B time to land in the queue.
        let deadline = Instant::now() + Duration::from_secs(5);
        while engine.gate().in_flight() < 2 && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(engine.gate().in_flight(), 2);

        // Job C is refused at once, typed.
        let started = Instant::now();
        let c = engine.generate_once(&req());
        assert!(started.elapsed() < Duration::from_secs(2));
        let err = c.expect_err("third job must be refused");
        match rejection_of(&err) {
            Some(EngineRejection::Busy {
                in_flight,
                capacity,
                ..
            }) => {
                assert_eq!(*in_flight, 2);
                assert_eq!(*capacity, 2);
            }
            other => panic!("expected Busy, got {other:?}"),
        }

        // Release A, then B runs; both complete, never concurrently.
        release_tx.send(()).unwrap();
        a.join().unwrap().unwrap();
        started_rx.recv().unwrap();
        release_tx.send(()).unwrap();
        b.join().unwrap().unwrap();
        assert_eq!(engine.gate().in_flight(), 0);
    }

    #[test]
    fn slot_is_released_when_the_inner_engine_errors() {
        struct Failing;
        impl Engine for Failing {
            fn name(&self) -> &'static str {
                "failing"
            }
            fn ready(&self) -> bool {
                true
            }
            fn generate_once(&self, _r: &GenerateRequest) -> Result<GenerateResponse> {
                anyhow::bail!("engine exploded")
            }
        }
        let engine = Gated::single_flight(Arc::new(Failing));
        for _ in 0..5 {
            assert!(engine.generate_once(&req()).is_err());
            assert_eq!(engine.gate().in_flight(), 0);
        }
    }

    #[test]
    fn advertised_capacity_is_running_plus_queued() {
        assert_eq!(AdmissionGate::new(1, 1).advertised_capacity(), 2);
        assert_eq!(AdmissionGate::new(2, 0).advertised_capacity(), 2);
        // capacity is clamped to at least one running slot
        assert_eq!(AdmissionGate::new(0, 3).advertised_capacity(), 4);
    }

    #[test]
    fn busy_rejection_is_recoverable_from_anyhow_chain() {
        let err: anyhow::Error = EngineRejection::Busy {
            model: "m".into(),
            in_flight: 2,
            capacity: 2,
        }
        .into();
        let wrapped = err.context("generate_stream failed");
        assert_eq!(
            rejection_of(&wrapped).map(|r| r.code()),
            Some("engine-busy")
        );
        let plain = anyhow::anyhow!("engine returned HTTP 500");
        assert!(rejection_of(&plain).is_none());
    }
}
