//! Optional daily serve window for the agent.
//!
//! When `COCORE_SERVE_START` and `COCORE_SERVE_END` (hours 0–23, local
//! time) are both set and differ, the agent only connects to the
//! advisor during `[start, end)` and disconnects + frees its inference
//! engines outside it. Absent or invalid → serve continuously (the
//! historical behavior).
//!
//! Hour granularity matches the menu-bar app's Schedule UI, which is the
//! only writer of these env vars (via the LaunchAgent plist). Keeping it
//! coarse sidesteps DST/leap-second edge cases — a serve window is a
//! "don't compete with my daytime use" knob, not a billing boundary.

use chrono::{Local, Timelike};
use std::collections::HashMap;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ServeWindow {
    /// Inclusive start hour, 0–23 (local time).
    pub start: u8,
    /// Exclusive end hour, 0–23 (local time).
    pub end: u8,
}

impl ServeWindow {
    /// Read the window from `COCORE_SERVE_START` / `COCORE_SERVE_END`.
    /// Returns `None` (serve continuously) when either is unset or the
    /// pair is invalid (out of range, or start == end).
    pub fn from_env() -> Option<ServeWindow> {
        let start = parse_hour(&std::env::var("COCORE_SERVE_START").ok()?)?;
        let end = parse_hour(&std::env::var("COCORE_SERVE_END").ok()?)?;
        ServeWindow::new(start, end)
    }

    pub fn new(start: u8, end: u8) -> Option<ServeWindow> {
        if start > 23 || end > 23 || start == end {
            return None;
        }
        Some(ServeWindow { start, end })
    }

    /// Is `hour` (0–23) inside the window? Handles a window that wraps
    /// past midnight (e.g. 22→8).
    pub fn contains(&self, hour: u8) -> bool {
        if self.start < self.end {
            hour >= self.start && hour < self.end
        } else {
            hour >= self.start || hour < self.end
        }
    }

    /// Whether the window is open right now (local time).
    pub fn contains_now(&self) -> bool {
        self.contains(local_hour())
    }

    /// Seconds from now until the window next closes. Meaningful while
    /// inside the window.
    pub fn seconds_until_close(&self) -> u64 {
        seconds_until_hour(self.end)
    }

    /// Seconds from now until the window next opens. Meaningful while
    /// outside the window.
    pub fn seconds_until_open(&self) -> u64 {
        seconds_until_hour(self.start)
    }
}

/// Per-model serve windows, parsed from `COCORE_MODEL_SCHEDULES` — a JSON
/// object mapping model id → `{"start": h, "end": h}` (hours 0–23, local
/// time, end exclusive, wrap supported). A model NOT present is "always
/// on" (subject only to the whole-agent [`ServeWindow`]). Written by the
/// menu-bar app's per-model Schedule UI. A malformed/out-of-range entry is
/// dropped (that model stays always-on) — a bad schedule must never brick
/// serving.
#[derive(Clone, Debug, Default)]
pub struct ModelSchedules {
    windows: HashMap<String, ServeWindow>,
}

impl ModelSchedules {
    pub fn from_env() -> ModelSchedules {
        match std::env::var("COCORE_MODEL_SCHEDULES") {
            Ok(raw) => Self::parse(&raw),
            Err(_) => ModelSchedules::default(),
        }
    }

    pub fn parse(raw: &str) -> ModelSchedules {
        let Ok(obj) = serde_json::from_str::<HashMap<String, serde_json::Value>>(raw) else {
            return ModelSchedules::default();
        };
        let mut windows = HashMap::new();
        for (model, v) in obj {
            let start = v.get("start").and_then(serde_json::Value::as_u64);
            let end = v.get("end").and_then(serde_json::Value::as_u64);
            if let (Some(s), Some(e)) = (start, end) {
                if let (Ok(s), Ok(e)) = (u8::try_from(s), u8::try_from(e)) {
                    if let Some(w) = ServeWindow::new(s, e) {
                        windows.insert(model, w);
                    }
                }
            }
        }
        ModelSchedules { windows }
    }

    pub fn is_empty(&self) -> bool {
        self.windows.is_empty()
    }

    /// The subset of `models` that should be loaded right now (local time):
    /// a model with no per-model window is always active; a scheduled one
    /// is active only while its window is open. Input order preserved.
    pub fn active_now(&self, models: &[String]) -> Vec<String> {
        self.active_at(local_hour(), models)
    }

    /// Active subset at a specific `hour` (0–23). Split out from
    /// [`active_now`] so it's unit-testable without mocking the clock.
    pub fn active_at(&self, hour: u8, models: &[String]) -> Vec<String> {
        models
            .iter()
            .filter(|m| self.windows.get(*m).is_none_or(|w| w.contains(hour)))
            .cloned()
            .collect()
    }
}

fn parse_hour(s: &str) -> Option<u8> {
    match s.trim().parse::<u8>() {
        Ok(h) if h <= 23 => Some(h),
        _ => None,
    }
}

/// Current local hour, 0–23.
pub fn local_hour() -> u8 {
    Local::now().hour() as u8
}

/// Seconds from now until the next local `hour:00:00`. Always in
/// `(0, 86400]` so callers never busy-loop on a zero sleep.
fn seconds_until_hour(hour: u8) -> u64 {
    let now = Local::now();
    let secs_into_day = now.hour() as i64 * 3600 + now.minute() as i64 * 60 + now.second() as i64;
    let target = hour as i64 * 3600;
    let mut delta = target - secs_into_day;
    if delta <= 0 {
        delta += 24 * 3600;
    }
    delta as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_invalid_windows() {
        assert!(ServeWindow::new(8, 8).is_none()); // empty
        assert!(ServeWindow::new(24, 8).is_none()); // out of range
        assert!(ServeWindow::new(0, 25).is_none());
        assert!(ServeWindow::new(0, 24).is_none());
    }

    #[test]
    fn daytime_window_no_wrap() {
        let w = ServeWindow::new(9, 17).unwrap();
        assert!(!w.contains(8));
        assert!(w.contains(9));
        assert!(w.contains(16));
        assert!(!w.contains(17)); // end is exclusive
        assert!(!w.contains(23));
    }

    #[test]
    fn overnight_window_wraps_midnight() {
        let w = ServeWindow::new(22, 8).unwrap(); // 10pm → 8am
        assert!(w.contains(22));
        assert!(w.contains(23));
        assert!(w.contains(0));
        assert!(w.contains(7));
        assert!(!w.contains(8)); // exclusive
        assert!(!w.contains(12));
        assert!(!w.contains(21));
    }

    #[test]
    fn parse_hour_bounds() {
        assert_eq!(parse_hour(" 0 "), Some(0));
        assert_eq!(parse_hour("23"), Some(23));
        assert_eq!(parse_hour("24"), None);
        assert_eq!(parse_hour(""), None);
        assert_eq!(parse_hour("x"), None);
    }

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
    }

    #[test]
    fn model_schedules_active_by_hour() {
        let sched = ModelSchedules::parse(r#"{"A":{"start":9,"end":17},"B":{"start":22,"end":8}}"#);
        let models = s(&["A", "B", "C"]); // C has no schedule → always on
        assert_eq!(sched.active_at(12, &models), s(&["A", "C"])); // A daytime open, B closed
        assert_eq!(sched.active_at(23, &models), s(&["B", "C"])); // B overnight open, A closed
        assert_eq!(sched.active_at(8, &models), s(&["C"])); // both closed (8 is exclusive end of B, before A)
    }

    #[test]
    fn model_schedules_malformed_keeps_models_always_on() {
        assert!(ModelSchedules::parse("not json").is_empty());
        // out-of-range start + empty window → both dropped, models stay always-on.
        let sched = ModelSchedules::parse(r#"{"A":{"start":25,"end":2},"B":{"start":5,"end":5}}"#);
        assert!(sched.is_empty());
        assert_eq!(sched.active_at(3, &s(&["A", "B"])), s(&["A", "B"]));
    }
}
