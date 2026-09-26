//! # Security details — a chain-wide protection pattern
//!
//! The "Secret Service" pattern, generalized. Every subsystem with an attack
//! surface — the shielded pool, the UTXO set, the mempool, the peer set, the
//! Phase-2 accumulator stores — shares the same shape of defense:
//!
//! - **Guards**: fail-closed invariants that an honest node must never break.
//!   A violation is a *critical* alert — evidence of corruption or an attack.
//! - **Scan**: surveillance that surfaces *soft* anomalies (velocity, ratios,
//!   saturation). Worth a look; not, alone, proof of a fault.
//!
//! A [`SecurityDetail`] implements that shape for one subsystem; the
//! [`SecurityCommand`] runs many details and aggregates their [`Alert`]s into
//! one [`SecurityReport`]. This is **read-only, reporting-only** infrastructure:
//! a detail observes and raises alerts; it never mutates consensus state. A
//! caller decides what a critical alert means (log, page, or halt).
//!
//! The framework itself is dependency-free and always compiled; individual
//! details live with their subsystems (e.g. the shielded pool's detail is gated
//! with the pool).

use std::fmt;

/// How serious an alert is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    /// Informational — a normal observation.
    Info,
    /// A soft anomaly — worth investigating, not proof of a fault.
    Warning,
    /// A broken invariant — an honest node should never reach this state.
    Critical,
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Severity::Info => write!(f, "INFO"),
            Severity::Warning => write!(f, "WARN"),
            Severity::Critical => write!(f, "CRITICAL"),
        }
    }
}

/// One finding from a security detail.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Alert {
    /// The detail that raised it (e.g. `"shielded-pool"`, `"utxo-set"`).
    pub detail: &'static str,
    pub severity: Severity,
    /// A short stable code for the invariant/anomaly (e.g. `"coin-from-future"`).
    pub code: &'static str,
    /// Human-readable specifics.
    pub message: String,
}

/// The aggregated findings of one or more details' sweeps.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SecurityReport {
    pub alerts: Vec<Alert>,
}

impl SecurityReport {
    /// An empty (clean) report.
    pub fn clean() -> Self {
        Self { alerts: Vec::new() }
    }

    /// Raise an alert.
    pub fn raise(&mut self, detail: &'static str, severity: Severity, code: &'static str, message: impl Into<String>) {
        self.alerts.push(Alert { detail, severity, code, message: message.into() });
    }

    /// Fold another report's alerts in.
    pub fn merge(&mut self, other: SecurityReport) {
        self.alerts.extend(other.alerts);
    }

    /// Any critical alert present? A hard-guarantee caller treats this as a halt
    /// condition.
    pub fn has_critical(&self) -> bool {
        self.alerts.iter().any(|a| a.severity == Severity::Critical)
    }

    /// The critical alerts, if any.
    pub fn criticals(&self) -> impl Iterator<Item = &Alert> {
        self.alerts.iter().filter(|a| a.severity == Severity::Critical)
    }

    /// True iff nothing at all was raised.
    pub fn is_clean(&self) -> bool {
        self.alerts.is_empty()
    }

    /// Count of alerts at or above a severity.
    pub fn count_at_least(&self, severity: Severity) -> usize {
        self.alerts.iter().filter(|a| a.severity >= severity).count()
    }
}

/// A protection detail for one subsystem. Holds its own read-only view of the
/// subsystem (a borrow of its store + any context) and reports on a sweep.
pub trait SecurityDetail {
    /// Stable label for this detail (used as the alert's `detail`).
    fn label(&self) -> &'static str;

    /// Observe the subsystem and raise any guard violations (critical) and scan
    /// anomalies (warning). Never mutates state.
    fn sweep(&self) -> SecurityReport;
}

/// The coordinator — "HQ". Runs a set of details and aggregates their reports.
pub struct SecurityCommand;

impl SecurityCommand {
    /// Sweep every detail and merge the findings into one report. The order of
    /// `details` is preserved in the merged alerts.
    pub fn sweep_all(details: &[&dyn SecurityDetail]) -> SecurityReport {
        let mut report = SecurityReport::clean();
        for d in details {
            report.merge(d.sweep());
        }
        report
    }

    /// Sweep and return `Err(report)` iff any detail raised a critical alert —
    /// the fail-closed entry point a caller uses to halt on corruption.
    pub fn assert_secure(details: &[&dyn SecurityDetail]) -> Result<SecurityReport, SecurityReport> {
        let report = Self::sweep_all(details);
        if report.has_critical() {
            Err(report)
        } else {
            Ok(report)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockDetail {
        label: &'static str,
        critical: bool,
        warnings: usize,
    }
    impl SecurityDetail for MockDetail {
        fn label(&self) -> &'static str {
            self.label
        }
        fn sweep(&self) -> SecurityReport {
            let mut r = SecurityReport::clean();
            if self.critical {
                r.raise(self.label, Severity::Critical, "mock-crit", "invariant broken");
            }
            for _ in 0..self.warnings {
                r.raise(self.label, Severity::Warning, "mock-warn", "anomaly");
            }
            r
        }
    }

    #[test]
    fn command_aggregates_details_and_flags_critical() {
        let clean = MockDetail { label: "a", critical: false, warnings: 1 };
        let broken = MockDetail { label: "b", critical: true, warnings: 2 };
        let details: [&dyn SecurityDetail; 2] = [&clean, &broken];

        let report = SecurityCommand::sweep_all(&details);
        assert_eq!(report.alerts.len(), 1 + 1 + 2, "all alerts aggregated");
        assert!(report.has_critical());
        assert_eq!(report.criticals().count(), 1);
        assert_eq!(report.count_at_least(Severity::Warning), 4);

        // assert_secure returns Err on a critical.
        assert!(SecurityCommand::assert_secure(&details).is_err());
    }

    #[test]
    fn all_clean_details_pass() {
        let a = MockDetail { label: "a", critical: false, warnings: 0 };
        let b = MockDetail { label: "b", critical: false, warnings: 0 };
        let details: [&dyn SecurityDetail; 2] = [&a, &b];
        let ok = SecurityCommand::assert_secure(&details).expect("no criticals");
        assert!(ok.is_clean());
    }

    #[test]
    fn severity_orders_and_displays() {
        assert!(Severity::Critical > Severity::Warning);
        assert!(Severity::Warning > Severity::Info);
        assert_eq!(Severity::Critical.to_string(), "CRITICAL");
    }
}
