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

/// Whether an alert may influence consensus. This is the load-bearing
/// distinction (Stage 2): mixing the two is how a security layer either lets
/// corruption through or becomes a DoS / consensus-divergence vector.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AlertClass {
    /// A broken invariant that MUST hold identically on every honest node.
    /// Its check is deterministic (no wall-clock, no node-local state) and
    /// cheap (O(1) on the hot path), so it is safe to HALT/reject on. A
    /// `Consensus` + `Critical` alert is a genuine halt condition.
    Consensus,
    /// A local operational heuristic (velocity, ratios, peer churn). May be
    /// non-deterministic and O(n); it is only ever logged/paged — NEVER halts
    /// the node, or a heuristic false-positive would wedge the chain.
    Operational,
}

/// One finding from a security detail.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Alert {
    /// The detail that raised it (e.g. `"shielded-pool"`, `"utxo-set"`).
    pub detail: &'static str,
    pub severity: Severity,
    /// Whether this alert may drive a consensus halt, or is operational-only.
    pub class: AlertClass,
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

    /// Raise a **consensus-critical** invariant alert (deterministic, cheap —
    /// safe to halt on when `Critical`).
    pub fn raise_consensus(&mut self, detail: &'static str, severity: Severity, code: &'static str, message: impl Into<String>) {
        self.alerts.push(Alert { detail, severity, class: AlertClass::Consensus, code, message: message.into() });
    }

    /// Raise an **operational** heuristic alert (log/page only — never halts).
    pub fn raise_operational(&mut self, detail: &'static str, severity: Severity, code: &'static str, message: impl Into<String>) {
        self.alerts.push(Alert { detail, severity, class: AlertClass::Operational, code, message: message.into() });
    }

    /// Fold another report's alerts in.
    pub fn merge(&mut self, other: SecurityReport) {
        self.alerts.extend(other.alerts);
    }

    /// Any critical alert of any class present (for paging/visibility).
    pub fn has_critical(&self) -> bool {
        self.alerts.iter().any(|a| a.severity == Severity::Critical)
    }

    /// A **consensus** halt condition: a `Critical` alert of class `Consensus`.
    /// This — not `has_critical` — is what a node acts on. An operational
    /// critical never halts.
    pub fn has_consensus_halt(&self) -> bool {
        self.alerts
            .iter()
            .any(|a| a.severity == Severity::Critical && a.class == AlertClass::Consensus)
    }

    /// The critical alerts of any class, if any.
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

    /// Sweep and return `Err(report)` iff a **consensus** halt condition is
    /// present (a `Critical` + `Consensus` alert). This is the fail-closed entry
    /// point a node wires into block-apply to halt on corruption. Operational
    /// alerts — even `Critical` ones — never trip this; they are for paging.
    pub fn assert_consensus_safe(
        details: &[&dyn SecurityDetail],
    ) -> Result<SecurityReport, SecurityReport> {
        let report = Self::sweep_all(details);
        if report.has_consensus_halt() {
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
        consensus_critical: bool,
        operational_critical: bool,
        warnings: usize,
    }
    impl SecurityDetail for MockDetail {
        fn label(&self) -> &'static str {
            self.label
        }
        fn sweep(&self) -> SecurityReport {
            let mut r = SecurityReport::clean();
            if self.consensus_critical {
                r.raise_consensus(self.label, Severity::Critical, "mock-crit", "invariant broken");
            }
            if self.operational_critical {
                r.raise_operational(self.label, Severity::Critical, "mock-op-crit", "severe anomaly");
            }
            for _ in 0..self.warnings {
                r.raise_operational(self.label, Severity::Warning, "mock-warn", "anomaly");
            }
            r
        }
    }

    #[test]
    fn command_aggregates_details_and_halts_only_on_consensus_critical() {
        let clean = MockDetail { label: "a", consensus_critical: false, operational_critical: false, warnings: 1 };
        let broken = MockDetail { label: "b", consensus_critical: true, operational_critical: false, warnings: 2 };
        let details: [&dyn SecurityDetail; 2] = [&clean, &broken];

        let report = SecurityCommand::sweep_all(&details);
        assert_eq!(report.alerts.len(), 1 + 1 + 2, "all alerts aggregated");
        assert!(report.has_critical());
        assert!(report.has_consensus_halt());
        assert_eq!(report.count_at_least(Severity::Warning), 4);

        // A consensus-critical trips the halt.
        assert!(SecurityCommand::assert_consensus_safe(&details).is_err());
    }

    #[test]
    fn operational_critical_pages_but_never_halts() {
        // The load-bearing Stage-2 property: an operational heuristic firing at
        // Critical severity is visible (has_critical) but must NOT halt the node
        // — otherwise a false-positive heuristic wedges the chain.
        let noisy = MockDetail { label: "a", consensus_critical: false, operational_critical: true, warnings: 3 };
        let details: [&dyn SecurityDetail; 1] = [&noisy];
        let report = SecurityCommand::assert_consensus_safe(&details).expect("operational critical does not halt");
        assert!(report.has_critical(), "still visible for paging");
        assert!(!report.has_consensus_halt(), "but never a consensus halt");
    }

    #[test]
    fn all_clean_details_pass() {
        let a = MockDetail { label: "a", consensus_critical: false, operational_critical: false, warnings: 0 };
        let b = MockDetail { label: "b", consensus_critical: false, operational_critical: false, warnings: 0 };
        let details: [&dyn SecurityDetail; 2] = [&a, &b];
        let ok = SecurityCommand::assert_consensus_safe(&details).expect("no consensus halt");
        assert!(ok.is_clean());
    }

    #[test]
    fn severity_orders_and_displays() {
        assert!(Severity::Critical > Severity::Warning);
        assert!(Severity::Warning > Severity::Info);
        assert_eq!(Severity::Critical.to_string(), "CRITICAL");
    }
}
