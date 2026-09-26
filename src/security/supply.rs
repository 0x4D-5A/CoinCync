//! Supply-integrity security detail — the chain's **inflation** surface, the
//! deepest value invariant. Snapshot-based (constructed from the current
//! `total_supply` / `total_burned`, so it never borrows chain internals) and
//! read-only.
//!
//! The guard is chosen to be **sound with zero false-positive risk**, because a
//! consensus-critical guard that can misfire is itself a DoS:
//! - **Guard (consensus-critical):** `total_burned ≤ total_supply`. You cannot
//!   burn more value than was ever emitted; a violation is accounting
//!   corruption / inflation of the burn counter. Always true honestly → safe to
//!   halt on.
//! - **Scan (operational):** `total_supply > MAX_SUPPLY`. Flagged as a
//!   *warning*, not a halt — tail emission could legitimately approach the cap,
//!   and a false halt must never wedge the chain; the operator reviews it.

use crate::security::{SecurityDetail, SecurityReport, Severity};

/// Pure supply invariants (testable in isolation). Returns
/// `(consensus_violation, operational_warning)`.
#[allow(clippy::type_complexity)]
pub fn supply_violations(
    total_supply: u128,
    total_burned: u128,
) -> (Option<(&'static str, String)>, Option<(&'static str, String)>) {
    let consensus = if total_burned > total_supply {
        Some((
            "burned-exceeds-supply",
            format!(
                "total_burned {total_burned} exceeds total_supply {total_supply} — \
                 accounting corruption / burn inflation"
            ),
        ))
    } else {
        None
    };
    let operational = if total_supply > crate::constants::MAX_SUPPLY {
        Some((
            "supply-over-cap",
            format!(
                "total_supply {total_supply} exceeds MAX_SUPPLY {} — review emission",
                crate::constants::MAX_SUPPLY
            ),
        ))
    } else {
        None
    };
    (consensus, operational)
}

/// A [`SecurityDetail`] over the chain's monetary supply, built from a snapshot.
pub struct SupplySecurityDetail {
    total_supply: u128,
    total_burned: u128,
}

impl SupplySecurityDetail {
    pub fn new(total_supply: u128, total_burned: u128) -> Self {
        Self { total_supply, total_burned }
    }
}

impl SecurityDetail for SupplySecurityDetail {
    fn label(&self) -> &'static str {
        "supply"
    }

    fn sweep(&self) -> SecurityReport {
        let mut r = SecurityReport::clean();
        let (consensus, operational) = supply_violations(self.total_supply, self.total_burned);
        if let Some((code, msg)) = consensus {
            r.raise_consensus("supply", Severity::Critical, code, msg);
        }
        if let Some((code, msg)) = operational {
            r.raise_operational("supply", Severity::Warning, code, msg);
        }
        r
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn supply_invariant_burn_cannot_exceed_supply() {
        // Honest: burned <= supply → no consensus violation.
        let (c, _) = supply_violations(1_000, 400);
        assert!(c.is_none());
        // Corruption: burned > supply → consensus violation.
        let (c, _) = supply_violations(400, 1_000);
        assert!(c.is_some());
    }

    #[test]
    fn over_cap_is_operational_never_a_halt() {
        use crate::security::Disposition;
        let over = crate::constants::MAX_SUPPLY + 1;
        let report = SupplySecurityDetail::new(over, 0).sweep();
        // Visible, but only a warning — never a consensus halt (tail emission
        // could legitimately near the cap; a false halt must not wedge the chain).
        assert!(report.has_critical() == false);
        assert!(report.alerts.iter().any(|a| a.code == "supply-over-cap"));
        assert_ne!(report.disposition(), Disposition::Halt);
    }

    #[test]
    fn healthy_supply_is_clean() {
        assert!(SupplySecurityDetail::new(crate::constants::MAX_SUPPLY / 2, 100).sweep().is_clean());
    }
}
