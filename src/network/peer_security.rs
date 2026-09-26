//! Peer-set security detail — the P2P **eclipse / partition / isolation**
//! surface. The peer set is node-LOCAL (not consensus), so every alert is
//! **operational** (page, never halt): being under-connected is a risk to
//! *this* node's view, not a chain-wide invariant. Read-only, O(1).

use crate::security::{SecurityDetail, SecurityReport, Severity};

/// Pure peer-health signal (testable in isolation): too few peers is an
/// eclipse/partition risk. Zero peers is the sharpest signal (fully isolated —
/// this node sees no network); below the healthy minimum is a softer warning.
pub fn peer_health(count: usize, min_healthy: usize) -> Option<(Severity, &'static str, String)> {
    if count == 0 {
        Some((
            Severity::Critical,
            "no-peers",
            "0 connected peers — this node is isolated (eclipse/partition risk)".to_string(),
        ))
    } else if count < min_healthy {
        Some((
            Severity::Warning,
            "low-peers",
            format!("{count} connected peers < healthy minimum {min_healthy} — eclipse risk"),
        ))
    } else {
        None
    }
}

/// A [`SecurityDetail`] over the connected peer set. Constructed from a
/// point-in-time peer count (so it never borrows the live P2P node), it flags
/// under-connection. All alerts operational.
pub struct PeerSecurityDetail {
    peer_count: usize,
    min_healthy: usize,
}

impl PeerSecurityDetail {
    /// Healthy-minimum default: matches the rig's ≥3-peer mesh gate — below a
    /// small mesh, an adversary controlling the few peers can eclipse the node.
    pub const DEFAULT_MIN_HEALTHY: usize = 3;

    pub fn new(peer_count: usize) -> Self {
        Self { peer_count, min_healthy: Self::DEFAULT_MIN_HEALTHY }
    }

    pub fn with_min_healthy(peer_count: usize, min_healthy: usize) -> Self {
        Self { peer_count, min_healthy }
    }
}

impl SecurityDetail for PeerSecurityDetail {
    fn label(&self) -> &'static str {
        "peer-set"
    }

    fn sweep(&self) -> SecurityReport {
        let mut r = SecurityReport::clean();
        if let Some((sev, code, msg)) = peer_health(self.peer_count, self.min_healthy) {
            // Operational only — an under-connected node must page its operator,
            // never halt the chain.
            r.raise_operational("peer-set", sev, code, msg);
        }
        r
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn peer_health_pure_signal() {
        assert!(matches!(peer_health(0, 3), Some((Severity::Critical, "no-peers", _))));
        assert!(matches!(peer_health(2, 3), Some((Severity::Warning, "low-peers", _))));
        assert!(peer_health(3, 3).is_none(), "at the minimum is healthy");
        assert!(peer_health(50, 3).is_none());
    }

    #[test]
    fn peer_detail_is_operational_never_consensus() {
        // Even full isolation (0 peers, a Critical) must not be a consensus halt.
        let report = PeerSecurityDetail::new(0).sweep();
        assert!(report.has_critical(), "isolation is visible");
        assert!(!report.has_consensus_halt(), "but P2P alerts never halt consensus");
        // A well-connected node is clean.
        assert!(PeerSecurityDetail::new(8).sweep().is_clean());
    }
}
