//! Whether this machine is running on its battery.
//!
//! The plan asks for one behaviour: a scheduled full inventory may wait while the machine
//! is on battery, if the person asked for that (`docs/PLAN.md` §6.5). It is off by default,
//! because a ranger that silently stops noticing things on a laptop is a ranger that lies
//! by omission.
//!
//! Linux answers from sysfs, which is a file; macOS would need `pmset`, and Windows needs a
//! struct from `GetSystemPowerStatus` that no safe wrapper here provides. Both report
//! `Unknown` with the reason, and the interface says so rather than pretending the machine
//! is plugged in.

/// What the machine is running on, as far as this process can tell.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Power {
    /// A battery is discharging, so this is a machine that could be saving power.
    Battery,
    /// Mains power, or a battery that is full.
    Mains,
    /// This platform cannot say, and this is why.
    Unknown(String),
}

impl Power {
    /// Whether the scheduled scan should wait, if the person asked it to.
    #[must_use]
    pub fn is_battery(&self) -> bool {
        matches!(self, Self::Battery)
    }
}

/// Ask the machine.
#[must_use]
pub fn source() -> Power {
    platform::source()
}

/// The sysfs status strings, and what each means for a scheduled scan.
///
/// `Full` is mains: a full battery is a machine that is about to be plugged in or already
/// is, and postponing a scan for it would be a guess. Anything else — `Unknown` included —
/// is `Mains` rather than `Battery`, because the only cost of a wrong `Mains` is a scan
/// that runs, and the cost of a wrong `Battery` is a scan that never does.
#[must_use]
pub fn from_status(status: &str) -> Power {
    match status.trim() {
        "Discharging" => Power::Battery,
        _ => Power::Mains,
    }
}

#[cfg(target_os = "linux")]
mod platform {
    use super::{Power, from_status};

    pub(super) fn source() -> Power {
        let Ok(entries) = std::fs::read_dir("/sys/class/power_supply") else {
            return Power::Unknown("this machine has no /sys/class/power_supply".to_owned());
        };
        for entry in entries.flatten() {
            if !entry.file_name().to_string_lossy().starts_with("BAT") {
                continue;
            }
            if let Ok(status) = std::fs::read_to_string(entry.path().join("status")) {
                return from_status(&status);
            }
        }
        Power::Unknown("no battery is visible in /sys/class/power_supply".to_owned())
    }
}

/// macOS would shell out to `pmset`, and Windows needs a call from inside a safe wrapper;
/// neither exists here, so the answer is "cannot tell" rather than a guess.
#[cfg(not(target_os = "linux"))]
mod platform {
    use super::Power;

    pub(super) fn source() -> Power {
        Power::Unknown(
            "this platform's power source is not readable without a native call ranger does \
             not make"
                .to_owned(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_discharging_battery_is_the_only_battery() {
        assert_eq!(from_status("Discharging\n"), Power::Battery);
        assert!(from_status("Discharging").is_battery());
    }

    #[test]
    fn everything_else_is_mains_because_a_wrong_mains_only_costs_a_scan() {
        for status in ["Charging", "Full", "Not charging", "Unknown", "", "  "] {
            assert_eq!(
                from_status(status),
                Power::Mains,
                "{status:?} must not postpone a scan"
            );
        }
    }

    #[test]
    fn an_unknown_platform_is_not_a_battery() {
        let power = source();
        // Whatever this host says, the rule holds: only Battery postpones.
        assert_eq!(power.is_battery(), matches!(power, Power::Battery));
        if let Power::Unknown(reason) = &power {
            assert!(!reason.is_empty(), "cannot-tell says why");
        }
    }
}
