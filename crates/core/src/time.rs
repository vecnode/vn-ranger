//! Time arithmetic without a date library.
//!
//! "Now" is always a parameter. The core never calls the clock.

/// Describe how long ago a timestamp was, in the words an interface can show.
#[must_use]
pub fn describe_age(now: u64, then: u64) -> String {
    if then == 0 {
        return "unknown".to_owned();
    }
    if now <= then {
        return "just now".to_owned();
    }
    let seconds = now - then;
    if seconds < 60 {
        return plural(seconds, "second");
    }
    let minutes = seconds / 60;
    if minutes < 60 {
        return plural(minutes, "minute");
    }
    let hours = minutes / 60;
    if hours < 24 {
        return plural(hours, "hour");
    }
    let days = hours / 24;
    if days < 30 {
        return plural(days, "day");
    }
    let months = days / 30;
    if months < 12 {
        return plural(months, "month");
    }
    plural(days / 365, "year")
}

fn plural(count: u64, unit: &str) -> String {
    if count == 1 {
        format!("1 {unit} ago")
    } else {
        format!("{count} {unit}s ago")
    }
}

/// Format a Unix timestamp as `YYYY-MM-DD HH:MM UTC`.
#[must_use]
pub fn format_utc(unix: u64) -> String {
    let days = (unix / 86_400) as i64;
    let seconds = unix % 86_400;
    let (year, month, day) = civil_from_days(days);
    format!(
        "{year:04}-{month:02}-{day:02} {:02}:{:02} UTC",
        seconds / 3_600,
        (seconds % 3_600) / 60
    )
}

/// Howard Hinnant's `civil_from_days`, which is exact for the proleptic Gregorian
/// calendar and needs no table.
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if month <= 2 { year + 1 } else { year };
    (year, month as u32, day as u32)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ages_read_naturally() {
        assert_eq!(describe_age(1_000, 0), "unknown");
        assert_eq!(describe_age(1_000, 1_000), "just now");
        assert_eq!(describe_age(1_001, 1_000), "1 second ago");
        assert_eq!(describe_age(1_120, 1_000), "2 minutes ago");
        assert_eq!(describe_age(7_300, 1_000), "1 hour ago");
        assert_eq!(describe_age(90_000, 1_000), "1 day ago");
        assert_eq!(describe_age(2_700_000, 1_000), "1 month ago");
        assert_eq!(describe_age(40_000_000, 1_000), "1 year ago");
    }

    #[test]
    fn utc_format_is_stable() {
        assert_eq!(format_utc(0), "1970-01-01 00:00 UTC");
        assert_eq!(format_utc(1_000_000_000), "2001-09-09 01:46 UTC");
        assert_eq!(format_utc(1_767_225_600), "2026-01-01 00:00 UTC");
    }
}
