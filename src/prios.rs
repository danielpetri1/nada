use sfv::{Dictionary, FieldType, ListEntry};
use tokio_quiche::quiche::h3;

const DEFAULT_URGENCY: u8 = 3;
// RFC default for received fields. Nada clients explicitly send u=3,i by default.
const DEFAULT_INCREMENTAL: bool = false;
const MIN_URGENCY: i64 = 0;
const MAX_URGENCY: i64 = 7;

/// Parses a `Vec<u8>`, returning a quiche `Priority`.
pub fn parse_raw_priority(raw_prio: Option<Vec<u8>>) -> Option<h3::Priority> {
    let mut urgency = DEFAULT_URGENCY;
    let mut incremental = DEFAULT_INCREMENTAL;

    let prio_bytes = raw_prio.unwrap_or_default();
    let parsed_prio = sfv::Parser::new(&prio_bytes);

    if let Ok(dict) = Dictionary::parse(parsed_prio) {
        urgency = dict
            .get("u")
            .and_then(|prio| match prio {
                ListEntry::Item(item) => item.bare_item.as_integer(),
                _ => None,
            })
            .map(i64::from)
            // RFC 9218 §4 requires ignoring out-of-range parameters.
            .filter(|u| (MIN_URGENCY..=MAX_URGENCY).contains(u))
            .map(|u| u as u8)
            .unwrap_or(DEFAULT_URGENCY);

        incremental = match dict.get("i") {
            Some(ListEntry::Item(item)) => item.bare_item.as_boolean().unwrap_or(false),
            _ => false,
        };
    }

    Some(h3::Priority::new(urgency, incremental))
}

#[cfg(test)]
mod eps {
    use super::*;

    fn bytes(s: &str) -> Option<Vec<u8>> {
        Some(s.as_bytes().to_vec())
    }

    #[test]
    fn returns_defaults_on_none() {
        let prio = parse_raw_priority(None).expect("Default priority");
        assert_eq!(prio, h3::Priority::default());
    }

    #[test]
    fn returns_defaults_on_empty() {
        let prio = parse_raw_priority(Some(Vec::new())).expect("Default priority");
        assert_eq!(prio, h3::Priority::default());
    }

    #[test]
    fn parses_urgency_only() {
        for urgency in 0..=7 {
            let prio = parse_raw_priority(bytes(&format!("u={urgency}"))).expect("Valid urgency");
            assert_eq!(prio, h3::Priority::new(urgency, false));
        }
    }

    #[test]
    fn parses_incremental_only() {
        let prio = parse_raw_priority(bytes("i")).expect("Default prio with incremental flag set");
        assert_eq!(prio, h3::Priority::new(3, true));
    }

    #[test]
    fn parses_both_fields() {
        let prio = parse_raw_priority(bytes("u=2, i")).expect("Parses both EPS parameters");
        assert_eq!(prio, h3::Priority::new(2, true));
    }

    #[test]
    fn ignores_out_of_range_urgency_and_preserves_incremental() {
        for urgency in [-5, -1, 8, 10] {
            for incremental in [false, true] {
                let field = format!("u={urgency}, i=?{}", u8::from(incremental));
                let prio = parse_raw_priority(bytes(&field)).expect("Default urgency");
                assert_eq!(prio, h3::Priority::new(3, incremental), "{field}");
            }
        }
    }

    #[test]
    fn invalid_types_fall_back_to_defaults() {
        let prio = parse_raw_priority(bytes("u=\"x\""))
            .expect("Non-integer urgency falls back to default");
        assert_eq!(prio, h3::Priority::default());

        let prio = parse_raw_priority(bytes("i=5"))
            .expect("Non-boolean incremental falls back to default");
        assert_eq!(prio, h3::Priority::default());
    }

    #[test]
    fn malformed_dict_falls_back_to_defaults() {
        let prio = parse_raw_priority(bytes("u"))
            .expect("Malformed structured dictionary falls back to default");
        assert_eq!(prio, h3::Priority::default());
    }
}
