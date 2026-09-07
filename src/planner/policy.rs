use crate::domain::vantage::VantagePoint;

pub struct Selection {
    pub selected: Vec<VantagePoint>,
    pub skipped: usize,
}

/// Deterministic first-K selection within budget, input order preserved.
pub fn select_vantages(
    include_direct: bool,
    proxies: Vec<VantagePoint>,
    max_probes: usize,
) -> Selection {
    let mut selected = Vec::new();
    if include_direct && max_probes > 0 {
        selected.push(VantagePoint::Direct);
    }
    let mut skipped = 0;
    for p in proxies {
        if selected.len() < max_probes {
            selected.push(p);
        } else {
            skipped += 1;
        }
    }
    Selection { selected, skipped }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::vantage::parse_proxy;

    #[test]
    fn bounds_selection() {
        let proxies = vec![
            parse_proxy("http://a.example:8080").unwrap(),
            parse_proxy("http://b.example:8080").unwrap(),
            parse_proxy("http://c.example:8080").unwrap(),
        ];
        let s = select_vantages(true, proxies, 2);
        assert_eq!(s.selected.len(), 2);
        assert_eq!(s.skipped, 2);
    }
}
