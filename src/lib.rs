use std::collections::HashMap;

/// Compute Shannon entropy of a string (bytes-level)
pub fn shannon_entropy(s: &str) -> f64 {
    if s.is_empty() { return 0.0 }
    let mut freq: HashMap<u8, usize> = HashMap::new();
    for b in s.bytes() {
        *freq.entry(b).or_insert(0usize) += 1;
    }
    let len = s.len() as f64;
    let mut ent = 0f64;
    for &count in freq.values() {
        let p = (count as f64) / len;
        ent -= p * p.log2();
    }
    ent
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_entropy_empty() {
        assert_eq!(shannon_entropy(""), 0.0);
    }

    #[test]
    fn test_entropy_low_high() {
        let low = shannon_entropy("aaaaaaaaaaaa");
        let high = shannon_entropy("a4G$9kL2#xPq7Z!");
        assert!(low < high);
    }
}
