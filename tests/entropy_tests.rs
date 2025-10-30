use lss::shannon_entropy;

#[test]
fn test_entropy_empty() {
    assert_eq!(shannon_entropy("") , 0.0);
}

#[test]
fn test_entropy_low_high() {
    let low = shannon_entropy("aaaaaaaaaaaa");
    let high = shannon_entropy("a4G$9kL2#xPq7Z!");
    assert!(low < high);
}
