use regex::Regex;
use std::path::PathBuf;
use std::fs;

#[derive(Debug, Clone)]
pub struct Rule {
    pub name: String,
    pub regex: Regex,
    pub pattern: String,
    pub tags: Vec<String>,
    pub confidence: f64,
}

pub fn load_default_rules() -> Vec<Rule> {
    let data = include_str!("../rules/default_rules.txt");
    parse_rules(data)
}

pub fn parse_rules(s: &str) -> Vec<Rule> {
    let mut v = Vec::new();
    for line in s.lines() {
        let l = line.trim();
        if l.is_empty() || l.starts_with('#') { continue }
        // Format: Name::Regex::tag1,tag2
        let parts: Vec<&str> = l.split("::").collect();
        if parts.len() >= 2 {
            let name = parts[0].trim().to_string();
            let pat = parts[1].trim();
            let mut tags = Vec::new();
            let mut confidence = 0.5f64;
            if parts.len() >= 3 { tags = parts[2].split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect(); }
            if parts.len() >= 4 { if let Ok(c) = parts[3].trim().parse::<f64>() { confidence = c } }
            if let Ok(re) = Regex::new(pat) {
                v.push(Rule { name, regex: re, pattern: pat.to_string(), tags, confidence });
            }
        }
    }
    v
}

pub fn load_rules_from_file(path: &PathBuf) -> Vec<Rule> {
    if let Ok(s) = fs::read_to_string(path) { parse_rules(&s) } else { Vec::new() }
}
