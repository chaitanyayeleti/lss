use anyhow::Result;
use clap::Parser;
use std::path::PathBuf;
use walkdir::WalkDir;
use rayon::prelude::*;
use std::fs;
use git2::Repository;
use serde::Deserialize;
use std::collections::{HashSet, HashMap};
use std::io::Read;
mod rules;
use lss::shannon_entropy;

#[derive(clap::Subcommand, Debug)]
enum RulesCmd {
    /// List rules, optionally filter by name substring
    List {
        /// optional name substring filter
        query: Option<String>,
        /// output json
        #[arg(long)]
        json: bool,
        /// page number (1-based)
        #[arg(long, default_value_t = 1)]
        page: usize,
        /// items per page
        #[arg(long, default_value_t = 20)]
        per_page: usize,
    },
}

#[derive(clap::Subcommand, Debug)]
enum Command {
    /// Scan a path for secrets (default)
    Scan {
        /// Path to scan
        #[arg(short, long, default_value = ".")]
        path: PathBuf,

        /// Output format: human or json
        #[arg(short, long, default_value = "human")]
        format: String,

        /// Override entropy threshold
        #[arg(long)]
        entropy_threshold: Option<f64>,

        /// Additional ignore file (one pattern per line)
        #[arg(long)]
        ignore_file: Option<PathBuf>,

        /// Load extra regex rules from a file (format: Name::Regex per line)
        #[arg(long)]
        rules_file: Option<PathBuf>,

        /// Include only findings that have any of these comma-separated tags
        #[arg(long)]
        include_tags: Option<String>,

        /// Exclude findings that have any of these comma-separated tags
        #[arg(long)]
        exclude_tags: Option<String>,

        /// Minimum rule confidence (0.0-1.0)
        #[arg(long)]
        min_confidence: Option<f64>,
    },

    /// Rules subcommands
    Rules { #[command(subcommand)] cmd: RulesCmd },
}

#[derive(clap::Parser, Debug)]
#[command(name = "lss")]
struct Cli {
    /// Run a scan (shorthand so you can run `lss --scan --path .`)
    #[arg(long)]
    scan: bool,

    /// Path to scan (when using `--scan` shorthand)
    #[arg(long)]
    path: Option<PathBuf>,

    /// Output format (when using `--scan` shorthand)
    #[arg(long)]
    format: Option<String>,

    /// Override entropy threshold (when using `--scan` shorthand)
    #[arg(long)]
    entropy_threshold: Option<f64>,

    /// Additional ignore file (when using `--scan` shorthand)
    #[arg(long)]
    ignore_file: Option<PathBuf>,

    /// Load extra regex rules from a file (when using `--scan` shorthand)
    #[arg(long)]
    rules_file: Option<PathBuf>,

    /// Include only findings that have any of these comma-separated tags (when using `--scan` shorthand)
    #[arg(long)]
    include_tags: Option<String>,

    /// Exclude findings that have any of these comma-separated tags (when using `--scan` shorthand)
    #[arg(long)]
    exclude_tags: Option<String>,

    /// Minimum rule confidence (0.0-1.0) (when using `--scan` shorthand)
    #[arg(long)]
    min_confidence: Option<f64>,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Debug, serde::Serialize)]
struct Finding {
    path: String,
    line: usize,
    snippet: String,
    matched_rules: Vec<String>,
    tags: Vec<String>,
    confidence: f64,
}

#[derive(Debug, Deserialize)]
struct Config {
    ignore: Option<Vec<String>>,
    entropy_threshold: Option<f64>,
}

fn default_patterns() -> Vec<rules::Rule> {
    rules::load_default_rules()
}

fn scan_file(path: &std::path::Path, patterns: &[rules::Rule]) -> Vec<Finding> {
    use std::collections::HashSet as StdHashSet;
    let mut findings = Vec::new();
    let content = match fs::read_to_string(path) {
        Ok(s) => s,
        Err(_) => return findings,
    };

    // aggregate matches per (line, snippet)
    let mut map: HashMap<(usize, String), (Vec<String>, StdHashSet<String>, Vec<f64>)> = HashMap::new();

    for (i, line) in content.lines().enumerate() {
        let snippet = line.trim().to_string();
        for rule in patterns.iter() {
            if rule.regex.is_match(line) {
                let key = (i + 1, snippet.clone());
                let entry = map.entry(key).or_insert((Vec::new(), StdHashSet::new(), Vec::new()));
                entry.0.push(rule.name.clone());
                for t in &rule.tags { entry.1.insert(t.clone()); }
                entry.2.push(rule.confidence);
            }
        }
    }

    for ((line, snippet), (names, tagset, confidences)) in map {
        // combined confidence: 1 - product(1 - ci)
        let mut prod = 1.0f64;
        for c in confidences { prod *= 1.0 - c; }
        let combined = 1.0 - prod;
        let tags: Vec<String> = tagset.into_iter().collect();
        findings.push(Finding {
            path: path.to_string_lossy().to_string(),
            line,
            snippet,
            matched_rules: names,
            tags,
            confidence: combined,
        });
    }

    findings
}


fn should_ignore(path: &str, ignores: &HashSet<String>) -> bool {
    for ig in ignores.iter() {
        if path.contains(ig) { return true }
    }
    false
}

fn scan_git_history(repo_path: &std::path::Path, patterns: &[rules::Rule], ignores: &HashSet<String>, entropy_threshold: f64) -> Vec<Finding> {
    use std::collections::HashSet as StdHashSet;
    let mut findings = Vec::new();
    let repo = match Repository::discover(repo_path) {
        Ok(r) => r,
        Err(_) => return findings,
    };

    let mut revwalk = match repo.revwalk() {
        Ok(rw) => rw,
        Err(_) => return findings,
    };

    if revwalk.push_head().is_err() { return findings }

    for oid in revwalk.flatten() {
        let commit = match repo.find_commit(oid) {
            Ok(c) => c,
            Err(_) => continue,
        };

        let tree = match commit.tree() {
            Ok(t) => t,
            Err(_) => continue,
        };

        let mut stack = vec![tree];
        while let Some(tree) = stack.pop() {
            for entry in tree.iter() {
                if let Some(name) = entry.name() {
                    match entry.kind() {
                        Some(git2::ObjectType::Blob) => {
                            if should_ignore(name, ignores) { continue }
                            let oid = entry.id();
                            if let Ok(blob) = repo.find_blob(oid) {
                                if let Ok(content) = std::str::from_utf8(blob.content()) {
                                    // aggregate per blob by (line, snippet)
                                    let mut map: HashMap<(usize, String), (Vec<String>, StdHashSet<String>, Vec<f64>)> = HashMap::new();
                                    for rule in patterns.iter() {
                                        for (i, line) in content.lines().enumerate() {
                                            if rule.regex.is_match(line) {
                                                let ent = shannon_entropy(line);
                                                if ent >= entropy_threshold {
                                                    let key = (i + 1, line.trim().to_string());
                                                    let entry = map.entry(key).or_insert((Vec::new(), StdHashSet::new(), Vec::new()));
                                                    entry.0.push(rule.name.clone());
                                                    for t in &rule.tags { entry.1.insert(t.clone()); }
                                                    entry.2.push(rule.confidence);
                                                }
                                            }
                                        }
                                    }
                                    for ((line, snippet), (names, tagset, confidences)) in map {
                                        let mut prod = 1.0f64;
                                        for c in confidences { prod *= 1.0 - c; }
                                        let combined = 1.0 - prod;
                                        let tags: Vec<String> = tagset.into_iter().collect();
                                        findings.push(Finding {
                                            path: format!("git:{}:{}", commit.id(), name),
                                            line,
                                            snippet,
                                            matched_rules: names,
                                            tags,
                                            confidence: combined,
                                        });
                                    }
                                }
                            }
                        }
                        Some(git2::ObjectType::Tree) => {
                            if let Ok(obj) = entry.to_object(&repo) {
                                if let Ok(t) = obj.peel_to_tree() {
                                    stack.push(t);
                                }
                            }
                        }
                        _ => {}
                    }
                }
            }
        }
    }

    findings
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let command = if cli.scan {
        Command::Scan {
            path: cli.path.unwrap_or(PathBuf::from(".")),
            format: cli.format.unwrap_or_else(|| "human".to_string()),
            entropy_threshold: cli.entropy_threshold,
            ignore_file: cli.ignore_file,
            rules_file: cli.rules_file,
            include_tags: cli.include_tags,
            exclude_tags: cli.exclude_tags,
            min_confidence: cli.min_confidence,
        }
    } else {
        cli.command.unwrap_or(Command::Scan { path: PathBuf::from("."), format: "human".to_string(), entropy_threshold: None, ignore_file: None, rules_file: None, include_tags: None, exclude_tags: None, min_confidence: None })
    };
    let res: Result<()> = match command {
        Command::Rules { cmd } => {
            match cmd {
                RulesCmd::List { query, json, page, per_page } => {
                    let mut rules = default_patterns();
                    if let Some(q) = &query {
                        rules = rules.into_iter().filter(|r| r.name.contains(q)).collect();
                    }
                    #[derive(Clone, serde::Serialize)]
                    struct RuleView { name: String, pattern: String, tags: Vec<String>, confidence: f64 }
                    let views: Vec<RuleView> = rules.into_iter().map(|r| RuleView { name: r.name, pattern: r.pattern, tags: r.tags, confidence: r.confidence }).collect();
                    let total = views.len();
                    let start = (page.saturating_sub(1)).saturating_mul(per_page);
                    let end = std::cmp::min(start + per_page, total);
                    let slice: Vec<RuleView> = if start < total { views[start..end].to_vec() } else { Vec::new() };
                    if json {
                        let out = serde_json::json!({"total": total, "page": page, "per_page": per_page, "rules": slice});
                        println!("{}", serde_json::to_string_pretty(&out)?);
                    } else {
                        for r in &slice { println!("{} :: {} [{}] conf={}", r.name, r.pattern, r.tags.join(","), r.confidence); }
                        println!("Showing {}-{} of {}", start+1, end, total);
                    }
                    Ok(())
                }
            }
        }
        Command::Scan { path, format, entropy_threshold: cli_entropy, ignore_file: cli_ignore, rules_file: cli_rules, include_tags, exclude_tags, min_confidence } => {
            // prepare patterns
            let mut patterns = default_patterns();
            if let Some(rf) = &cli_rules { let extra = rules::load_rules_from_file(rf); patterns.extend(extra); }

            // prepare tag filters
            let include_tags_set: Option<HashSet<String>> = include_tags.map(|s| s.split(',').map(|t| t.trim().to_string()).collect());
            let exclude_tags_set: Option<HashSet<String>> = exclude_tags.map(|s| s.split(',').map(|t| t.trim().to_string()).collect());

            // load config
            let mut ignores: HashSet<String> = HashSet::new();
            let mut entropy_threshold = 3.5f64; // default
            if let Some(cfg_dir) = dirs_next::config_dir() {
                let cfg = cfg_dir.join("lss").join("config.toml");
                if cfg.exists() {
                    if let Ok(mut s) = fs::File::open(&cfg) {
                        let mut buf = String::new();
                        if s.read_to_string(&mut buf).is_ok() {
                            if let Ok(c) = toml::from_str::<Config>(&buf) {
                                if let Some(v) = c.ignore { for it in v { ignores.insert(it); } }
                                if let Some(e) = c.entropy_threshold { entropy_threshold = e }
                            }
                        }
                    }
                }
            }
            // CLI overrides
            if let Some(e) = cli_entropy { entropy_threshold = e }
            if let Some(ignf) = &cli_ignore { if let Ok(s) = fs::read_to_string(ignf) { for line in s.lines() { let t = line.trim(); if !t.is_empty() { ignores.insert(t.to_string()); } } } }

            // prepare walk
            let walker = WalkDir::new(&path).into_iter();
            let entries: Vec<_> = walker.filter_map(|e| e.ok()).filter(|e| e.file_type().is_file()).collect();

            // load root .lssignore
            let mut ignore_fileset: HashSet<String> = HashSet::new();
            let ignore_path = path.join(".lssignore");
            if ignore_path.exists() {
                if let Ok(s) = fs::read_to_string(&ignore_path) {
                    for line in s.lines() { let t = line.trim(); if !t.is_empty() { ignore_fileset.insert(t.to_string()); } }
                }
            }

            // perform scanning (files + git history)
            let results_files: Vec<Finding> = entries.par_iter().flat_map(|entry| {
                let p = entry.path();
                let s = p.to_string_lossy().to_string();
                // combine config ignores and .lssignore
                let mut combined_ignores = ignores.clone();
                for it in ignore_fileset.iter() { combined_ignores.insert(it.clone()); }
                // per-repo ignores up the tree
                let mut repo_ignores = HashSet::new();
                if let Some(parent) = p.parent() {
                    let mut dir = parent;
                    while dir.starts_with(&path) {
                        let lp = dir.join(".lssignore");
                        if lp.exists() {
                            if let Ok(txt) = fs::read_to_string(&lp) {
                                for line in txt.lines() { let t = line.trim(); if !t.is_empty() { repo_ignores.insert(t.to_string()); } }
                            }
                        }
                        if let Some(up) = dir.parent() { dir = up } else { break }
                    }
                }
                for it in repo_ignores { combined_ignores.insert(it); }
                if should_ignore(&s, &combined_ignores) { return Vec::new() }
                let mut r = scan_file(&p, &patterns);
                // apply entropy and tag/confidence filters
                r.retain(|f| {
                    if f.confidence < min_confidence.unwrap_or(0.0) { return false }
                    if let Some(ex) = &exclude_tags_set { for t in &f.tags { if ex.contains(t) { return false } } }
                    if let Some(inc) = &include_tags_set { for t in &f.tags { if inc.contains(t) { return true } } ; return false }
                    true
                });
                r.retain(|f| shannon_entropy(&f.snippet) >= entropy_threshold);
                r
            }).collect();

            // scan git history for repos inside the path
            let mut results_git = Vec::new();
            if let Ok(entries) = fs::read_dir(&path) {
                for e in entries.flatten() {
                    let p = e.path();
                    if p.join(".git").exists() {
                        let mut g = scan_git_history(&p, &patterns, &ignores, entropy_threshold);
                        results_git.append(&mut g);
                    }
                }
            }

            let mut results = results_files;
            results.extend(results_git);

            if format == "json" {
                println!("{}", serde_json::to_string_pretty(&results)?);
            } else {
                for f in &results {
                    let rules_str = if f.matched_rules.is_empty() { "".to_string() } else { format!(" [{}]", f.matched_rules.join(",")) };
                    let tags = if f.tags.is_empty() { "".to_string() } else { format!(" tags={}", f.tags.join(",")) };
                    println!("{}:{}: {}{}{} conf={}", f.path, f.line, f.snippet, rules_str, tags, f.confidence);
                }
                println!("\nFound {} potential secrets", results.len());
            }

            Ok(())
        }
    };

    res
}
