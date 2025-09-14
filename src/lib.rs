use serde_json::Value;
use std::cmp::Ordering;

pub fn pretty_run_status(run: &Value) -> String {
    let a = run.get("attributes");
    let status = a
        .and_then(|a| a.get("buildResult")).and_then(|s| s.as_str())
        .or_else(|| a.and_then(|a| a.get("executionProgress")).and_then(|s| s.as_str()))
        .or_else(|| a.and_then(|a| a.get("completionStatus")).and_then(|s| s.as_str()))
        .or_else(|| a.and_then(|a| a.get("status")).and_then(|s| s.as_str()))
        .unwrap_or("UNKNOWN");
    status.to_string()
}

pub fn compare_runs_desc(a: &Value, b: &Value) -> Ordering {
    let ca = a.get("attributes").and_then(|x| x.get("createdDate")).and_then(|s| s.as_str());
    let cb = b.get("attributes").and_then(|x| x.get("createdDate")).and_then(|s| s.as_str());
    match (ca, cb) {
        (Some(a), Some(b)) => b.cmp(a), // newer first
        (Some(_), None) => Ordering::Less,
        (None, Some(_)) => Ordering::Greater,
        _ => {
            let ida = a.get("id").and_then(|s| s.as_str()).unwrap_or("");
            let idb = b.get("id").and_then(|s| s.as_str()).unwrap_or("");
            idb.cmp(ida)
        }
    }
}

pub fn is_branch_git_ref(v: &Value) -> bool {
    v.get("attributes")
        .and_then(|a| a.get("canonicalName"))
        .and_then(|s| s.as_str())
        .map(|s| s.starts_with("refs/heads/") || s.starts_with("heads/") || s.contains("/heads/"))
        .unwrap_or(false)
}
