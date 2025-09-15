use serde_json::Value;
use std::cmp::Ordering;

pub fn pretty_run_status(run: &Value) -> String {
    let attributes = run.get("attributes");
    let status = attributes
        .and_then(|a| a.get("buildResult"))
        .and_then(|s| s.as_str())
        .or_else(|| {
            attributes
                .and_then(|a| a.get("executionProgress"))
                .and_then(|s| s.as_str())
        })
        .or_else(|| {
            attributes
                .and_then(|a| a.get("completionStatus"))
                .and_then(|s| s.as_str())
        })
        .or_else(|| {
            attributes
                .and_then(|a| a.get("status"))
                .and_then(|s| s.as_str())
        })
        .unwrap_or("UNKNOWN");
    status.to_string()
}

pub fn compare_runs_desc(a: &Value, b: &Value) -> Ordering {
    let created_a = a
        .get("attributes")
        .and_then(|x| x.get("createdDate"))
        .and_then(|s| s.as_str());
    let created_b = b
        .get("attributes")
        .and_then(|x| x.get("createdDate"))
        .and_then(|s| s.as_str());
    match (created_a, created_b) {
        (Some(a), Some(b)) => b.cmp(a),
        (Some(_), None) => Ordering::Less,
        (None, Some(_)) => Ordering::Greater,
        _ => {
            let id_a = a.get("id").and_then(|s| s.as_str()).unwrap_or("");
            let id_b = b.get("id").and_then(|s| s.as_str()).unwrap_or("");
            id_b.cmp(id_a)
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

pub fn resource_name(resource: &Value) -> String {
    if let Some(attrs) = resource.get("attributes") {
        if let Some(s) = attrs.get("name").and_then(|n| n.as_str()) {
            return s.to_string();
        }
        if let Some(s) = attrs.get("canonicalName").and_then(|n| n.as_str()) {
            return s.to_string();
        }
        if let Some(s) = attrs.get("title").and_then(|n| n.as_str()) {
            return s.to_string();
        }
    }
    resource
        .get("id")
        .and_then(|i| i.as_str())
        .unwrap_or("<unknown>")
        .to_string()
}

pub fn resource_id(resource: &Value) -> String {
    resource
        .get("id")
        .and_then(|i| i.as_str())
        .unwrap_or("")
        .to_string()
}

