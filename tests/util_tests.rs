use serde_json::json;

#[test]
fn pretty_status_prefers_build_result_then_progress() {
    let v = json!({"attributes": {"buildResult": "SUCCEEDED", "status": "SOMETHING"}});
    assert_eq!(xcloud::pretty_run_status(&v), "SUCCEEDED");
    let v2 = json!({"attributes": {"executionProgress": "RUNNING"}});
    assert_eq!(xcloud::pretty_run_status(&v2), "RUNNING");
}

#[test]
fn resource_name_and_id_fallbacks() {
    let v = json!({"id":"abc","attributes": {"name": "My Name"}});
    assert_eq!(xcloud::resource_name(&v), "My Name");
    assert_eq!(xcloud::resource_id(&v), "abc");

    let v2 = json!({"id":"def","attributes": {"canonicalName": "refs/heads/main"}});
    assert_eq!(xcloud::resource_name(&v2), "refs/heads/main");
    assert_eq!(xcloud::resource_id(&v2), "def");

    let v3 = json!({"id":"ghi"});
    assert_eq!(xcloud::resource_name(&v3), "ghi");
    assert_eq!(xcloud::resource_id(&v3), "ghi");
}

#[test]
fn test_is_branch_git_ref() {
    let branch = json!({
        "id": "ref1",
        "attributes": {"canonicalName": "refs/heads/main"}
    });
    let tag = json!({
        "id": "ref2",
        "attributes": {"canonicalName": "refs/tags/1.0.0"}
    });
    assert!(xcloud::is_branch_git_ref(&branch));
    assert!(!xcloud::is_branch_git_ref(&tag));
}

#[test]
fn test_compare_runs_desc() {
    let a = json!({"id":"1","attributes":{"createdDate":"2025-01-01T00:00:00Z"}});
    let b = json!({"id":"2","attributes":{"createdDate":"2025-02-01T00:00:00Z"}});
    let ord = xcloud::compare_runs_desc(&a, &b);
    assert_eq!(ord as i32, std::cmp::Ordering::Greater as i32);
}
