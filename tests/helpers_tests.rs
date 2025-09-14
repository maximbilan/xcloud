use serde_json::json;

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
