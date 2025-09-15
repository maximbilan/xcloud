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
