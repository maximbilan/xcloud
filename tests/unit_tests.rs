use serde_json::json;

#[test]
fn pretty_status_prefers_build_result_then_progress() {
    let v = json!({"attributes": {"buildResult": "SUCCEEDED", "status": "SOMETHING"}});
    assert_eq!(xcloud::pretty_run_status(&v), "SUCCEEDED");
    let v2 = json!({"attributes": {"executionProgress": "RUNNING"}});
    assert_eq!(xcloud::pretty_run_status(&v2), "RUNNING");
}
