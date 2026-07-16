use super::*;

pub(super) mod probes;
#[cfg(test)]
pub(super) use probes::collect_group_probe_members;

pub(super) fn build_router_with_tasks(
    runtime: Arc<Runtime>,
    auth: ControlAuthState,
    tasks: TaskManager,
) -> Router {
    let state = ApiState { runtime, tasks };
    Router::new()
        .route("/health", get(health))
        .route("/v1/version", get(version))
        .route("/v1/status", get(status))
        .route("/v1/outbounds", get(outbounds))
        .route("/v1/outbounds/use", post(use_outbound))
        .route("/v1/groups", get(groups))
        .route("/v1/countries", get(countries))
        .route("/v1/countries/use", post(use_country))
        .route("/v1/probes", post(probes::probe_outbounds))
        .route("/v1/probes/group", post(probes::probe_group_body))
        .route("/v1/route/decision", post(route_decision))
        .route("/v1/subscriptions", get(subscriptions))
        .route("/v1/subscriptions/import", post(import_subscription))
        .route("/v1/subscriptions/use", post(use_subscription))
        .route(
            "/v1/subscriptions/reload-active",
            post(reload_active_subscription),
        )
        .route(
            "/v1/subscriptions/update-all",
            post(update_all_subscriptions),
        )
        .route("/v1/subscriptions/update", post(update_subscription))
        .route(
            "/v1/subscriptions/active-config",
            post(active_subscription_config),
        )
        .route("/v1/providers/proxies", get(proxy_providers))
        .route("/v1/providers/rules", get(rule_providers))
        .route("/v1/providers/update", post(update_providers))
        .route("/v1/providers/update-all", post(update_all_providers))
        .route("/v1/rules", get(rules_snapshot))
        .route("/v1/smart-rules", get(smart_rules).post(upsert_smart_rule))
        .route("/v1/smart-rules/enabled", post(set_smart_rule_enabled))
        .route("/v1/smart-rules/delete", post(delete_smart_rule))
        .route(
            "/v1/smart-rules/apply-recommendations",
            post(apply_smart_recommendations),
        )
        .route(
            "/v1/smart-rules/apply-recommendation",
            post(apply_smart_recommendation),
        )
        .route("/v1/traffic", get(traffic))
        .route("/v1/traffic/subscriptions", get(subscription_traffic))
        .route("/v1/connections", get(connections))
        .route("/v1/logs", get(logs))
        .route("/v1/config", get(config))
        .route("/v1/config/reload", post(reload_config))
        .route("/v1/tun", get(tun_status))
        .route("/v1/doctor", get(doctor))
        .route("/v1/doctor/run", post(run_doctor))
        .route("/v1/diagnostics/export", post(export_diagnostics))
        .route("/v1/geo/update", post(update_geo))
        .route("/v1/tasks", get(task_list))
        .route("/v1/tasks/:id", get(task_status))
        .route("/v1/tasks/:id/cancel", post(cancel_task))
        .route("/v1/events", get(task_events))
        .layer(middleware::from_fn_with_state(auth, authorize_writes))
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}
