use super::*;

pub(super) mod probes;
pub(super) mod providers;
pub(super) mod routing;
pub(super) mod subscriptions;
pub(super) mod system;
pub(super) mod tasks;
#[cfg(test)]
pub(super) use probes::collect_group_probe_members;

pub(super) fn build_router_with_tasks(
    runtime: Arc<Runtime>,
    auth: ControlAuthState,
    tasks: TaskManager,
) -> Router {
    let state = ApiState { runtime, tasks };
    Router::new()
        .route("/health", get(tasks::health))
        .route("/v1/schema", get(system::api_schema))
        .route("/v1/version", get(system::version))
        .route("/v1/status", get(system::status))
        .route("/v1/outbounds", get(routing::outbounds))
        .route("/v1/outbounds/use", post(routing::use_outbound))
        .route("/v1/groups", get(routing::groups))
        .route("/v1/countries", get(routing::countries))
        .route("/v1/countries/use", post(routing::use_country))
        .route("/v1/probes", post(probes::probe_outbounds))
        .route("/v1/probes/group", post(probes::probe_group_body))
        .route("/v1/route/decision", post(routing::route_decision))
        .route("/v1/subscriptions", get(subscriptions::subscriptions))
        .route(
            "/v1/subscriptions/import",
            post(subscriptions::import_subscription),
        )
        .route(
            "/v1/subscriptions/use",
            post(subscriptions::use_subscription),
        )
        .route(
            "/v1/subscriptions/reload-active",
            post(subscriptions::reload_active_subscription),
        )
        .route(
            "/v1/subscriptions/update-all",
            post(subscriptions::update_all_subscriptions),
        )
        .route(
            "/v1/subscriptions/update",
            post(subscriptions::update_subscription),
        )
        .route(
            "/v1/subscriptions/active-config",
            post(subscriptions::active_subscription_config),
        )
        .route("/v1/providers/proxies", get(providers::proxy_providers))
        .route("/v1/providers/rules", get(providers::rule_providers))
        .route("/v1/providers/update", post(providers::update_providers))
        .route(
            "/v1/providers/update-all",
            post(providers::update_all_providers),
        )
        .route("/v1/rules", get(routing::rules_snapshot))
        .route(
            "/v1/smart-rules",
            get(routing::smart_rules).post(routing::upsert_smart_rule),
        )
        .route(
            "/v1/smart-rules/enabled",
            post(routing::set_smart_rule_enabled),
        )
        .route("/v1/smart-rules/delete", post(routing::delete_smart_rule))
        .route(
            "/v1/smart-rules/apply-recommendations",
            post(routing::apply_smart_recommendations),
        )
        .route(
            "/v1/smart-rules/apply-recommendation",
            post(routing::apply_smart_recommendation),
        )
        .route("/v1/traffic", get(system::traffic))
        .route(
            "/v1/traffic/subscriptions",
            get(subscriptions::subscription_traffic),
        )
        .route("/v1/connections", get(system::connections))
        .route("/v1/logs", get(system::logs))
        .route("/v1/config", get(system::config))
        .route("/v1/config/reload", post(system::reload_config))
        .route("/v1/tun", get(system::tun_status))
        .route("/v1/doctor", get(system::doctor))
        .route("/v1/doctor/run", post(system::run_doctor))
        .route("/v1/diagnostics/export", post(system::export_diagnostics))
        .route("/v1/geo/update", post(system::update_geo))
        .route("/v1/tasks", get(tasks::task_list))
        .route("/v1/tasks/:id", get(tasks::task_status))
        .route("/v1/tasks/:id/cancel", post(tasks::cancel_task))
        .route("/v1/events", get(task_events))
        .layer(middleware::from_fn_with_state(auth, authorize_writes))
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}
