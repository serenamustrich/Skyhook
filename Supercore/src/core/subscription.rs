use crate::{config::SuperConfig, subscription_store::SubscriptionStore};

use super::Runtime;

impl Runtime {
    pub fn subscription_store(&self) -> SubscriptionStore {
        SubscriptionStore::new(self.base_config().subscriptions.store_path)
    }

    pub fn active_subscription_config(
        &self,
        use_first_node: Option<bool>,
    ) -> anyhow::Result<SuperConfig> {
        let base_config = self.base_config();
        let use_first_node =
            use_first_node.unwrap_or(base_config.subscriptions.use_first_node_as_default);
        self.subscription_store()
            .active_runtime_config(base_config, use_first_node)
    }

    pub fn reload_active_subscription(&self) -> anyhow::Result<SuperConfig> {
        let use_first_node = self.config().subscriptions.use_first_node_as_default;
        let config = self.active_subscription_config(Some(use_first_node))?;
        self.reload_config(config)
    }
}
