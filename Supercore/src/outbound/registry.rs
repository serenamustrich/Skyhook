use std::sync::Arc;

use anyhow::anyhow;

use crate::{config::OutboundConfig, telemetry::Telemetry};

use super::{group::GroupOutbound, Outbound, OutboundMap};

pub(crate) fn insert_leaf(
    outbounds: &mut OutboundMap,
    name: &str,
    outbound: Arc<dyn Outbound>,
) -> anyhow::Result<()> {
    if outbounds.insert(name.to_string(), outbound).is_some() {
        return Err(anyhow!("duplicate outbound name {name}"));
    }
    Ok(())
}

pub(crate) fn attach_groups(
    configs: &[OutboundConfig],
    outbounds: &mut OutboundMap,
    telemetry: Option<Arc<Telemetry>>,
) -> anyhow::Result<()> {
    for config in configs {
        let OutboundConfig::Group {
            name,
            kind,
            members,
        } = config
        else {
            continue;
        };
        let mut group_members = Vec::new();
        for member in members {
            let outbound = outbounds
                .get(member)
                .cloned()
                .ok_or_else(|| anyhow!("group {name} references undefined outbound {member}"))?;
            group_members.push(outbound);
        }
        if group_members.is_empty() {
            return Err(anyhow!("group {name} has no members"));
        }
        let outbound: Arc<dyn Outbound> = Arc::new(GroupOutbound::new(
            name.clone(),
            kind.clone(),
            group_members,
            telemetry.clone(),
        ));
        insert_leaf(outbounds, name, outbound)?;
    }
    Ok(())
}
