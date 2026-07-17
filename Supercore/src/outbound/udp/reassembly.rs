use std::{collections::HashMap, hash::Hash, time::Duration, time::Instant};

use anyhow::anyhow;

const DEFAULT_MAX_ENTRIES: usize = 64;
const DEFAULT_MAX_PAYLOAD: usize = 65_535;
const DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_secs(10);

struct FragmentSet {
    total: u8,
    fragments: Vec<Option<Vec<u8>>>,
    received_bytes: usize,
    last_used: Instant,
}

pub(crate) struct FragmentReassembler<K> {
    packets: HashMap<K, FragmentSet>,
    max_entries: usize,
    max_payload: usize,
    idle_timeout: Duration,
}

impl<K> Default for FragmentReassembler<K> {
    fn default() -> Self {
        Self {
            packets: HashMap::new(),
            max_entries: DEFAULT_MAX_ENTRIES,
            max_payload: DEFAULT_MAX_PAYLOAD,
            idle_timeout: DEFAULT_IDLE_TIMEOUT,
        }
    }
}

impl<K> FragmentReassembler<K>
where
    K: Clone + Eq + Hash,
{
    pub(crate) fn push(
        &mut self,
        key: K,
        fragment_id: u8,
        fragment_total: u8,
        payload: Vec<u8>,
    ) -> anyhow::Result<Option<Vec<u8>>> {
        if fragment_total == 0 || fragment_id >= fragment_total {
            return Err(anyhow!(
                "invalid UDP fragment id/count: {fragment_id}/{fragment_total}"
            ));
        }
        if fragment_total == 1 {
            if payload.len() > self.max_payload {
                return Err(anyhow!("UDP fragment payload is too large"));
            }
            return Ok(Some(payload));
        }

        let now = Instant::now();
        self.packets
            .retain(|_, entry| now.duration_since(entry.last_used) < self.idle_timeout);
        if !self.packets.contains_key(&key) && self.packets.len() >= self.max_entries {
            if let Some(oldest) = self
                .packets
                .iter()
                .min_by_key(|(_, entry)| entry.last_used)
                .map(|(key, _)| key.clone())
            {
                self.packets.remove(&oldest);
            }
        }

        let entry = self
            .packets
            .entry(key.clone())
            .or_insert_with(|| FragmentSet {
                total: fragment_total,
                fragments: vec![None; fragment_total as usize],
                received_bytes: 0,
                last_used: now,
            });
        if entry.total != fragment_total {
            self.packets.remove(&key);
            return Err(anyhow!("inconsistent UDP fragment count"));
        }
        let slot = &mut entry.fragments[fragment_id as usize];
        if slot.is_some() {
            self.packets.remove(&key);
            return Err(anyhow!("duplicate UDP fragment {fragment_id}"));
        }
        let new_size = entry.received_bytes.saturating_add(payload.len());
        if new_size > self.max_payload {
            self.packets.remove(&key);
            return Err(anyhow!("UDP reassembled payload is too large"));
        }
        *slot = Some(payload);
        entry.received_bytes = new_size;
        entry.last_used = now;
        if entry.fragments.iter().any(Option::is_none) {
            return Ok(None);
        }

        let entry = self
            .packets
            .remove(&key)
            .ok_or_else(|| anyhow!("UDP reassembly entry disappeared"))?;
        let mut output = Vec::with_capacity(entry.received_bytes);
        for fragment in entry.fragments {
            output.extend_from_slice(
                &fragment.ok_or_else(|| anyhow!("missing UDP fragment after completion"))?,
            );
        }
        Ok(Some(output))
    }
}

#[cfg(test)]
mod tests {
    use super::FragmentReassembler;

    #[test]
    fn reassembles_out_of_order_and_removes_completed_entry() {
        let mut reassembly = FragmentReassembler::default();
        assert_eq!(
            reassembly.push(7u16, 1, 2, b"world".to_vec()).unwrap(),
            None
        );
        assert_eq!(
            reassembly.push(7u16, 0, 2, b"hello ".to_vec()).unwrap(),
            Some(b"hello world".to_vec())
        );
        assert_eq!(reassembly.packets.len(), 0);
    }

    #[test]
    fn rejects_duplicate_inconsistent_and_oversized_fragments() {
        let mut reassembly = FragmentReassembler::default();
        assert_eq!(reassembly.push(1u16, 0, 2, b"a".to_vec()).unwrap(), None);
        assert!(reassembly
            .push(1u16, 0, 2, b"a".to_vec())
            .unwrap_err()
            .to_string()
            .contains("duplicate"));

        assert_eq!(reassembly.push(2u16, 0, 2, b"a".to_vec()).unwrap(), None);
        assert!(reassembly
            .push(2u16, 1, 3, b"b".to_vec())
            .unwrap_err()
            .to_string()
            .contains("inconsistent"));

        assert!(reassembly
            .push(3u16, 0, 1, vec![0; 65_536])
            .unwrap_err()
            .to_string()
            .contains("too large"));
    }
}
