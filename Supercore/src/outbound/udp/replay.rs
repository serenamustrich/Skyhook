#[derive(Default)]
pub(crate) struct ReplayWindow64 {
    initialized: bool,
    highest: u64,
    bitmap: u64,
}

impl ReplayWindow64 {
    pub(crate) fn accept(&mut self, packet_id: u64) -> bool {
        if !self.initialized {
            self.initialized = true;
            self.highest = packet_id;
            self.bitmap = 1;
            return true;
        }
        if packet_id > self.highest {
            let shift = packet_id - self.highest;
            self.bitmap = if shift >= 64 {
                1
            } else {
                (self.bitmap << shift) | 1
            };
            self.highest = packet_id;
            return true;
        }
        let distance = self.highest - packet_id;
        if distance >= 64 {
            return false;
        }
        let mask = 1u64 << distance;
        if self.bitmap & mask != 0 {
            return false;
        }
        self.bitmap |= mask;
        true
    }
}

#[cfg(test)]
mod tests {
    use super::ReplayWindow64;

    #[test]
    fn accepts_reordered_packets_once_and_rejects_old_packets() {
        let mut replay = ReplayWindow64::default();
        assert!(replay.accept(100));
        assert!(replay.accept(102));
        assert!(replay.accept(101));
        assert!(!replay.accept(101));
        assert!(replay.accept(200));
        assert!(!replay.accept(100));
    }
}
