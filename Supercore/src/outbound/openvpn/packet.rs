use anyhow::{anyhow, bail};

pub(super) const MAX_CONTROL_PAYLOAD: usize = 1_100;
pub(super) const SESSION_ID_LEN: usize = 8;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub(super) enum OpCode {
    SoftResetV1 = 3,
    ControlV1 = 4,
    AckV1 = 5,
    DataV1 = 6,
    HardResetClientV2 = 7,
    HardResetServerV2 = 8,
    DataV2 = 9,
}

impl OpCode {
    pub(super) fn decode(header: u8) -> anyhow::Result<Self> {
        match header >> 3 {
            3 => Ok(Self::SoftResetV1),
            4 => Ok(Self::ControlV1),
            5 => Ok(Self::AckV1),
            6 => Ok(Self::DataV1),
            7 => Ok(Self::HardResetClientV2),
            8 => Ok(Self::HardResetServerV2),
            9 => Ok(Self::DataV2),
            value => bail!("unsupported OpenVPN opcode {value}"),
        }
    }

    pub(super) fn header(self, key_id: u8) -> anyhow::Result<u8> {
        if key_id > 7 {
            bail!("OpenVPN key id must fit in three bits");
        }
        Ok((self as u8) << 3 | key_id)
    }

    pub(super) fn is_data(self) -> bool {
        matches!(self, Self::DataV1 | Self::DataV2)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct ControlPacket {
    pub(super) opcode: OpCode,
    pub(super) key_id: u8,
    pub(super) session_id: [u8; SESSION_ID_LEN],
    pub(super) acknowledgements: Vec<u32>,
    pub(super) remote_session_id: Option<[u8; SESSION_ID_LEN]>,
    pub(super) message_id: Option<u32>,
    pub(super) payload: Vec<u8>,
}

impl ControlPacket {
    pub(super) fn encode_plain(&self) -> anyhow::Result<Vec<u8>> {
        if self.acknowledgements.len() > u8::MAX as usize {
            bail!("too many OpenVPN acknowledgements");
        }
        if !self.acknowledgements.is_empty() && self.remote_session_id.is_none() {
            bail!("OpenVPN acknowledgement packet is missing the remote session id");
        }
        if self.opcode != OpCode::AckV1 && self.message_id.is_none() {
            bail!("OpenVPN control packet is missing its message id");
        }
        let mut output = Vec::with_capacity(
            1 + SESSION_ID_LEN
                + 1
                + self.acknowledgements.len() * 4
                + self.remote_session_id.map(|_| SESSION_ID_LEN).unwrap_or(0)
                + self.message_id.map(|_| 4).unwrap_or(0)
                + self.payload.len(),
        );
        output.push(self.opcode.header(self.key_id)?);
        output.extend_from_slice(&self.session_id);
        output.push(self.acknowledgements.len() as u8);
        for acknowledgement in &self.acknowledgements {
            output.extend_from_slice(&acknowledgement.to_be_bytes());
        }
        if let Some(remote) = self.remote_session_id {
            output.extend_from_slice(&remote);
        }
        if let Some(message_id) = self.message_id {
            output.extend_from_slice(&message_id.to_be_bytes());
        }
        output.extend_from_slice(&self.payload);
        Ok(output)
    }

    pub(super) fn decode_plain(packet: &[u8]) -> anyhow::Result<Self> {
        if packet.len() < 1 + SESSION_ID_LEN + 1 {
            bail!("OpenVPN control packet is too short");
        }
        let opcode = OpCode::decode(packet[0])?;
        if opcode.is_data() {
            bail!("OpenVPN data packet was passed to control decoder");
        }
        let key_id = packet[0] & 0x07;
        let mut session_id = [0u8; SESSION_ID_LEN];
        session_id.copy_from_slice(&packet[1..1 + SESSION_ID_LEN]);
        let mut offset = 1 + SESSION_ID_LEN;
        let acknowledgement_count = packet[offset] as usize;
        offset += 1;
        let acknowledgement_bytes = acknowledgement_count
            .checked_mul(4)
            .ok_or_else(|| anyhow!("OpenVPN acknowledgement count overflow"))?;
        if packet.len() < offset + acknowledgement_bytes {
            bail!("OpenVPN acknowledgement list is truncated");
        }
        let acknowledgements = packet[offset..offset + acknowledgement_bytes]
            .chunks_exact(4)
            .map(|value| u32::from_be_bytes(value.try_into().expect("four-byte chunk")))
            .collect::<Vec<_>>();
        offset += acknowledgement_bytes;
        let remote_session_id = if acknowledgement_count > 0 {
            if packet.len() < offset + SESSION_ID_LEN {
                bail!("OpenVPN remote session id is truncated");
            }
            let mut remote = [0u8; SESSION_ID_LEN];
            remote.copy_from_slice(&packet[offset..offset + SESSION_ID_LEN]);
            offset += SESSION_ID_LEN;
            Some(remote)
        } else {
            None
        };
        let message_id = if opcode == OpCode::AckV1 {
            None
        } else {
            if packet.len() < offset + 4 {
                bail!("OpenVPN control message id is truncated");
            }
            let value = u32::from_be_bytes(packet[offset..offset + 4].try_into()?);
            offset += 4;
            Some(value)
        };
        Ok(Self {
            opcode,
            key_id,
            session_id,
            acknowledgements,
            remote_session_id,
            message_id,
            payload: packet[offset..].to_vec(),
        })
    }
}

#[derive(Clone, Debug)]
pub(super) struct ReplayWindow {
    highest: u32,
    bitmap: u128,
    initialized: bool,
}

impl ReplayWindow {
    pub(super) fn new() -> Self {
        Self {
            highest: 0,
            bitmap: 0,
            initialized: false,
        }
    }

    pub(super) fn accept(&mut self, packet_id: u32) -> bool {
        if packet_id == 0 {
            return false;
        }
        if !self.initialized {
            self.highest = packet_id;
            self.bitmap = 1;
            self.initialized = true;
            return true;
        }
        if packet_id > self.highest {
            let shift = packet_id - self.highest;
            self.bitmap = if shift >= 128 {
                1
            } else {
                (self.bitmap << shift) | 1
            };
            self.highest = packet_id;
            return true;
        }
        let distance = self.highest - packet_id;
        if distance >= 128 {
            return false;
        }
        let mask = 1u128 << distance;
        if self.bitmap & mask != 0 {
            return false;
        }
        self.bitmap |= mask;
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn control_packet_round_trip() {
        let packet = ControlPacket {
            opcode: OpCode::ControlV1,
            key_id: 2,
            session_id: *b"client01",
            acknowledgements: vec![4, 7],
            remote_session_id: Some(*b"server01"),
            message_id: Some(8),
            payload: b"tls".to_vec(),
        };
        assert_eq!(ControlPacket::decode_plain(&packet.encode_plain().unwrap()).unwrap(), packet);
    }

    #[test]
    fn replay_window_accepts_reordering_once() {
        let mut window = ReplayWindow::new();
        assert!(window.accept(10));
        assert!(window.accept(12));
        assert!(window.accept(11));
        assert!(!window.accept(11));
        assert!(!window.accept(0));
    }
}
