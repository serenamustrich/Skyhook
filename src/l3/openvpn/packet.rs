use anyhow::anyhow;

pub const P_CONTROL_HARD_RESET_CLIENT_V2: u8 = 7;
pub const P_CONTROL_V1: u8 = 4;
pub const P_ACK_V1: u8 = 5;
pub const P_DATA_V1: u8 = 9;

const SESSION_ID_LEN: usize = 8;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenVpnPacket {
    pub opcode: u8,
    pub session_id: [u8; SESSION_ID_LEN],
    pub packet_id: u32,
    pub payload: Vec<u8>,
}

pub fn generate_session_id() -> [u8; SESSION_ID_LEN] {
    let mut id = [0u8; SESSION_ID_LEN];
    getrandom::fill(&mut id).expect("failed to generate session id");
    id
}

pub fn parse(data: &[u8]) -> anyhow::Result<OpenVpnPacket> {
    if data.is_empty() {
        return Err(anyhow!("openvpn packet too short"));
    }

    let opcode = data[0];
    let mut pos = 1;

    if data.len() < pos + SESSION_ID_LEN {
        return Err(anyhow!("openvpn packet too short for session id"));
    }
    let mut session_id = [0u8; SESSION_ID_LEN];
    session_id.copy_from_slice(&data[pos..pos + SESSION_ID_LEN]);
    pos += SESSION_ID_LEN;

    if data.len() < pos + 4 {
        return Err(anyhow!("openvpn packet too short for packet id"));
    }
    let packet_id = u32::from_be_bytes(data[pos..pos + 4].try_into().unwrap());
    pos += 4;

    let payload = data[pos..].to_vec();

    Ok(OpenVpnPacket {
        opcode,
        session_id,
        packet_id,
        payload,
    })
}

pub fn serialize(packet: &OpenVpnPacket) -> Vec<u8> {
    let mut buf = Vec::with_capacity(1 + SESSION_ID_LEN + 4 + packet.payload.len());
    buf.push(packet.opcode);
    buf.extend_from_slice(&packet.session_id);
    buf.extend_from_slice(&packet.packet_id.to_be_bytes());
    buf.extend_from_slice(&packet.payload);
    buf
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_control_v1() {
        let pkt = OpenVpnPacket {
            opcode: P_CONTROL_V1,
            session_id: generate_session_id(),
            packet_id: 42,
            payload: vec![0xde, 0xad, 0xbe, 0xef],
        };
        let bytes = serialize(&pkt);
        let parsed = parse(&bytes).unwrap();
        assert_eq!(pkt, parsed);
    }

    #[test]
    fn roundtrip_ack_v1() {
        let pkt = OpenVpnPacket {
            opcode: P_ACK_V1,
            session_id: [1, 2, 3, 4, 5, 6, 7, 8],
            packet_id: 0,
            payload: vec![],
        };
        let bytes = serialize(&pkt);
        let parsed = parse(&bytes).unwrap();
        assert_eq!(pkt, parsed);
    }

    #[test]
    fn roundtrip_hard_reset_client_v2() {
        let pkt = OpenVpnPacket {
            opcode: P_CONTROL_HARD_RESET_CLIENT_V2,
            session_id: generate_session_id(),
            packet_id: 1,
            payload: vec![0u8; 64],
        };
        let bytes = serialize(&pkt);
        let parsed = parse(&bytes).unwrap();
        assert_eq!(pkt, parsed);
    }

    #[test]
    fn roundtrip_data_v1() {
        let pkt = OpenVpnPacket {
            opcode: P_DATA_V1,
            session_id: [0xff; 8],
            packet_id: 999,
            payload: vec![1, 2, 3],
        };
        let bytes = serialize(&pkt);
        let parsed = parse(&bytes).unwrap();
        assert_eq!(pkt, parsed);
    }

    #[test]
    fn parse_empty_returns_error() {
        assert!(parse(&[]).is_err());
    }

    #[test]
    fn parse_truncated_session_id_returns_error() {
        assert!(parse(&[P_CONTROL_V1, 0, 0]).is_err());
    }

    #[test]
    fn parse_truncated_packet_id_returns_error() {
        let mut data = vec![P_CONTROL_V1];
        data.extend_from_slice(&[0u8; 8]);
        data.extend_from_slice(&[0, 0]);
        assert!(parse(&data).is_err());
    }
}
