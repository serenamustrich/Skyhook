use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    io::{Cursor, Read, Write},
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::{anyhow, bail, Context};
use getrandom::fill as random_fill;
use rustls::{
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    crypto::{
        aws_lc_rs, verify_tls12_signature, verify_tls13_signature,
        WebPkiSupportedAlgorithms,
    },
    pki_types::{CertificateDer, ServerName, UnixTime},
    ClientConfig, ClientConnection, DigitallySignedStruct, RootCertStore, SignatureScheme,
};
use tokio::time::timeout;

use super::{
    config::{OpenVpnCipher, OpenVpnProfile},
    data::DataChannel,
    key_method::{
        derive_key_material, parse_peer_id, parse_server_auth, tls_exporter_label,
        ClientKeySource, ServerKeyRecord,
    },
    link::OpenVpnLink,
    packet::{ControlPacket, OpCode, MAX_CONTROL_PAYLOAD},
    push::PushReply,
    wrap::ControlWrap,
};

const CONTROL_RETRANSMIT: Duration = Duration::from_secs(1);
const CONTROL_MAX_RETRIES: u8 = 8;
const CONTROL_REORDER_WINDOW: u32 = 64;
const MAX_CONTROL_PLAINTEXT: usize = 128 * 1024;
const ACK_BATCH: usize = 8;
const SERVER_AUTH_EKU: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01];

pub(super) struct NegotiatedConnection {
    pub(super) link: OpenVpnLink,
    pub(super) control: ReliableControl,
    pub(super) tls: ClientConnection,
    pub(super) data: DataChannel,
    pub(super) push: PushReply,
    pub(super) cipher: OpenVpnCipher,
}

#[derive(Clone)]
struct PendingControl {
    packet: ControlPacket,
    last_sent: Instant,
    retries: u8,
}

pub(super) struct ReliableControl {
    local_session: [u8; 8],
    remote_session: Option<[u8; 8]>,
    key_id: u8,
    next_send_id: u32,
    next_receive_id: u32,
    pending: BTreeMap<u32, PendingControl>,
    reordered: BTreeMap<u32, (OpCode, Vec<u8>)>,
    acknowledgements: BTreeSet<u32>,
    wrap: ControlWrap,
}

pub(super) struct ControlEvents {
    pub(super) payloads: Vec<Vec<u8>>,
    pub(super) hard_reset: bool,
    pub(super) soft_reset: bool,
}

impl ReliableControl {
    fn new(profile: &OpenVpnProfile) -> anyhow::Result<Self> {
        let mut local_session = [0; 8];
        random_fill(&mut local_session)?;
        let wrap = if let Some(material) = &profile.tls_crypt {
            ControlWrap::tls_crypt(material)?
        } else if let Some(material) = &profile.tls_auth {
            ControlWrap::tls_auth(material, profile.auth, profile.key_direction)?
        } else {
            ControlWrap::none()
        };
        Ok(Self {
            local_session,
            remote_session: None,
            key_id: 0,
            next_send_id: 0,
            next_receive_id: 0,
            pending: BTreeMap::new(),
            reordered: BTreeMap::new(),
            acknowledgements: BTreeSet::new(),
            wrap,
        })
    }

    pub(super) fn local_session(&self) -> [u8; 8] {
        self.local_session
    }

    pub(super) fn remote_session(&self) -> anyhow::Result<[u8; 8]> {
        self.remote_session
            .ok_or_else(|| anyhow!("OpenVPN server session id is not established"))
    }

    async fn send_hard_reset(&mut self, link: &mut OpenVpnLink) -> anyhow::Result<()> {
        self.send_reliable(link, OpCode::HardResetClientV2, Vec::new())
            .await
    }

    pub(super) async fn send_tls(
        &mut self,
        link: &mut OpenVpnLink,
        payload: &[u8],
    ) -> anyhow::Result<()> {
        if payload.is_empty() {
            return Ok(());
        }
        for chunk in payload.chunks(MAX_CONTROL_PAYLOAD) {
            self.send_reliable(link, OpCode::ControlV1, chunk.to_vec())
                .await?;
        }
        Ok(())
    }

    async fn send_reliable(
        &mut self,
        link: &mut OpenVpnLink,
        opcode: OpCode,
        payload: Vec<u8>,
    ) -> anyhow::Result<()> {
        let message_id = self.next_send_id;
        self.next_send_id = self
            .next_send_id
            .checked_add(1)
            .ok_or_else(|| anyhow!("OpenVPN control message id exhausted"))?;
        let acknowledgements = self.take_acknowledgements(4);
        let packet = ControlPacket {
            opcode,
            key_id: self.key_id,
            session_id: self.local_session,
            remote_session_id: (!acknowledgements.is_empty())
                .then_some(self.remote_session())
                .transpose()?,
            acknowledgements,
            message_id: Some(message_id),
            payload,
        };
        self.transmit(link, &packet).await?;
        self.pending.insert(
            message_id,
            PendingControl {
                packet,
                last_sent: Instant::now(),
                retries: 0,
            },
        );
        Ok(())
    }

    pub(super) async fn receive(
        &mut self,
        link: &mut OpenVpnLink,
        wire: &[u8],
    ) -> anyhow::Result<ControlEvents> {
        let plain = self.wrap.unwrap(wire)?;
        let packet = ControlPacket::decode_plain(&plain)?;
        if packet.key_id != self.key_id {
            bail!("OpenVPN control packet uses inactive key id {}", packet.key_id);
        }
        if let Some(remote) = packet.remote_session_id {
            if remote != self.local_session {
                bail!("OpenVPN control acknowledgement targets another session");
            }
        }
        for acknowledgement in &packet.acknowledgements {
            self.pending.remove(acknowledgement);
        }
        if self.remote_session.is_none() {
            if packet.opcode != OpCode::HardResetServerV2 {
                bail!("OpenVPN server sent control data before its hard reset");
            }
            self.remote_session = Some(packet.session_id);
        } else if self.remote_session != Some(packet.session_id) {
            bail!("OpenVPN control packet session id changed unexpectedly");
        }

        let mut hard_reset = false;
        let mut soft_reset = false;
        let mut payloads = Vec::new();
        if let Some(message_id) = packet.message_id {
            self.acknowledgements.insert(message_id);
            if message_id >= self.next_receive_id
                && message_id.saturating_sub(self.next_receive_id) <= CONTROL_REORDER_WINDOW
            {
                self.reordered
                    .entry(message_id)
                    .or_insert((packet.opcode, packet.payload));
            }
            while let Some((opcode, payload)) = self.reordered.remove(&self.next_receive_id) {
                self.next_receive_id = self
                    .next_receive_id
                    .checked_add(1)
                    .ok_or_else(|| anyhow!("OpenVPN receive message id exhausted"))?;
                match opcode {
                    OpCode::ControlV1 if !payload.is_empty() => payloads.push(payload),
                    OpCode::HardResetServerV2 => hard_reset = true,
                    OpCode::SoftResetV1 => soft_reset = true,
                    _ => {}
                }
            }
        }
        self.send_acknowledgements(link).await?;
        Ok(ControlEvents {
            payloads,
            hard_reset,
            soft_reset,
        })
    }

    pub(super) async fn retransmit_due(
        &mut self,
        link: &mut OpenVpnLink,
    ) -> anyhow::Result<()> {
        let now = Instant::now();
        let due = self
            .pending
            .iter()
            .filter(|(_, pending)| now.duration_since(pending.last_sent) >= CONTROL_RETRANSMIT)
            .map(|(id, _)| *id)
            .collect::<Vec<_>>();
        for id in due {
            let packet = self
                .pending
                .get(&id)
                .map(|pending| pending.packet.clone())
                .ok_or_else(|| anyhow!("OpenVPN retransmit queue changed unexpectedly"))?;
            let retries = self.pending.get(&id).map(|pending| pending.retries).unwrap_or(0);
            if retries >= CONTROL_MAX_RETRIES {
                bail!("OpenVPN control packet {id} was not acknowledged");
            }
            self.transmit(link, &packet).await?;
            if let Some(pending) = self.pending.get_mut(&id) {
                pending.last_sent = now;
                pending.retries += 1;
            }
        }
        Ok(())
    }

    async fn send_acknowledgements(&mut self, link: &mut OpenVpnLink) -> anyhow::Result<()> {
        while !self.acknowledgements.is_empty() {
            let acknowledgements = self.take_acknowledgements(ACK_BATCH);
            let packet = ControlPacket {
                opcode: OpCode::AckV1,
                key_id: self.key_id,
                session_id: self.local_session,
                remote_session_id: Some(self.remote_session()?),
                acknowledgements,
                message_id: None,
                payload: Vec::new(),
            };
            self.transmit(link, &packet).await?;
        }
        Ok(())
    }

    fn take_acknowledgements(&mut self, limit: usize) -> Vec<u32> {
        let values = self
            .acknowledgements
            .iter()
            .take(limit)
            .copied()
            .collect::<Vec<_>>();
        for value in &values {
            self.acknowledgements.remove(value);
        }
        values
    }

    async fn transmit(
        &mut self,
        link: &mut OpenVpnLink,
        packet: &ControlPacket,
    ) -> anyhow::Result<()> {
        let plain = packet.encode_plain()?;
        let wire = self.wrap.wrap(&plain)?;
        link.send(&wire).await
    }
}

pub(super) async fn negotiate(
    profile: &OpenVpnProfile,
    remote_index: usize,
    timeout_ms: u64,
) -> anyhow::Result<NegotiatedConnection> {
    let remote = profile
        .remotes
        .get(remote_index)
        .ok_or_else(|| anyhow!("OpenVPN remote index is out of range"))?;
    let dial_timeout = timeout_ms.min(profile.handshake_timeout.as_millis() as u64).max(1);
    let mut link = OpenVpnLink::connect(remote, dial_timeout).await?;
    let mut control = ReliableControl::new(profile)?;
    control.send_hard_reset(&mut link).await?;
    let deadline = Instant::now() + Duration::from_millis(dial_timeout);

    loop {
        let events = receive_events_until(&mut control, &mut link, deadline).await?;
        if events.hard_reset {
            break;
        }
    }

    let tls_config = tls_config(profile)?;
    let tls_name = profile
        .server_name
        .as_deref()
        .unwrap_or(remote.host.as_str())
        .to_string();
    let server_name = ServerName::try_from(tls_name.clone())
        .map_err(|_| anyhow!("invalid OpenVPN TLS server name {tls_name}"))?;
    let mut tls = ClientConnection::new(Arc::new(tls_config), server_name)?;
    send_tls_output(&mut control, &mut link, &mut tls).await?;
    while tls.is_handshaking() {
        let events = receive_events_until(&mut control, &mut link, deadline).await?;
        if events.soft_reset {
            bail!("OpenVPN server requested renegotiation during initial handshake");
        }
        feed_tls_payloads(&mut tls, events.payloads)?;
        send_tls_output(&mut control, &mut link, &mut tls).await?;
    }

    let client_source = ClientKeySource::random()?;
    write_tls_plaintext(&mut tls, &client_source.encode(profile, remote_index)?)?;
    send_tls_output(&mut control, &mut link, &mut tls).await?;
    let mut plaintext = Vec::new();
    let server_record = loop {
        drain_tls_plaintext(&mut tls, &mut plaintext)?;
        if plaintext.len() > MAX_CONTROL_PLAINTEXT {
            bail!("OpenVPN TLS plaintext exceeded the negotiation limit");
        }
        if plaintext.starts_with(b"AUTH_FAILED") {
            let message = String::from_utf8_lossy(&plaintext);
            bail!("OpenVPN authentication failed: {}", message.trim_matches('\0'));
        }
        if let Ok(record) = ServerKeyRecord::decode(&plaintext) {
            break record;
        }
        let events = receive_events_until(&mut control, &mut link, deadline).await?;
        feed_tls_payloads(&mut tls, events.payloads)?;
        send_tls_output(&mut control, &mut link, &mut tls).await?;
    };
    plaintext.drain(..server_record.consumed);

    let auth = parse_server_auth(&server_record.options, profile.auth)?;
    write_tls_plaintext(&mut tls, b"PUSH_REQUEST\0")?;
    send_tls_output(&mut control, &mut link, &mut tls).await?;
    let push = loop {
        drain_tls_plaintext(&mut tls, &mut plaintext)?;
        if plaintext.len() > MAX_CONTROL_PLAINTEXT {
            bail!("OpenVPN pushed configuration exceeded the negotiation limit");
        }
        if let Some(message) = take_control_message(&mut plaintext)? {
            if message.starts_with("PUSH_REPLY") || message.starts_with("AUTH_") {
                break PushReply::parse(&message)?;
            }
        }
        let events = receive_events_until(&mut control, &mut link, deadline).await?;
        feed_tls_payloads(&mut tls, events.payloads)?;
        send_tls_output(&mut control, &mut link, &mut tls).await?;
    };
    let exported = if push.tls_exporter || server_record.uses_tls_exporter() {
        let mut material = [0u8; 256];
        tls.export_keying_material(&mut material, tls_exporter_label(), None)?;
        Some(material)
    } else {
        None
    };
    let cipher = if let Some(cipher) = &push.cipher {
        let cipher = OpenVpnCipher::parse(cipher)?;
        if !profile.data_ciphers.contains(&cipher) {
            bail!("OpenVPN server pushed unadvertised data cipher {}", cipher.name());
        }
        cipher
    } else {
        server_record.negotiated_cipher(profile)?
    };
    let keys = derive_key_material(
        &client_source,
        &server_record.source,
        &control.local_session(),
        &control.remote_session()?,
        cipher,
        exported.as_ref().map(|value| value.as_slice()),
    )?;
    let peer_id = push.peer_id.or_else(|| parse_peer_id(&server_record.options));
    let data = DataChannel::new(
        cipher,
        auth,
        keys,
        0,
        peer_id,
        profile.compression_lzo,
    )?;
    Ok(NegotiatedConnection {
        link,
        control,
        tls,
        data,
        push,
        cipher,
    })
}

pub(super) fn process_tls_control(
    tls: &mut ClientConnection,
    payloads: Vec<Vec<u8>>,
    plaintext: &mut Vec<u8>,
) -> anyhow::Result<Vec<String>> {
    feed_tls_payloads(tls, payloads)?;
    drain_tls_plaintext(tls, plaintext)?;
    if plaintext.len() > MAX_CONTROL_PLAINTEXT {
        bail!("OpenVPN TLS control message exceeded the runtime limit");
    }
    let mut messages = Vec::new();
    while let Some(message) = take_control_message(plaintext)? {
        messages.push(message);
    }
    Ok(messages)
}

pub(super) async fn send_pending_tls(
    control: &mut ReliableControl,
    link: &mut OpenVpnLink,
    tls: &mut ClientConnection,
) -> anyhow::Result<()> {
    send_tls_output(control, link, tls).await
}

async fn receive_events_until(
    control: &mut ReliableControl,
    link: &mut OpenVpnLink,
    deadline: Instant,
) -> anyhow::Result<ControlEvents> {
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            bail!("OpenVPN negotiation timed out");
        }
        let wait = remaining.min(Duration::from_millis(200));
        match timeout(wait, link.receive()).await {
            Ok(result) => {
                let wire = result.context("OpenVPN control transport closed while receiving a packet")?;
                if wire
                    .first()
                    .copied()
                    .and_then(|header| OpCode::decode(header).ok())
                    .is_some_and(OpCode::is_data)
                {
                    continue;
                }
                return control
                    .receive(link, &wire)
                    .await
                    .context("OpenVPN control packet processing failed");
            }
            Err(_) => control.retransmit_due(link).await?,
        }
    }
}

fn feed_tls_payloads(tls: &mut ClientConnection, payloads: Vec<Vec<u8>>) -> anyhow::Result<()> {
    for payload in payloads {
        let mut cursor = Cursor::new(payload);
        while cursor.position() < cursor.get_ref().len() as u64 {
            let read = tls.read_tls(&mut cursor)?;
            if read == 0 {
                bail!("OpenVPN TLS engine stopped consuming control data");
            }
            tls.process_new_packets().map_err(|error| {
                anyhow!(
                    "OpenVPN TLS record processing failed after consuming {read} bytes: {error}"
                )
            })?;
        }
    }
    Ok(())
}

async fn send_tls_output(
    control: &mut ReliableControl,
    link: &mut OpenVpnLink,
    tls: &mut ClientConnection,
) -> anyhow::Result<()> {
    while tls.wants_write() {
        let mut output = Vec::new();
        let written = tls.write_tls(&mut output)?;
        if written == 0 {
            break;
        }
        control.send_tls(link, &output).await?;
    }
    Ok(())
}

fn write_tls_plaintext(tls: &mut ClientConnection, value: &[u8]) -> anyhow::Result<()> {
    tls.writer().write_all(value)?;
    Ok(())
}

fn drain_tls_plaintext(tls: &mut ClientConnection, output: &mut Vec<u8>) -> anyhow::Result<()> {
    let mut chunk = [0u8; 4_096];
    loop {
        match tls.reader().read(&mut chunk) {
            Ok(0) => break,
            Ok(length) => output.extend_from_slice(&chunk[..length]),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

fn take_control_message(buffer: &mut Vec<u8>) -> anyhow::Result<Option<String>> {
    let Some(end) = buffer.iter().position(|byte| *byte == 0) else {
        return Ok(None);
    };
    let bytes = buffer.drain(..=end).collect::<Vec<_>>();
    Ok(Some(std::str::from_utf8(&bytes[..bytes.len() - 1])?.to_string()))
}

fn tls_config(profile: &OpenVpnProfile) -> anyhow::Result<ClientConfig> {
    let ca_certificates = rustls_pemfile::certs(&mut profile.ca.as_slice())
        .collect::<Result<Vec<_>, _>>()?;
    if ca_certificates.is_empty() {
        bail!("OpenVPN CA block contains no certificates");
    }
    let mut roots = RootCertStore::empty();
    for certificate in ca_certificates {
        roots.add(certificate)?;
    }
    let provider = aws_lc_rs::default_provider();
    let expected_name = profile
        .verify_x509_name
        .as_ref()
        .map(|name| ServerName::try_from(name.clone()))
        .transpose()
        .map_err(|_| anyhow!("invalid OpenVPN verify-x509-name"))?;
    let verifier = Arc::new(OpenVpnCertificateVerifier {
        roots,
        algorithms: provider.signature_verification_algorithms,
        expected_name,
        require_server_eku: profile.remote_cert_tls_server,
    });
    let builder = ClientConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])?
        .dangerous()
        .with_custom_certificate_verifier(verifier);
    let mut config = match (&profile.cert, &profile.key) {
        (Some(cert), Some(key)) => {
            let certificates = rustls_pemfile::certs(&mut cert.as_slice())
                .collect::<Result<Vec<_>, _>>()?;
            if certificates.is_empty() {
                bail!("OpenVPN client certificate block is empty");
            }
            let key = rustls_pemfile::private_key(&mut key.as_slice())?
                .ok_or_else(|| anyhow!("OpenVPN client key block contains no private key"))?;
            builder.with_client_auth_cert(certificates, key)?
        }
        (None, None) => builder.with_no_client_auth(),
        _ => bail!("OpenVPN client cert and key must be configured together"),
    };
    config.enable_sni = true;
    Ok(config)
}

#[derive(Clone)]
struct OpenVpnCertificateVerifier {
    roots: RootCertStore,
    algorithms: WebPkiSupportedAlgorithms,
    expected_name: Option<ServerName<'static>>,
    require_server_eku: bool,
}

impl fmt::Debug for OpenVpnCertificateVerifier {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OpenVpnCertificateVerifier")
            .field("root_count", &self.roots.len())
            .field("checks_name", &self.expected_name.is_some())
            .field("requires_server_eku", &self.require_server_eku)
            .finish()
    }
}

impl ServerCertVerifier for OpenVpnCertificateVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let certificate = webpki::EndEntityCert::try_from(end_entity)
            .map_err(|error| rustls::Error::General(format!("OpenVPN certificate parse failed: {error}")))?;
        let usage = if self.require_server_eku {
            webpki::KeyUsage::required(SERVER_AUTH_EKU)
        } else {
            webpki::KeyUsage::server_auth()
        };
        certificate
            .verify_for_usage(
                self.algorithms.all,
                &self.roots.roots,
                intermediates,
                now,
                usage,
                None,
                None,
            )
            .map_err(|error| rustls::Error::General(format!("OpenVPN certificate chain validation failed: {error}")))?;
        if let Some(expected) = &self.expected_name {
            certificate
                .verify_is_valid_for_subject_name(expected)
                .map_err(|error| rustls::Error::General(format!("OpenVPN certificate name validation failed: {error}")))?;
        }
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(message, certificate, signature, &self.algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(message, certificate, signature, &self.algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algorithms.supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn control_reliable_packet_ids_begin_at_zero() {
        let profile = OpenVpnProfile::load(
            None,
            Some(
                "client\nremote vpn.example 1194\nauth-user-pass [inline]\n<auth-user-pass>\nu\np\n</auth-user-pass>\n<ca>\ninvalid\n</ca>\n",
            ),
            &crate::config::OpenVpnOptions::default(),
        )
        .unwrap();
        let control = ReliableControl::new(&profile).unwrap();
        assert_eq!(control.next_send_id, 0);
        assert_eq!(control.next_receive_id, 0);
    }
}
