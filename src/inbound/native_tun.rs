use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::anyhow;
use serde::Serialize;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::broadcast,
};

use crate::{
    config::{SuperConfig, TunBackend},
    core::Runtime,
    routing::Destination,
};

use super::native_tun_flow::{classify_ip_protocol, FlowKey, FlowTable};
use super::native_tun_packet::{
    build_ipv4_udp_response, extract_dns_query, extract_tls_sni, extract_transport_ports,
    is_dns_packet, parse_ip_packet, TunIpPacket,
};
use super::native_tun_system::{execute_setup_plan, NativeTunSetupGuard, NativeTunSetupPlan};

const MACOS_UTUN_ADDRESS_FAMILY_LEN: usize = 4;

#[derive(Debug)]
pub struct DnsHijackCounters {
    pub queries: AtomicU64,
    pub successes: AtomicU64,
    pub failures: AtomicU64,
    pub unsupported_ipv6: AtomicU64,
}

impl DnsHijackCounters {
    pub fn new() -> Self {
        Self {
            queries: AtomicU64::new(0),
            successes: AtomicU64::new(0),
            failures: AtomicU64::new(0),
            unsupported_ipv6: AtomicU64::new(0),
        }
    }

    pub fn snapshot(&self) -> DnsHijackSnapshot {
        DnsHijackSnapshot {
            queries: self.queries.load(Ordering::Relaxed),
            successes: self.successes.load(Ordering::Relaxed),
            failures: self.failures.load(Ordering::Relaxed),
            unsupported_ipv6: self.unsupported_ipv6.load(Ordering::Relaxed),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct DnsHijackSnapshot {
    pub queries: u64,
    pub successes: u64,
    pub failures: u64,
    pub unsupported_ipv6: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct NativeTunProfile {
    pub enabled: bool,
    pub backend: &'static str,
    pub l3_profile: Option<String>,
    pub mtu: u16,
    pub interface_name: Option<String>,
    pub setup_enabled: bool,
    pub auto_route: bool,
    pub warnings: Vec<String>,
}

pub async fn serve(runtime: Arc<Runtime>) -> anyhow::Result<()> {
    let runtime_config = runtime.config();
    let config = runtime_config.tun.clone();
    if !config.enabled {
        return Ok(());
    }

    if config.backend != TunBackend::NativeL3 {
        return Ok(());
    }

    let l3_profile = config
        .l3_profile
        .as_ref()
        .ok_or_else(|| anyhow!("native_l3 tun backend requires tun.l3_profile to be set"))?
        .clone();

    let mtu = if config.mtu == 0 { 1500 } else { config.mtu };

    runtime
        .telemetry()
        .log(
            "info",
            format!(
                "native_l3 tun inbound starting: l3_profile={}, mtu={}",
                l3_profile, mtu
            ),
        )
        .await;

    let (tun_file, interface_name) = create_tun_interface(&config.name, mtu)?;
    let tun_device = NativeTunDevice {
        file: tun_file,
        interface_name,
        mtu,
    };

    tracing::info!(
        interface = %tun_device.interface_name,
        mtu = tun_device.mtu,
        "native_tun: created interface"
    );

    let metrics = runtime.tun_metrics().clone();
    metrics.set_interface_name(Some(tun_device.interface_name.clone()));
    metrics.set_l3_profile(Some(l3_profile.clone()));
    metrics.set_mtu(mtu);

    let mut setup_guard: Option<NativeTunSetupGuard> = None;

    if config.setup {
        let mut plan = NativeTunSetupPlan::from_config(&config, tun_device.interface_name.clone());

        let endpoints = runtime.collect_l3_endpoints();
        if !endpoints.is_empty() {
            plan.add_endpoint_bypass(endpoints);
        }

        tracing::info!(
            addresses = plan.inet4_address.len() + plan.inet6_address.len(),
            routes = plan.route_add.len(),
            bypass = plan.bypass.len(),
            endpoint_bypass = plan.endpoint_bypass.len(),
            "native_tun: executing setup plan"
        );

        match execute_setup_plan(&plan).await {
            Ok(setup) => {
                metrics.set_routes(setup.result.installed_routes.clone());
                metrics.set_bypass_routes(setup.result.installed_bypass_routes.clone());
                metrics.set_skipped_bypass_routes(setup.result.skipped_bypass_routes.clone());
                metrics
                    .set_endpoint_bypass_installed(setup.result.installed_endpoint_bypass.clone());
                metrics.set_endpoint_bypass_skipped(setup.result.skipped_endpoint_bypass.clone());
                metrics.set_setup_warnings(setup.result.warnings.clone());
                for warning in &setup.result.warnings {
                    tracing::warn!("native_tun: setup warning: {}", warning);
                }
                setup_guard = Some(setup.guard);
                tracing::info!(
                    routes = setup.result.installed_routes.len(),
                    bypass = setup.result.installed_bypass_routes.len(),
                    endpoint_bypass = setup.result.installed_endpoint_bypass.len(),
                    skipped = setup.result.skipped_bypass_routes.len(),
                    "native_tun: setup complete"
                );
            }
            Err(e) => {
                tracing::error!(error = %e, "native_tun: setup failed");
                return Err(e);
            }
        }
    }

    metrics.set_running(true);

    let _runtime_guard = NativeTunRuntimeGuard {
        metrics: metrics.clone(),
    };

    let (mut tun_reader, mut tun_writer) = tokio::io::split(tun_device.file);

    let mut inbound_rx = runtime.subscribe_l3_ip_packets(&l3_profile)?;

    let dns_hijack_enabled = runtime.config().dns.enabled && runtime.config().dns.hijack_udp_53;
    let dns_counters = Arc::new(DnsHijackCounters::new());
    let dns_counters_clone = dns_counters.clone();

    let flow_table = Arc::new(FlowTable::new(10000, Duration::from_secs(300)));
    let flow_table_clone = flow_table.clone();

    let (dns_response_tx, mut dns_response_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(128);

    let mut session_manager = super::native_tun_session::NativeSessionManager::new();
    let tun_addr = config
        .inet4_address
        .first()
        .and_then(|s| s.split('/').next())
        .and_then(|ip| ip.parse::<std::net::Ipv4Addr>().ok())
        .unwrap_or(std::net::Ipv4Addr::new(198, 18, 0, 1));
    session_manager
        .stack_mut()
        .add_address(smoltcp::wire::IpCidr::new(
            smoltcp::wire::IpAddress::Ipv4(smoltcp::wire::Ipv4Address::from(tun_addr.octets())),
            30,
        ));

    let dns_cache = session_manager.dns_cache().clone();
    let (l4_packet_tx, mut l4_packet_rx) = tokio::sync::mpsc::channel::<(Vec<u8>, FlowKey)>(256);
    let (l4_egress_tx, mut l4_egress_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(256);

    let runtime_clone = runtime.clone();
    let l3_profile_clone = l3_profile.clone();
    let read_metrics = metrics.clone();

    let read_handle = tokio::spawn(async move {
        let mut buf = vec![0u8; 65535];
        loop {
            match tun_reader.read(&mut buf).await {
                Ok(0) => {
                    runtime_clone
                        .telemetry()
                        .log("warn", "native_tun: read returned 0, stopping".to_string())
                        .await;
                    break;
                }
                Ok(len) => {
                    read_metrics.record_read(len as u64);
                    let packet = match decode_tun_read_packet(&buf[..len]) {
                        Ok(pkt) => pkt,
                        Err(e) => {
                            read_metrics.record_decode_error();
                            runtime_clone
                                .telemetry()
                                .log(
                                    "warn",
                                    format!("native_tun: decode read packet failed: {e}"),
                                )
                                .await;
                            continue;
                        }
                    };

                    if dns_hijack_enabled {
                        match parse_ip_packet(&packet) {
                            Ok(ip_packet) if is_dns_packet(&ip_packet) => {
                                dns_counters_clone.queries.fetch_add(1, Ordering::Relaxed);
                                match &ip_packet {
                                    TunIpPacket::Ipv6(_) => {
                                        dns_counters_clone
                                            .unsupported_ipv6
                                            .fetch_add(1, Ordering::Relaxed);
                                        runtime_clone
                                            .telemetry()
                                            .log(
                                                "warn",
                                                "native_tun: DNS hijack for IPv6 not implemented"
                                                    .to_string(),
                                            )
                                            .await;
                                    }
                                    TunIpPacket::Ipv4(_) => {
                                        match extract_dns_query(&ip_packet) {
                                            Ok((src, dst, dns_payload)) => {
                                                let src_ipv4 = match src.ip() {
                                                    std::net::IpAddr::V4(v4) => v4,
                                                    _ => Ipv4Addr::LOCALHOST,
                                                };
                                                let dst_ipv4 = match dst.ip() {
                                                    std::net::IpAddr::V4(v4) => v4,
                                                    _ => Ipv4Addr::LOCALHOST,
                                                };
                                                match runtime_clone
                                                    .exchange_dns_over_tcp(&dns_payload)
                                                    .await
                                                {
                                                    Ok(response) => {
                                                        super::native_tun_dns::parse_dns_response_to_cache(
                                                            &dns_payload,
                                                            &response,
                                                            &dns_cache,
                                                        );
                                                        let response_packet =
                                                            build_ipv4_udp_response(
                                                                dst_ipv4,
                                                                src_ipv4,
                                                                53,
                                                                src.port(),
                                                                &response,
                                                            );
                                                        match encode_tun_write_packet(
                                                            &response_packet,
                                                        ) {
                                                            Ok(encoded) => {
                                                                if dns_response_tx
                                                                    .send(encoded)
                                                                    .await
                                                                    .is_err()
                                                                {
                                                                    dns_counters_clone
                                                                        .failures
                                                                        .fetch_add(
                                                                            1,
                                                                            Ordering::Relaxed,
                                                                        );
                                                                    break;
                                                                }
                                                                dns_counters_clone
                                                                    .successes
                                                                    .fetch_add(
                                                                        1,
                                                                        Ordering::Relaxed,
                                                                    );
                                                            }
                                                            Err(e) => {
                                                                dns_counters_clone
                                                                    .failures
                                                                    .fetch_add(
                                                                        1,
                                                                        Ordering::Relaxed,
                                                                    );
                                                                runtime_clone
                                                                    .telemetry()
                                                                    .log("warn", format!("native_tun: encode DNS response failed: {e}"))
                                                                    .await;
                                                            }
                                                        }
                                                    }
                                                    Err(e) => {
                                                        dns_counters_clone
                                                            .failures
                                                            .fetch_add(1, Ordering::Relaxed);
                                                        runtime_clone
                                                            .telemetry()
                                                            .log("warn", format!("native_tun: DNS query failed: {e}"))
                                                            .await;
                                                    }
                                                }
                                            }
                                            Err(e) => {
                                                dns_counters_clone
                                                    .failures
                                                    .fetch_add(1, Ordering::Relaxed);
                                                runtime_clone
                                                    .telemetry()
                                                    .log("warn", format!("native_tun: extract DNS query failed: {e}"))
                                                    .await;
                                            }
                                        }
                                    }
                                }
                                continue;
                            }
                            _ => {}
                        }
                    }

                    if let Ok(ip_packet) = parse_ip_packet(&packet) {
                        let (src_port, dst_port) = extract_transport_ports(&ip_packet);
                        let sni = extract_tls_sni(&ip_packet);

                        let (protocol, src, dst) = match &ip_packet {
                            TunIpPacket::Ipv4(ipv4) => {
                                let proto = classify_ip_protocol(ipv4.protocol);
                                let src = std::net::SocketAddr::new(
                                    std::net::IpAddr::V4(ipv4.source),
                                    src_port,
                                );
                                let dst = std::net::SocketAddr::new(
                                    std::net::IpAddr::V4(ipv4.destination),
                                    dst_port,
                                );
                                (proto, src, dst)
                            }
                            TunIpPacket::Ipv6(ipv6) => {
                                let proto = classify_ip_protocol(ipv6.next_header);
                                let src = std::net::SocketAddr::new(
                                    std::net::IpAddr::V6(ipv6.source),
                                    src_port,
                                );
                                let dst = std::net::SocketAddr::new(
                                    std::net::IpAddr::V6(ipv6.destination),
                                    dst_port,
                                );
                                (proto, src, dst)
                            }
                        };

                        let flow_key = FlowKey { protocol, src, dst };

                        let flow = flow_table_clone.get_or_create_flow(
                            flow_key.clone(),
                            sni.clone(),
                            None,
                        );
                        flow_table_clone.update_flow(&flow_key, packet.len() as u64);

                        if flow.decision.is_none() {
                            let destination = if let Some(hostname) = sni.as_deref() {
                                Destination::new(hostname.to_string(), dst_port)
                            } else {
                                Destination::new(dst.ip().to_string(), dst_port)
                            };
                            let decision = runtime_clone.decide(&destination);
                            flow_table_clone.set_decision(&flow_key, decision);
                        }

                        let flow_decision = flow_table_clone
                            .get_flow(&flow_key)
                            .and_then(|f| f.decision.clone());

                        if let Some(decision) = flow_decision {
                            let route = super::native_tun_router::resolve_native_route(
                                &runtime_clone,
                                &decision,
                            )
                            .await;

                            match &route.target {
                                super::native_tun_router::NativeRouteTarget::L3Profile { name } => {
                                    let result =
                                        runtime_clone.send_l3_ip_packet(name, packet).await;
                                    if !result.accepted {
                                        read_metrics.record_rejected();
                                    }
                                }
                                super::native_tun_router::NativeRouteTarget::Reject { reason } => {
                                    read_metrics.record_dropped(reason.clone());
                                }
                                _ => {
                                    let _ = l4_packet_tx.send((packet, flow_key)).await;
                                }
                            }
                        } else {
                            let result = runtime_clone
                                .send_l3_ip_packet(&l3_profile_clone, packet)
                                .await;
                            if !result.accepted {
                                read_metrics.record_rejected();
                            }
                        }
                    } else {
                        let result = runtime_clone
                            .send_l3_ip_packet(&l3_profile_clone, packet)
                            .await;
                        if !result.accepted {
                            read_metrics.record_rejected();
                        }
                    }
                }
                Err(e) => {
                    runtime_clone
                        .telemetry()
                        .log("error", format!("native_tun: read error: {e}"))
                        .await;
                    break;
                }
            }
        }
    });

    let runtime_clone = runtime.clone();
    let write_metrics = metrics.clone();
    let write_handle = tokio::spawn(async move {
        loop {
            tokio::select! {
                Some(encoded) = dns_response_rx.recv() => {
                    if let Err(e) = tun_writer.write_all(&encoded).await {
                        runtime_clone
                            .telemetry()
                            .log("error", format!("native_tun: write DNS response failed: {e}"))
                            .await;
                        break;
                    }
                    write_metrics.record_write(encoded.len() as u64);
                }
                Some(packet) = l4_egress_rx.recv() => {
                    let encoded = match encode_tun_write_packet(&packet) {
                        Ok(pkt) => pkt,
                        Err(e) => {
                            write_metrics.record_encode_error();
                            continue;
                        }
                    };
                    if let Err(e) = tun_writer.write_all(&encoded).await {
                        runtime_clone
                            .telemetry()
                            .log("error", format!("native_tun: write L4 egress failed: {e}"))
                            .await;
                        break;
                    }
                    write_metrics.record_write(encoded.len() as u64);
                }
                result = inbound_rx.recv() => {
                    match result {
                        Ok(packet) => {
                            let encoded = match encode_tun_write_packet(&packet.packet) {
                                Ok(pkt) => pkt,
                                Err(e) => {
                                    write_metrics.record_encode_error();
                                    runtime_clone
                                        .telemetry()
                                        .log(
                                            "warn",
                                            format!("native_tun: encode write packet failed: {e}"),
                                        )
                                        .await;
                                    continue;
                                }
                            };
                            if let Err(e) = tun_writer.write_all(&encoded).await {
                                runtime_clone
                                    .telemetry()
                                    .log("error", format!("native_tun: write error: {e}"))
                                    .await;
                                break;
                            }
                            write_metrics.record_write(encoded.len() as u64);
                        }
                        Err(broadcast::error::RecvError::Lagged(_)) => {
                            runtime_clone
                                .telemetry()
                                .log(
                                    "warn",
                                    "native_tun: inbound packet channel lagged".to_string(),
                                )
                                .await;
                        }
                        Err(broadcast::error::RecvError::Closed) => {
                            runtime_clone
                                .telemetry()
                                .log(
                                    "info",
                                    "native_tun: inbound packet channel closed".to_string(),
                                )
                                .await;
                            break;
                        }
                    }
                }
            }
        }
    });

    let runtime_clone = runtime.clone();
    let l4_handle = tokio::spawn(async move {
        let mut session_mgr = session_manager;
        let runtime = runtime_clone;
        loop {
            tokio::select! {
                Some((packet, _flow_key)) = l4_packet_rx.recv() => {
                    session_mgr.inject_packet(packet);
                }
                _ = tokio::time::sleep(Duration::from_millis(1)) => {}
            }

            session_mgr.process_events(&runtime).await;

            let response_packets = session_mgr.take_pending_writes();
            for packet in response_packets {
                if l4_egress_tx.send(packet).await.is_err() {
                    break;
                }
            }
        }
    });

    tokio::select! {
        _ = read_handle => {}
        _ = write_handle => {}
        _ = l4_handle => {}
    }

    drop(_runtime_guard);

    if let Some(guard) = setup_guard {
        tracing::info!("native_tun: cleaning up routes");
        guard.cleanup().await;
    }

    Ok(())
}

#[derive(Debug)]
pub struct NativeTunDevice {
    pub file: tokio::fs::File,
    pub interface_name: String,
    pub mtu: u16,
}

struct NativeTunRuntimeGuard {
    metrics: super::native_tun_metrics::NativeTunMetrics,
}

impl Drop for NativeTunRuntimeGuard {
    fn drop(&mut self) {
        self.metrics.set_running(false);
    }
}

fn create_tun_interface(
    name: &Option<String>,
    _mtu: u16,
) -> anyhow::Result<(tokio::fs::File, String)> {
    #[cfg(target_os = "macos")]
    {
        use std::os::unix::io::FromRawFd;

        let fd = unsafe { libc::socket(libc::PF_SYSTEM, libc::SOCK_DGRAM, libc::SYSPROTO_CONTROL) };
        if fd < 0 {
            return Err(anyhow!("failed to create system socket for utun"));
        }

        let mut ctl_info: libc::ctl_info = unsafe { std::mem::zeroed() };
        let control_name = b"com.apple.net.utun_control\0";
        let copy_len = control_name.len().min(libc::MAX_KCTL_NAME);
        for (dst, src) in ctl_info.ctl_name[..copy_len]
            .iter_mut()
            .zip(control_name.iter())
        {
            *dst = *src as i8;
        }

        let ret = unsafe { libc::ioctl(fd, libc::CTLIOCGINFO, &mut ctl_info) };
        if ret < 0 {
            unsafe {
                libc::close(fd);
            }
            return Err(anyhow!("failed to get utun control info"));
        }

        let mut sc_unit: u32 = 0;
        if let Some(name) = name {
            if let Some(suffix) = name.strip_prefix("utun") {
                if let Ok(unit) = suffix.parse::<u32>() {
                    sc_unit = unit + 1;
                }
            }
        }

        let mut addr: libc::sockaddr_ctl = unsafe { std::mem::zeroed() };
        addr.sc_len = std::mem::size_of::<libc::sockaddr_ctl>() as u8;
        addr.sc_family = libc::AF_SYSTEM as u8;
        addr.ss_sysaddr = libc::AF_SYS_CONTROL as u16;
        addr.sc_id = ctl_info.ctl_id;
        addr.sc_unit = sc_unit;

        let ret = unsafe {
            libc::connect(
                fd,
                &addr as *const libc::sockaddr_ctl as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_ctl>() as u32,
            )
        };
        if ret < 0 {
            unsafe {
                libc::close(fd);
            }
            return Err(anyhow!("failed to connect utun socket"));
        }

        let mut ifname_buf = [0u8; libc::IFNAMSIZ];
        let mut ifname_len = ifname_buf.len() as libc::socklen_t;
        let ret = unsafe {
            libc::getsockopt(
                fd,
                libc::SYSPROTO_CONTROL,
                libc::UTUN_OPT_IFNAME,
                ifname_buf.as_mut_ptr() as *mut _,
                &mut ifname_len,
            )
        };
        if ret < 0 {
            unsafe {
                libc::close(fd);
            }
            return Err(anyhow!("failed to get utun interface name"));
        }

        let ifname = std::str::from_utf8(&ifname_buf[..(ifname_len as usize).saturating_sub(1)])
            .unwrap_or("utun?")
            .to_string();
        tracing::info!(interface = %ifname, "created macOS utun interface");

        let file = unsafe { std::fs::File::from_raw_fd(fd) };
        Ok((tokio::fs::File::from_std(file), ifname))
    }

    #[cfg(target_os = "linux")]
    {
        use std::os::unix::io::FromRawFd;

        let fd = unsafe { libc::open(b"/dev/net/tun\0".as_ptr() as *const _, libc::O_RDWR) };
        if fd < 0 {
            return Err(anyhow!("failed to open /dev/net/tun"));
        }

        let mut ifr: libc::ifreq = unsafe { std::mem::zeroed() };
        ifr.ifr_ifru.ifru_flags = libc::IFF_TUN as libc::c_short | libc::IFF_NO_PI as libc::c_short;

        if let Some(name) = name {
            let name_bytes = name.as_bytes();
            let len = name_bytes.len().min(libc::IFNAMSIZ - 1);
            for (dst, src) in ifr.ifr_name[..len].iter_mut().zip(name_bytes.iter()) {
                *dst = *src as libc::c_char;
            }
        }

        let ret = unsafe { libc::ioctl(fd, libc::TUNSETIFF, &ifr) };
        if ret < 0 {
            unsafe {
                libc::close(fd);
            }
            return Err(anyhow!("failed to set TUN interface name"));
        }

        let actual_name = unsafe {
            let nul_pos = ifr
                .ifr_name
                .iter()
                .position(|&c| c == 0)
                .unwrap_or(ifr.ifr_name.len());
            std::str::from_utf8_unchecked(&std::slice::from_raw_parts(
                ifr.ifr_name.as_ptr() as *const u8,
                nul_pos,
            ))
            .to_string()
        };

        let file = unsafe { std::fs::File::from_raw_fd(fd) };
        Ok((tokio::fs::File::from_std(file), actual_name))
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        Err(anyhow!(
            "native_tun backend is not supported on this platform"
        ))
    }
}

pub fn strip_macos_utun_header(packet: &[u8]) -> anyhow::Result<&[u8]> {
    if packet.len() < MACOS_UTUN_ADDRESS_FAMILY_LEN {
        return Err(anyhow!("packet too short for utun header"));
    }
    Ok(&packet[MACOS_UTUN_ADDRESS_FAMILY_LEN..])
}

pub fn add_macos_utun_header(packet: &[u8]) -> anyhow::Result<Vec<u8>> {
    if packet.is_empty() {
        return Err(anyhow!("empty packet"));
    }
    let version = packet[0] >> 4;
    let af_bytes = match version {
        4 => (libc::AF_INET as u32).to_be_bytes(),
        6 => (libc::AF_INET6 as u32).to_be_bytes(),
        _ => return Err(anyhow!("unknown IP version: {version}")),
    };
    let mut result = Vec::with_capacity(MACOS_UTUN_ADDRESS_FAMILY_LEN + packet.len());
    result.extend_from_slice(&af_bytes);
    result.extend_from_slice(packet);
    Ok(result)
}

pub fn decode_tun_read_packet(raw: &[u8]) -> anyhow::Result<Vec<u8>> {
    #[cfg(target_os = "macos")]
    {
        strip_macos_utun_header(raw).map(|p| p.to_vec())
    }
    #[cfg(target_os = "linux")]
    {
        Ok(raw.to_vec())
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = raw;
        Err(anyhow!("unsupported platform for native tun"))
    }
}

pub fn encode_tun_write_packet(packet: &[u8]) -> anyhow::Result<Vec<u8>> {
    #[cfg(target_os = "macos")]
    {
        add_macos_utun_header(packet)
    }
    #[cfg(target_os = "linux")]
    {
        Ok(packet.to_vec())
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = packet;
        Err(anyhow!("unsupported platform for native tun"))
    }
}

pub fn profile(config: &SuperConfig) -> NativeTunProfile {
    let mut warnings = Vec::new();

    if config.tun.enabled && config.tun.backend == TunBackend::NativeL3 {
        if config.tun.l3_profile.is_none() {
            warnings.push("native_l3 backend requires tun.l3_profile to be set".to_string());
        }

        if !config.tun.setup && config.tun.auto_route {
            warnings.push("auto_route requires tun.setup=true to install routes".to_string());
        }

        if config.tun.dns_strategy != crate::config::TunDnsStrategy::Direct {
            warnings.push("native_l3 backend only supports direct DNS strategy".to_string());
        }

        #[cfg(target_os = "linux")]
        if config.tun.setup {
            warnings.push("native_l3 route setup on Linux is experimental".to_string());
        }
    }

    NativeTunProfile {
        enabled: config.tun.enabled && config.tun.backend == TunBackend::NativeL3,
        backend: "native-l3",
        l3_profile: config.tun.l3_profile.clone(),
        mtu: if config.tun.mtu == 0 {
            1500
        } else {
            config.tun.mtu
        },
        interface_name: config.tun.name.clone(),
        setup_enabled: config.tun.setup,
        auto_route: config.tun.auto_route,
        warnings,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strip_macos_utun_header_ipv4() {
        let mut packet = vec![0x00, 0x00, 0x00, 0x02];
        packet.extend_from_slice(&[0x45, 0x00, 0x00, 0x1c]);
        let stripped = strip_macos_utun_header(&packet).unwrap();
        assert_eq!(stripped, &[0x45, 0x00, 0x00, 0x1c]);
    }

    #[test]
    fn strip_macos_utun_header_ipv6() {
        let mut packet = vec![0x00, 0x00, 0x00, 0x1e];
        packet.extend_from_slice(&[0x60, 0x00, 0x00, 0x00]);
        let stripped = strip_macos_utun_header(&packet).unwrap();
        assert_eq!(stripped, &[0x60, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn strip_macos_utun_header_too_short() {
        let packet = [0x00, 0x00, 0x00];
        assert!(strip_macos_utun_header(&packet).is_err());
    }

    #[test]
    fn add_macos_utun_header_ipv4() {
        let packet = [0x45, 0x00, 0x00, 0x1c];
        let result = add_macos_utun_header(&packet).unwrap();
        assert_eq!(result.len(), 8);
        assert_eq!(&result[..4], &[0x00, 0x00, 0x00, 0x02]);
        assert_eq!(&result[4..], &packet);
    }

    #[test]
    fn add_macos_utun_header_ipv6() {
        let packet = [0x60, 0x00, 0x00, 0x00];
        let result = add_macos_utun_header(&packet).unwrap();
        assert_eq!(result.len(), 8);
        assert_eq!(&result[..4], &[0x00, 0x00, 0x00, 0x1e]);
        assert_eq!(&result[4..], &packet);
    }

    #[test]
    fn add_macos_utun_header_unknown_version() {
        let packet = [0x00, 0x00, 0x00, 0x00];
        assert!(add_macos_utun_header(&packet).is_err());
    }

    #[test]
    fn add_macos_utun_header_empty() {
        let packet = [];
        assert!(add_macos_utun_header(&packet).is_err());
    }

    #[test]
    fn decode_tun_read_packet_strips_header() {
        let mut raw = vec![0x00, 0x00, 0x00, 0x02];
        raw.extend_from_slice(&[0x45, 0x00, 0x00, 0x1c, 0x00, 0x01]);
        let decoded = decode_tun_read_packet(&raw).unwrap();
        assert_eq!(decoded, &[0x45, 0x00, 0x00, 0x1c, 0x00, 0x01]);
    }

    #[test]
    fn decode_tun_read_packet_too_short() {
        let raw = [0x00, 0x00, 0x00];
        assert!(decode_tun_read_packet(&raw).is_err());
    }

    #[test]
    fn encode_tun_write_packet_adds_header_ipv4() {
        let packet = [0x45, 0x00, 0x00, 0x1c];
        let encoded = encode_tun_write_packet(&packet).unwrap();
        assert_eq!(encoded.len(), 8);
        assert_eq!(&encoded[..4], &[0x00, 0x00, 0x00, 0x02]);
        assert_eq!(&encoded[4..], &packet);
    }

    #[test]
    fn encode_tun_write_packet_adds_header_ipv6() {
        let packet = [0x60, 0x00, 0x00, 0x00];
        let encoded = encode_tun_write_packet(&packet).unwrap();
        assert_eq!(encoded.len(), 8);
        assert_eq!(&encoded[..4], &[0x00, 0x00, 0x00, 0x1e]);
        assert_eq!(&encoded[4..], &packet);
    }

    #[test]
    fn encode_tun_write_packet_rejects_empty() {
        assert!(encode_tun_write_packet(&[]).is_err());
    }

    #[test]
    fn encode_tun_write_packet_rejects_unknown_version() {
        assert!(encode_tun_write_packet(&[0x00, 0x00]).is_err());
    }

    #[test]
    fn decode_encode_roundtrip_ipv4() {
        let original = [0x45, 0x00, 0x00, 0x1c, 0x00, 0x01, 0x40, 0x00];
        let encoded = encode_tun_write_packet(&original).unwrap();
        let decoded = decode_tun_read_packet(&encoded).unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn decode_encode_roundtrip_ipv6() {
        let original = [0x60, 0x00, 0x00, 0x00, 0x00, 0x14, 0x06, 0x40];
        let encoded = encode_tun_write_packet(&original).unwrap();
        let decoded = decode_tun_read_packet(&encoded).unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn profile_warns_missing_l3_profile() {
        let config = SuperConfig {
            tun: crate::config::TunConfig {
                enabled: true,
                backend: TunBackend::NativeL3,
                l3_profile: None,
                ..Default::default()
            },
            ..Default::default()
        };
        let p = profile(&config);
        assert!(p.warnings.iter().any(|w| w.contains("l3_profile")));
    }

    #[test]
    fn profile_warns_auto_route_without_setup() {
        let config = SuperConfig {
            tun: crate::config::TunConfig {
                enabled: true,
                backend: TunBackend::NativeL3,
                l3_profile: Some("wg".to_string()),
                setup: false,
                auto_route: true,
                ..Default::default()
            },
            ..Default::default()
        };
        let p = profile(&config);
        assert!(p.warnings.iter().any(|w| w.contains("auto_route")));
    }

    #[test]
    fn profile_no_warn_when_setup_enabled() {
        let config = SuperConfig {
            tun: crate::config::TunConfig {
                enabled: true,
                backend: TunBackend::NativeL3,
                l3_profile: Some("wg".to_string()),
                setup: true,
                auto_route: true,
                bypass: vec!["10.0.0.0/8".to_string()],
                ..Default::default()
            },
            ..Default::default()
        };
        let p = profile(&config);
        assert!(!p.warnings.iter().any(|w| w.contains("route setup")));
        assert!(!p.warnings.iter().any(|w| w.contains("auto_route")));
        assert!(!p.warnings.iter().any(|w| w.contains("bypass")));
    }

    #[test]
    fn config_native_l3_with_l3_profile_parses() {
        let yaml = r#"
tun:
  enabled: true
  backend: native-l3
  l3_profile: my-wireguard
  mtu: 1420
  setup: true
  auto_route: true
  inet4_address:
    - 198.18.0.1/30
l3:
  enabled: true
"#;
        let config: SuperConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.tun.backend, TunBackend::NativeL3);
        assert_eq!(config.tun.l3_profile.as_deref(), Some("my-wireguard"));
        assert_eq!(config.tun.mtu, 1420);
        assert!(config.tun.setup);
        assert!(config.tun.auto_route);
        let p = profile(&config);
        assert!(p.enabled);
        assert_eq!(p.l3_profile.as_deref(), Some("my-wireguard"));
        assert_eq!(p.mtu, 1420);
        assert!(p.setup_enabled);
        assert!(p.auto_route);
    }
}
