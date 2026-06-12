use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::Instant;

use smoltcp::iface::{Interface, SocketHandle, SocketSet};
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::tcp::{self, Socket as TcpSocket, SocketBuffer as TcpSocketBuffer};
use smoltcp::socket::udp::{self, PacketBuffer as UdpPacketBuffer, Socket as UdpSocket};
use smoltcp::storage::PacketMetadata;
use smoltcp::time::Instant as SmolInstant;
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr, IpEndpoint};

use super::native_tun_flow::FlowKey;

const TCP_RX_BUFFER_SIZE: usize = 65536;
const TCP_TX_BUFFER_SIZE: usize = 65536;
const UDP_BUFFER_SIZE: usize = 1500;
const UDP_METADATA_COUNT: usize = 64;

pub struct NativeTunStack {
    iface: Interface,
    sockets: SocketSet<'static>,
    rx_packets: Vec<Vec<u8>>,
    tx_packets: Vec<Vec<u8>>,
    tcp_handles: HashMap<FlowKey, SocketHandle>,
    udp_handles: HashMap<FlowKey, SocketHandle>,
}

struct TunDevice<'a> {
    rx: &'a mut Vec<Vec<u8>>,
    tx: &'a mut Vec<Vec<u8>>,
}

impl<'a> Device for TunDevice<'a> {
    type RxToken<'b>
        = TunRxToken<'b>
    where
        Self: 'b;
    type TxToken<'b>
        = TunTxToken<'b>
    where
        Self: 'b;

    fn receive(
        &mut self,
        _timestamp: SmolInstant,
    ) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        if self.rx.is_empty() {
            return None;
        }
        Some((
            TunRxToken { packets: self.rx },
            TunTxToken { packets: self.tx },
        ))
    }

    fn transmit(&mut self, _timestamp: SmolInstant) -> Option<Self::TxToken<'_>> {
        Some(TunTxToken { packets: self.tx })
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.max_transmission_unit = 1500;
        caps.medium = Medium::Ip;
        caps
    }
}

struct TunRxToken<'a> {
    packets: &'a mut Vec<Vec<u8>>,
}

impl<'a> RxToken for TunRxToken<'a> {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        let packet = self.packets.remove(0);
        f(&packet)
    }
}

struct TunTxToken<'a> {
    packets: &'a mut Vec<Vec<u8>>,
}

impl<'a> TxToken for TunTxToken<'a> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut buf = vec![0u8; len];
        let result = f(&mut buf);
        self.packets.push(buf);
        result
    }
}

#[derive(Debug)]
pub enum StackEvent {
    TcpSynReceived {
        flow_key: FlowKey,
        local_endpoint: IpEndpoint,
        remote_endpoint: IpEndpoint,
    },
    TcpData {
        flow_key: FlowKey,
        data: Vec<u8>,
    },
    TcpClosed {
        flow_key: FlowKey,
    },
    UdpDatagram {
        flow_key: FlowKey,
        data: Vec<u8>,
        src_endpoint: IpEndpoint,
        dst_endpoint: IpEndpoint,
    },
}

impl NativeTunStack {
    pub fn new() -> Self {
        let mut rx_packets = Vec::new();
        let mut tx_packets = Vec::new();

        let mut device = TunDevice {
            rx: &mut rx_packets,
            tx: &mut tx_packets,
        };

        let config = smoltcp::iface::Config::new(HardwareAddress::Ip);
        let iface = Interface::new(config, &mut device, SmolInstant::from_micros(0));
        let sockets = SocketSet::new(vec![]);

        Self {
            iface,
            sockets,
            rx_packets,
            tx_packets,
            tcp_handles: HashMap::new(),
            udp_handles: HashMap::new(),
        }
    }

    pub fn add_address(&mut self, cidr: IpCidr) {
        self.iface.update_ip_addrs(|addrs| {
            if !addrs.iter().any(|a| a == &cidr) {
                addrs.push(cidr).ok();
            }
        });
    }

    pub fn inject_packet(&mut self, packet: Vec<u8>) {
        self.rx_packets.push(packet);
    }

    pub fn poll(&mut self, now: Instant) -> Vec<StackEvent> {
        let timestamp = SmolInstant::from_micros(now.elapsed().as_micros() as i64);
        let mut events = Vec::new();

        {
            let mut device = TunDevice {
                rx: &mut self.rx_packets,
                tx: &mut self.tx_packets,
            };
            self.iface.poll(timestamp, &mut device, &mut self.sockets);
        }

        self.process_tcp_events(&mut events);

        events
    }

    pub fn take_pending_writes(&mut self) -> Vec<Vec<u8>> {
        std::mem::take(&mut self.tx_packets)
    }

    pub fn create_tcp_socket(&mut self, flow_key: FlowKey, _local_port: u16) -> SocketHandle {
        let rx_buf = TcpSocketBuffer::new(vec![0; TCP_RX_BUFFER_SIZE]);
        let tx_buf = TcpSocketBuffer::new(vec![0; TCP_TX_BUFFER_SIZE]);
        let socket = TcpSocket::new(rx_buf, tx_buf);
        let handle = self.sockets.add(socket);
        self.tcp_handles.insert(flow_key, handle);
        handle
    }

    pub fn create_udp_socket(&mut self, flow_key: FlowKey, local_port: u16) -> SocketHandle {
        let rx_meta: Vec<PacketMetadata<udp::UdpMetadata>> =
            vec![PacketMetadata::EMPTY; UDP_METADATA_COUNT];
        let rx_buf = UdpPacketBuffer::new(rx_meta, vec![0u8; UDP_BUFFER_SIZE]);
        let tx_meta: Vec<PacketMetadata<udp::UdpMetadata>> =
            vec![PacketMetadata::EMPTY; UDP_METADATA_COUNT];
        let tx_buf = UdpPacketBuffer::new(tx_meta, vec![0u8; UDP_BUFFER_SIZE]);
        let mut socket = UdpSocket::new(rx_buf, tx_buf);
        let endpoint = IpEndpoint::new(IpAddress::v4(0, 0, 0, 0), local_port);
        socket.bind(endpoint).ok();
        let handle = self.sockets.add(socket);
        self.udp_handles.insert(flow_key, handle);
        handle
    }

    pub fn tcp_connect(
        &mut self,
        handle: SocketHandle,
        local_port: u16,
        remote: IpEndpoint,
    ) -> Result<(), String> {
        let cx = self.iface.context();
        let socket = self.sockets.get_mut::<TcpSocket>(handle);
        socket
            .connect(cx, remote, local_port)
            .map_err(|e| format!("tcp connect: {:?}", e))
    }

    pub fn tcp_send(&mut self, handle: SocketHandle, data: &[u8]) {
        let _ = self.sockets.get_mut::<TcpSocket>(handle).send_slice(data);
    }

    pub fn tcp_recv(&mut self, handle: SocketHandle) -> Vec<u8> {
        let socket = self.sockets.get_mut::<TcpSocket>(handle);
        let mut buf = vec![0u8; TCP_RX_BUFFER_SIZE];
        match socket.recv_slice(&mut buf) {
            Ok(n) if n > 0 => {
                buf.truncate(n);
                buf
            }
            _ => Vec::new(),
        }
    }

    pub fn tcp_may_send(&self, handle: SocketHandle) -> bool {
        self.sockets.get::<TcpSocket>(handle).may_send()
    }

    pub fn tcp_may_recv(&self, handle: SocketHandle) -> bool {
        self.sockets.get::<TcpSocket>(handle).may_recv()
    }

    pub fn tcp_close(&mut self, handle: SocketHandle) {
        self.sockets.get_mut::<TcpSocket>(handle).close();
    }

    pub fn tcp_abort(&mut self, handle: SocketHandle) {
        self.sockets.get_mut::<TcpSocket>(handle).abort();
    }

    pub fn tcp_state(&self, handle: SocketHandle) -> tcp::State {
        self.sockets.get::<TcpSocket>(handle).state()
    }

    pub fn udp_send(&mut self, handle: SocketHandle, data: &[u8], dst: IpEndpoint) {
        let _ = self
            .sockets
            .get_mut::<UdpSocket>(handle)
            .send_slice(data, dst);
    }

    pub fn udp_recv(&mut self, handle: SocketHandle) -> Option<(Vec<u8>, IpEndpoint)> {
        let socket = self.sockets.get_mut::<UdpSocket>(handle);
        let mut buf = vec![0u8; UDP_BUFFER_SIZE];
        match socket.recv_slice(&mut buf) {
            Ok((n, meta)) => {
                buf.truncate(n);
                Some((buf, meta.endpoint))
            }
            Err(_) => None,
        }
    }

    pub fn tcp_handles(&self) -> &HashMap<FlowKey, SocketHandle> {
        &self.tcp_handles
    }

    pub fn udp_handles(&self) -> &HashMap<FlowKey, SocketHandle> {
        &self.udp_handles
    }

    pub fn remove_socket(&mut self, handle: SocketHandle) {
        self.sockets.remove(handle);
        self.tcp_handles.retain(|_, h| *h != handle);
        self.udp_handles.retain(|_, h| *h != handle);
    }

    fn process_tcp_events(&mut self, events: &mut Vec<StackEvent>) {
        let handles: Vec<(FlowKey, SocketHandle)> = self
            .tcp_handles
            .iter()
            .map(|(k, h)| (k.clone(), *h))
            .collect();

        for (flow_key, handle) in handles {
            let state = self.sockets.get::<TcpSocket>(handle).state();

            match state {
                tcp::State::SynReceived => {
                    let socket = self.sockets.get::<TcpSocket>(handle);
                    let local = socket
                        .local_endpoint()
                        .unwrap_or(IpEndpoint::new(IpAddress::v4(0, 0, 0, 0), 0));
                    let remote = socket
                        .remote_endpoint()
                        .unwrap_or(IpEndpoint::new(IpAddress::v4(0, 0, 0, 0), 0));
                    events.push(StackEvent::TcpSynReceived {
                        flow_key,
                        local_endpoint: local,
                        remote_endpoint: remote,
                    });
                }
                tcp::State::Established => {
                    let data = self.tcp_recv(handle);
                    if !data.is_empty() {
                        events.push(StackEvent::TcpData {
                            flow_key: flow_key.clone(),
                            data,
                        });
                    }
                }
                tcp::State::CloseWait | tcp::State::Closed | tcp::State::TimeWait => {
                    events.push(StackEvent::TcpClosed { flow_key });
                }
                _ => {}
            }
        }
    }
}

pub fn socket_addr_to_endpoint(addr: SocketAddr) -> IpEndpoint {
    addr.into()
}

pub fn endpoint_to_socket_addr(ep: IpEndpoint) -> SocketAddr {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    let ip: IpAddr = match ep.addr {
        IpAddress::Ipv4(v4) => IpAddr::V4(Ipv4Addr::from(v4.octets())),
        IpAddress::Ipv6(v6) => IpAddr::V6(Ipv6Addr::from(v6.octets())),
    };
    SocketAddr::new(ip, ep.port)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inbound::native_tun_flow::FlowProtocol;

    #[test]
    fn stack_creation() {
        let stack = NativeTunStack::new();
        assert!(stack.tx_packets.is_empty());
        assert!(stack.tcp_handles.is_empty());
        assert!(stack.udp_handles.is_empty());
    }

    #[test]
    fn tcp_socket_creation() {
        let mut stack = NativeTunStack::new();
        let flow_key = FlowKey {
            protocol: FlowProtocol::Tcp,
            src: "10.0.0.1:12345".parse().unwrap(),
            dst: "1.2.3.4:443".parse().unwrap(),
        };
        let _handle = stack.create_tcp_socket(flow_key.clone(), 12345);
        assert!(stack.tcp_handles.contains_key(&flow_key));
    }

    #[test]
    fn udp_socket_creation() {
        let mut stack = NativeTunStack::new();
        let flow_key = FlowKey {
            protocol: FlowProtocol::Udp,
            src: "10.0.0.1:12345".parse().unwrap(),
            dst: "8.8.8.8:53".parse().unwrap(),
        };
        let _handle = stack.create_udp_socket(flow_key.clone(), 12345);
        assert!(stack.udp_handles.contains_key(&flow_key));
    }

    #[test]
    fn endpoint_conversion_roundtrip() {
        let addr: SocketAddr = "1.2.3.4:443".parse().unwrap();
        let ep = socket_addr_to_endpoint(addr);
        let back = endpoint_to_socket_addr(ep);
        assert_eq!(addr, back);
    }

    #[test]
    fn inject_and_poll_no_crash() {
        let mut stack = NativeTunStack::new();
        let fake_ip = vec![
            0x45, 0x00, 0x00, 0x14, 0, 0, 0, 0, 64, 6, 0, 0, 10, 0, 0, 1, 1, 2, 3, 4,
        ];
        stack.inject_packet(fake_ip);
        let events = stack.poll(Instant::now());
        assert!(events.is_empty());
    }
}
