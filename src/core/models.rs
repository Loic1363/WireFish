use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Packet {
    pub timestamp: u128,
    pub eth: Option<EthernetHeader>,
    pub ip: Option<IpHeader>,
    pub transport: Option<TransportProtocol>, 
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EthernetHeader {
    pub src_mac: String,
    pub dst_mac: String,
    pub ethertype: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpHeader {
    pub src_ip: String,
    pub dst_ip: String,
    pub protocol: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TransportProtocol {
    Tcp(TcpHeader),
    Udp(UdpHeader),
    Icmp,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TcpHeader {
    pub src_port: u16,
    pub dst_port: u16,
    pub flags: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UdpHeader {
    pub src_port: u16,
    pub dst_port: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(dead_code)]
pub struct IpReputation {
    pub ip: String,
    pub country: Option<String>,
    pub score: u32, // 0 = safe, 100 = malicious
    pub tags: Vec<String>,
}
