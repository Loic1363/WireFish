use crate::core::models::*;

pub fn parse_packet(raw: &[u8]) -> Option<Packet> {
    if raw.len() < 14 {
        return None;
    }

    // Ethernet header
    let ethertype = u16::from_be_bytes([raw[12], raw[13]]);

    let eth = EthernetHeader {
        src_mac: format!("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            raw[6], raw[7], raw[8], raw[9], raw[10], raw[11]),
        dst_mac: format!("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            raw[0], raw[1], raw[2], raw[3], raw[4], raw[5]),
        ethertype,
    };

    // Simple IPv4 parsing
    if ethertype == 0x0800 && raw.len() >= 34 {
        let src_ip = format!("{}.{}.{}.{}",
            raw[26], raw[27], raw[28], raw[29]);
        let dst_ip = format!("{}.{}.{}.{}",
            raw[30], raw[31], raw[32], raw[33]);

        let protocol = raw[23];

        let ip_header = IpHeader {
            src_ip,
            dst_ip,
            protocol,
        };

        let transport = match protocol {
            6  => parse_tcp(raw),
            17 => parse_udp(raw),
            1  => Some(TransportProtocol::Icmp),
            _  => Some(TransportProtocol::Unknown)
        };

        return Some(Packet {
            timestamp: chrono::Utc::now().timestamp_millis() as u128,
            eth: Some(eth),
            ip: Some(ip_header),
            transport,
            payload: raw.to_vec(),
        });
    }

    None
}

fn parse_tcp(raw: &[u8]) -> Option<TransportProtocol> {
    let src_port = u16::from_be_bytes([raw[34], raw[35]]);
    let dst_port = u16::from_be_bytes([raw[36], raw[37]]);
    let flags = raw[47];

    Some(TransportProtocol::Tcp(TcpHeader {
        src_port,
        dst_port,
        flags,
    }))
}

fn parse_udp(raw: &[u8]) -> Option<TransportProtocol> {
    let src_port = u16::from_be_bytes([raw[34], raw[35]]);
    let dst_port = u16::from_be_bytes([raw[36], raw[37]]);

    Some(TransportProtocol::Udp(UdpHeader {
        src_port,
        dst_port,
    }))
}
