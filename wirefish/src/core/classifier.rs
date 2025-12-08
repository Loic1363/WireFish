use crate::core::models::*;

pub fn classify(packet: &Packet) -> String {
    match &packet.transport {
        Some(TransportProtocol::Tcp(t)) => {
            match t.dst_port {
                80  => "HTTP".into(),
                443 => "HTTPS".into(),
                22  => "SSH".into(),
                53  => "DNS-over-TCP".into(),
                _   => "TCP".into(),
            }
        }

        Some(TransportProtocol::Udp(u)) => {
            match u.dst_port {
                53 => "DNS".into(),
                67 | 68 => "DHCP".into(),
                _ => "UDP".into(),
            }
        }

        Some(TransportProtocol::Icmp) => "ICMP".into(),
        _ => "Unknown".into(),
    }
}
