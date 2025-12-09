use crate::core::models::{Packet, TransportProtocol};

fn looks_like_tls(payload: &[u8]) -> bool {
    if payload.len() < 5 {
        return false;
    }
    payload[0] == 0x16 && payload[1] == 0x03
}

fn is_tls12(payload: &[u8]) -> bool {
    if payload.len() < 3 {
        return false;
    }
    payload[0] == 0x16 && payload[1] == 0x03 && payload[2] == 0x03
}

fn is_tls13(payload: &[u8]) -> bool {
    if payload.len() < 3 {
        return false;
    }
    payload[0] == 0x16 && payload[1] == 0x03 && payload[2] == 0x04
}

pub fn classify(packet: &Packet) -> &'static str {
    if let Some(eth) = &packet.eth {
        match eth.ethertype {
            0x0806 => return "ARP",
            0x88CC => return "LLDP",
            _ => {}
        }
    }

    let (src_port, dst_port) = match &packet.transport {
        Some(TransportProtocol::Tcp(t)) => (Some(t.src_port), Some(t.dst_port)),
        Some(TransportProtocol::Udp(u)) => (Some(u.src_port), Some(u.dst_port)),
        _ => (None, None),
    };

    let l4_proto = packet.ip.as_ref().map(|ip| ip.protocol);

    if let Some(proto) = l4_proto {
        match proto {
            1 => return "ICMP",
            2 => return "IGMPv2",
            58 => return "ICMPv6",

            6 => {
                if let (Some(sport), Some(dport)) = (src_port, dst_port) {
                    let (minp, maxp) = if sport < dport {
                        (sport, dport)
                    } else {
                        (dport, sport)
                    };

                    if minp == 53 {
                        return "DNS";
                    }
                    if minp == 80 || maxp == 80 {
                        return "HTTP";
                    }
                    if minp == 443 || maxp == 443 {
                        if is_tls13(&packet.payload) {
                            return "TLSv1.3";
                        }
                        if is_tls12(&packet.payload) {
                            return "TLSv1.2";
                        }
                        if looks_like_tls(&packet.payload) {
                            return "TLS";
                        }
                        return "HTTPS";
                    }
                }
                return "TCP";
            }

            17 => {
                if let (Some(sport), Some(dport)) = (src_port, dst_port) {
                    let (minp, _) = if sport < dport {
                        (sport, dport)
                    } else {
                        (dport, sport)
                    };

                    return match minp {
                        53 => "DNS",
                        67 | 68 => "DHCP",
                        123 => "NTP",
                        137 => "NBNS",
                        1900 => "SSDP",
                        5353 => "mDNS",
                        443 => "QUIC",
                        _ => "UDP",
                    };
                }
                return "UDP";
            }

            _ => {
                if let Some(ip) = &packet.ip {
                    if ip.src_ip.contains(':') || ip.dst_ip.contains(':') {
                        return "IPV6";
                    }
                    return "IPV4";
                }
            }
        }
    }

    "OTHER"
}
