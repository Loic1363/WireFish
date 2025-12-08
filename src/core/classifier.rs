use crate::core::models::{Packet, TransportProtocol};

pub fn classify(packet: &Packet) -> String {
    // Si on a une couche transport, on se base dessus
    if let Some(t) = &packet.transport {
        return match t {
            TransportProtocol::Tcp(tcp) => match tcp.dst_port {
                80  => "HTTP".into(),
                443 => "HTTPS".into(),
                22  => "SSH".into(),
                53  => "DNS".into(),
                _   => "TCP".into(),
            },
            TransportProtocol::Udp(udp) => match udp.dst_port {
                53        => "DNS".into(),
                67 | 68   => "DHCP".into(),
                _         => "UDP".into(),
            },
            TransportProtocol::Icmp => "ICMP".into(),
            TransportProtocol::Unknown => "UNK".into(), // <= 3 chars
        };
    }

    // Sinon, on regarde juste l'EtherType
    if let Some(eth) = &packet.eth {
        return match eth.ethertype {
            0x0806 => "ARP".into(),
            0x86DD => "IPV6".into(),   // <= 4 chars
            _      => "OTHER".into(), // <= 5 chars
        };
    }

    "OTHER".into()
}
