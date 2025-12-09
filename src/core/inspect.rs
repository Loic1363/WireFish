use std::time::{Duration, UNIX_EPOCH};

use crate::core::classifier;
use crate::core::models::{Packet, TransportProtocol};

fn format_timestamp_ms(ts_ms: u128) -> String {
    let ts_ms = ts_ms as u64;
    let secs = ts_ms / 1000;
    let millis = ts_ms % 1000;
    let t = UNIX_EPOCH + Duration::from_secs(secs);
    let datetime: chrono::DateTime<chrono::Utc> = t.into();
    format!("{}.{:03}", datetime.format("%Y-%m-%d %H:%M:%S"), millis)
}

fn hexdump(data: &[u8]) {
    let mut offset = 0usize;
    for chunk in data.chunks(16) {
        print!("{:04x}  ", offset);

        for i in 0..16 {
            if i < chunk.len() {
                print!("{:02x} ", chunk[i]);
            } else {
                print!("   ");
            }
            if i == 7 {
                print!(" ");
            }
        }

        print!("  ");

        for b in chunk {
            let c = if b.is_ascii_graphic() || *b == b' ' {
                *b as char
            } else {
                '.'
            };
            print!("{}", c);
        }

        println!();
        offset += 16;
    }
}

pub fn print_packet_details(index: u64, p: &Packet) {
    let length = p.payload.len();

    println!(
        "Frame {}: {} bytes captured ({} bits)",
        index,
        length,
        length as u64 * 8
    );
    println!("  Arrival Time: {}", format_timestamp_ms(p.timestamp));
    println!("  Payload Length: {} bytes", length);

    if let Some(eth) = &p.eth {
        println!();
        println!("Ethernet II");
        println!("  Source:      {}", eth.src_mac);
        println!("  Destination: {}", eth.dst_mac);
        println!("  Type:        0x{:04x}", eth.ethertype);
    }

    if let Some(ip) = &p.ip {
        println!();
        let version = if ip.src_ip.contains(':') || ip.dst_ip.contains(':') {
            6
        } else {
            4
        };
        println!("Internet Protocol Version {}", version);
        println!("  Source IP:      {}", ip.src_ip);
        println!("  Destination IP: {}", ip.dst_ip);
        println!("  Protocol:       {}", ip.protocol);
    }

    if let Some(tp) = &p.transport {
        println!();
        match tp {
            TransportProtocol::Tcp(t) => {
                println!("Transmission Control Protocol");
                println!("  Source Port:      {}", t.src_port);
                println!("  Destination Port: {}", t.dst_port);
                println!("  Flags:            0x{:02x}", t.flags);
            }
            TransportProtocol::Udp(u) => {
                println!("User Datagram Protocol");
                println!("  Source Port:      {}", u.src_port);
                println!("  Destination Port: {}", u.dst_port);
            }
            TransportProtocol::Icmp => {
                println!("Internet Control Message Protocol");
            }
            TransportProtocol::Unknown => {
                println!("Transport: Unknown");
            }
        }
    }

    println!();
    println!("High-level protocol: {}", classifier::classify(p));

    println!();
    println!("Data ({} bytes):", length);
    hexdump(&p.payload);
}
