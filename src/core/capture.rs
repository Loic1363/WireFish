use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::{Duration, Instant};

use pcap::{Capture, Device, Error};
use crossbeam::channel::Sender;

use crate::core::parser::parse_packet;
use crate::core::models::{Packet, IpHeader};

pub fn list_devices() -> Vec<String> {
    Device::list()
        .unwrap_or_default()
        .into_iter()
        .map(|d| d.name)
        .collect()
}

pub fn quick_peek(device_name: &str, duration_ms: u64) -> usize {
    let mut cap = match Capture::from_device(device_name)
        .and_then(|d| d.promisc(true).timeout(200).snaplen(65535).open())
    {
        Ok(c) => c,
        Err(_) => return 0,
    };

    let start = Instant::now();
    let mut count = 0;

    while start.elapsed() < Duration::from_millis(duration_ms) {
        match cap.next_packet() {
            Ok(_pkt) => {
                count += 1;
            }
            Err(Error::TimeoutExpired) => {
                continue;
            }
            Err(_) => {
                break;
            }
        }
    }

    count
}

fn fill_ip_from_l3(packet: &mut Packet, ether_type: u16, data: &[u8]) {
    match ether_type {
        0x0800 => {
            // IPv4
            if data.len() >= 34 {
                let ip_start = 14;
                let ihl = (data[ip_start] & 0x0f) as usize;
                let header_len = ihl * 4;

                if data.len() >= ip_start + header_len {
                    let proto = data[ip_start + 9];

                    let src = Ipv4Addr::new(
                        data[ip_start + 12],
                        data[ip_start + 13],
                        data[ip_start + 14],
                        data[ip_start + 15],
                    );
                    let dst = Ipv4Addr::new(
                        data[ip_start + 16],
                        data[ip_start + 17],
                        data[ip_start + 18],
                        data[ip_start + 19],
                    );

                    packet.ip = Some(IpHeader {
                        src_ip: src.to_string(),
                        dst_ip: dst.to_string(),
                        protocol: proto,
                    });
                }
            }
        }

        0x86DD => {
            if data.len() >= 14 + 40 {
                let ip_start = 14;
                let next_header = data[ip_start + 6];

                let src = Ipv6Addr::from([
                    data[ip_start + 8],  data[ip_start + 9],  data[ip_start + 10], data[ip_start + 11],
                    data[ip_start + 12], data[ip_start + 13], data[ip_start + 14], data[ip_start + 15],
                    data[ip_start + 16], data[ip_start + 17], data[ip_start + 18], data[ip_start + 19],
                    data[ip_start + 20], data[ip_start + 21], data[ip_start + 22], data[ip_start + 23],
                ]);
                let dst = Ipv6Addr::from([
                    data[ip_start + 24], data[ip_start + 25], data[ip_start + 26], data[ip_start + 27],
                    data[ip_start + 28], data[ip_start + 29], data[ip_start + 30], data[ip_start + 31],
                    data[ip_start + 32], data[ip_start + 33], data[ip_start + 34], data[ip_start + 35],
                    data[ip_start + 36], data[ip_start + 37], data[ip_start + 38], data[ip_start + 39],
                ]);

                packet.ip = Some(IpHeader {
                    src_ip: src.to_string(),
                    dst_ip: dst.to_string(),
                    protocol: next_header, 
                });
            }
        }

        0x0806 => {
            if data.len() >= 14 + 28 {
                let arp_start = 14;
                let sender_ip = Ipv4Addr::new(
                    data[arp_start + 14],
                    data[arp_start + 15],
                    data[arp_start + 16],
                    data[arp_start + 17],
                );
                let target_ip = Ipv4Addr::new(
                    data[arp_start + 24],
                    data[arp_start + 25],
                    data[arp_start + 26],
                    data[arp_start + 27],
                );

                packet.ip = Some(IpHeader {
                    src_ip: sender_ip.to_string(),
                    dst_ip: target_ip.to_string(),
                    protocol: 0,
                });
            }
        }

        _ => {
        }
    }
}

pub fn capture_on(device_name: &str, sender: Sender<Packet>, debug: bool) {
    let mut cap = Capture::from_device(device_name)
        .unwrap()
        .promisc(true)
        .timeout(1000)
        .snaplen(65535)
        .open()
        .unwrap();

    if debug {
        println!("🔁 [DEBUG] Capture loop started on {device_name}");
    }

    loop {
        match cap.next_packet() {
            Ok(packet) => {
                let data = &packet.data;

                if debug {
                    println!("[DEBUG] paquet brut capturé: {} octets", data.len());
                }

                if let Some(mut parsed) = parse_packet(data) {
                    if data.len() >= 14 {
                        let ether_type = u16::from_be_bytes([data[12], data[13]]);
                        fill_ip_from_l3(&mut parsed, ether_type, data);
                    }

                    let _ = sender.send(parsed);
                }
            }
            Err(Error::TimeoutExpired) => continue,
            Err(e) => {
                eprintln!("Erreur capture sur {device_name}: {e}");
                break;
            }
        }
    }
}
