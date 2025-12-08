use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::core::models::Packet;

const STORAGE_FILE: &str = "wirefish_packets.jsonl";

#[derive(Serialize, Deserialize, Debug)]
pub struct InspectRecord {
    pub id: u64,
    pub iface: String,
    pub proto: String,
    pub src_ip: String,
    pub dst_ip: String,
    pub size: usize,
    pub payload: Vec<u8>,
}

pub fn reset_storage() {
    if let Err(e) = OpenOptions::new()
        .write(true)
        .truncate(true)
        .create(true)
        .open(STORAGE_FILE)
    {
        eprintln!("[storage] Impossible de réinitialiser {STORAGE_FILE}: {e}");
    }
}

pub fn save_packet_for_inspect(
    id: u64,
    iface: &str,
    proto: &str,
    packet: &Packet,
) {
    let (src, dst) = if let Some(ip) = &packet.ip {
        (ip.src_ip.clone(), ip.dst_ip.clone())
    } else {
        ("?".to_string(), "?".to_string())
    };

    let rec = InspectRecord {
        id,
        iface: iface.to_string(),
        proto: proto.to_string(),
        src_ip: src,
        dst_ip: dst,
        size: packet.payload.len(),
        payload: packet.payload.clone(), 
    };

    if let Err(e) = append_record(&rec) {
        eprintln!("⚠️ [storage] Impossible d’enregistrer le paquet #{id}: {e}");
    }
}

fn append_record(rec: &InspectRecord) -> std::io::Result<()> {
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(STORAGE_FILE)?;
    let line = serde_json::to_string(rec).unwrap();
    writeln!(file, "{}", line)?;
    Ok(())
}

pub fn inspect_packet(id: u64) {
    if !Path::new(STORAGE_FILE).exists() {
        eprintln!("❌ Aucun fichier de capture trouvé ({STORAGE_FILE}). Lance d’abord une capture.");
        return;
    }

    let file = match File::open(STORAGE_FILE) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("Impossible d’ouvrir {STORAGE_FILE}: {e}");
            return;
        }
    };

    let reader = BufReader::new(file);
    for line in reader.lines() {
        if let Ok(line) = line {
            if line.trim().is_empty() {
                continue;
            }

            let rec: InspectRecord = match serde_json::from_str(&line) {
                Ok(r) => r,
                Err(_) => continue,
            };

            if rec.id == id {
                print_record(&rec);
                return;
            }
        }
    }

    eprintln!("Paquet #{id} introuvable dans {STORAGE_FILE}");
}

fn print_record(rec: &InspectRecord) {
    println!();
    println!("══════════════════════════════════════════════════════════════════════");
    println!(" WireFish - Détail paquet #{}", rec.id);
    println!("══════════════════════════════════════════════════════════════════════");
    println!("[Général]");
    println!("  Interface   : {}", rec.iface);
    println!("  Protocole   : {}", rec.proto);
    println!("  Longueur    : {} octets", rec.size);
    println!("  Source IP   : {}", rec.src_ip);
    println!("  Dest IP     : {}", rec.dst_ip);

    println!("\n[Analyse L3/L4]");
    analyze_layers(&rec.payload);

    println!("\n[Hexdump + ASCII]");
    hex_dump(&rec.payload);
    println!("══════════════════════════════════════════════════════════════════════");
}

fn analyze_layers(data: &[u8]) {
    if data.is_empty() {
        println!("  (Pas de payload)");
        return;
    }

    let version = data[0] >> 4;
    match version {
        4 => analyze_ipv4(data),
        6 => analyze_ipv6(data),
        _ => {
            println!("  Format inconnu (byte[0] = 0x{:02x})", data[0]);
        }
    }
}

fn analyze_ipv4(data: &[u8]) {
    if data.len() < 20 {
        println!("  IPv4 header tronqué ({} octets)", data.len());
        return;
    }

    let ihl = (data[0] & 0x0f) as usize;
    let header_len = ihl * 4;
    if data.len() < header_len {
        println!("  IPv4 header incomplet (IHL={ihl}, len={})", data.len());
        return;
    }

    let total_len = u16::from_be_bytes([data[2], data[3]]);
    let ttl = data[8];
    let proto = data[9];

    let src = std::net::Ipv4Addr::new(data[12], data[13], data[14], data[15]);
    let dst = std::net::Ipv4Addr::new(data[16], data[17], data[18], data[19]);

    println!("  IPv4 :");
    println!("    Version        : 4");
    println!("    IHL            : {} ({} octets)", ihl, header_len);
    println!("    Total length   : {}", total_len);
    println!("    TTL            : {}", ttl);
    println!("    Protocol (L4)  : {}{}", proto, match proto {
        6 => " (TCP)",
        17 => " (UDP)",
        1 => " (ICMP)",
        _ => "",
    });
    println!("    Src            : {}", src);
    println!("    Dst            : {}", dst);

    if proto == 6 {
        analyze_tcp(&data[header_len..]);
    } else if proto == 17 {
        analyze_udp(&data[header_len..]);
    }
}

fn analyze_ipv6(data: &[u8]) {
    if data.len() < 40 {
        println!("  IPv6 header tronqué ({} octets)", data.len());
        return;
    }

    let traffic_class = ((data[0] & 0x0f) << 4) | (data[1] >> 4);
    let flow_label =
        ((data[1] as u32 & 0x0f) << 16) | ((data[2] as u32) << 8) | data[3] as u32;
    let payload_len = u16::from_be_bytes([data[4], data[5]]);
    let next_header = data[6];
    let hop_limit = data[7];

    use std::net::Ipv6Addr;
    let src = Ipv6Addr::from(<[u8; 16]>::try_from(&data[8..24]).unwrap());
    let dst = Ipv6Addr::from(<[u8; 16]>::try_from(&data[24..40]).unwrap());

    println!("  IPv6 :");
    println!("    Version        : 6");
    println!("    Traffic class  : 0x{:02x}", traffic_class);
    println!("    Flow label     : 0x{:05x}", flow_label);
    println!("    Payload length : {}", payload_len);
    println!("    Next header    : {}{}", next_header, match next_header {
        6 => " (TCP)",
        17 => " (UDP)",
        58 => " (ICMPv6)",
        _ => "",
    });
    println!("    Hop limit      : {}", hop_limit);
    println!("    Src            : {}", src);
    println!("    Dst            : {}", dst);

    let l4 = &data[40..];
    if next_header == 6 {
        analyze_tcp(l4);
    } else if next_header == 17 {
        analyze_udp(l4);
    }
}

fn analyze_tcp(data: &[u8]) {
    if data.len() < 20 {
        println!("  TCP header tronqué ({} octets)", data.len());
        return;
    }

    let src_port = u16::from_be_bytes([data[0], data[1]]);
    let dst_port = u16::from_be_bytes([data[2], data[3]]);
    let seq = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
    let ack = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);
    let data_offset = (data[12] >> 4) as usize;
    let flags = data[13];

    println!("  TCP :");
    println!("    Src port       : {}", src_port);
    println!("    Dst port       : {}", dst_port);
    println!("    Seq            : {}", seq);
    println!("    Ack            : {}", ack);
    println!("    Data offset    : {} ({} octets)", data_offset, data_offset * 4);
    println!("    Flags          : 0x{:02x}", flags);
}

fn analyze_udp(data: &[u8]) {
    if data.len() < 8 {
        println!("  UDP header tronqué ({} octets)", data.len());
        return;
    }

    let src_port = u16::from_be_bytes([data[0], data[1]]);
    let dst_port = u16::from_be_bytes([data[2], data[3]]);
    let len = u16::from_be_bytes([data[4], data[5]]);

    println!("  UDP :");
    println!("    Src port       : {}", src_port);
    println!("    Dst port       : {}", dst_port);
    println!("    Length         : {}", len);
}

fn hex_dump(data: &[u8]) {
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

        for &b in chunk {
            let c = if b.is_ascii_graphic() || b == b' ' {
                b as char
            } else {
                '.'
            };
            print!("{}", c);
        }

        println!();
        offset += 16;
    }
}
