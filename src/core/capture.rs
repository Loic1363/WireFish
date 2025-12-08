use pcap::{Capture, Device, Error};
use crossbeam::channel::Sender;
use crate::core::parser::parse_packet;
use crate::core::models::Packet;
use std::time::{Duration, Instant};

pub fn list_devices() -> Vec<String> {
    Device::list()
        .unwrap_or_default()
        .into_iter()
        .map(|d| d.name)
        .collect()
}

/// Petit scan de trafic : on écoute `duration_ms` ms et on compte les paquets
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
                // Pas grave, juste pas de paquet sur ce tick
                continue;
            }
            Err(_) => {
                // Autre erreur → on arrête
                break;
            }
        }
    }

    count
}

pub fn capture_on(device_name: &str, sender: Sender<Packet>) {
    let mut cap = Capture::from_device(device_name)
        .unwrap()
        .promisc(true)
        .timeout(1000)
        .snaplen(65535)
        .open()
        .unwrap();

    println!("🔁 [DEBUG] Capture loop started on {device_name}");

    loop {
        match cap.next_packet() {
            Ok(packet) => {
                println!(
                    "🟢 [DEBUG] paquet brut capturé: {} octets",
                    packet.data.len()
                );

                if let Some(parsed) = parse_packet(&packet.data) {
                    let _ = sender.send(parsed);
                }
            }
            Err(Error::TimeoutExpired) => {
                // Juste un timeout, pas mortel
                continue;
            }
            Err(e) => {
                eprintln!("🔴 [DEBUG] erreur capture sur {device_name}: {e}");
                break;
            }
        }
    }
}
