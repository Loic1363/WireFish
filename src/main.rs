mod core;

use crossbeam::channel::{unbounded, Receiver};
use core::models::Packet;
use core::{capture, classifier, enrichment};
use std::thread;
use std::time::Duration;

fn listen_to_packets(rx: Receiver<Packet>) {
    println!("🚀 WireFish started! Listening for packets...");

    for packet in rx.iter() {
        // classification
        let proto = classifier::classify(&packet);

        // enrichissement (IP source)
        let rep = packet.ip.as_ref().and_then(|ip| {
            enrichment::query_ip_info(&ip.src_ip)
        });

        println!("📦 [{}] {} → {}  ({})",
            packet.timestamp,
            packet.ip.as_ref().map(|ip| ip.src_ip.clone()).unwrap_or("??".into()),
            packet.ip.as_ref().map(|ip| ip.dst_ip.clone()).unwrap_or("??".into()),
            proto
        );

        if let Some(r) = rep {
            println!("   🌍 {} ({:?}) score={}", r.ip, r.country, r.score);
        }

        println!("---------------------------");

        // petite pause pour éviter flood
        thread::sleep(Duration::from_millis(20));
    }
}

fn main() {
    // Liste des interfaces réseau
    let devices = capture::list_devices();

    if devices.is_empty() {
        eprintln!("❌ Aucun device réseau trouvé. (Npcap / libpcap installé ?)");
        return;
    }

    println!("🧭 Interfaces détectées :");
    for (i, dev) in devices.iter().enumerate() {
        println!("  {} → {}", i, dev);
    }

    let device = &devices[0];
    println!("\n🔌 Capture sur {}", device);

    let (tx, rx) = unbounded::<Packet>();

    // Thread de capture
    let device_clone = device.clone();
    thread::spawn(move || {
        capture::capture_on(&device_clone, tx);
    });

    // Thread d’analyse d’affichage
    listen_to_packets(rx);
}
