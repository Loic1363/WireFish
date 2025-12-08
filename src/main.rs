mod core;

use crossbeam::channel::{unbounded, Receiver};
use std::io::{self, Write};
use std::thread;
use std::time::Duration;

use crate::core::{capture, classifier};
use crate::core::models::Packet;

fn listen_to_packets(rx: Receiver<Packet>) {
    println!("🚀 WireFish started! Listening for packets...\n");

    let mut count = 0usize;

    for packet in rx.iter() {
        count += 1;

        let proto = classifier::classify(&packet);

        let (src, dst) = if let Some(ip) = &packet.ip {
            (ip.src_ip.clone(), ip.dst_ip.clone())
        } else {
            ("?".into(), "?".into())
        };

        println!(
            "📦 #{count} [{}] {} → {}  ({})",
            packet.timestamp, src, dst, proto
        );

        println!("---------------------------");

        thread::sleep(Duration::from_millis(10));
    }
}

fn choose_device(devices: &[String]) -> Option<String> {
    println!("🔎 Scan rapide du trafic (≈ paquets / 0.5s)...\n");

    let mut counts = Vec::new();
    for dev in devices {
        let c = capture::quick_peek(dev, 500);
        counts.push(c);
    }

    println!("🧭 Interfaces détectées :");
    for (i, (dev, c)) in devices.iter().zip(counts.iter()).enumerate() {
        println!("  {i} → {dev}   (~{c} pkts / 0.5s)");
    }

    println!();
    println!("Choisis l'interface à écouter (index, ex: 3 puis Entrée) :");

    loop {
        print!("> ");
        io::stdout().flush().ok();

        let mut input = String::new();
        if io::stdin().read_line(&mut input).is_err() {
            println!("Erreur de lecture, réessaie.");
            continue;
        }

        let input = input.trim();

        if input.is_empty() {
            println!("(Entrée vide → on prend 0 par défaut)");
            return devices.get(0).cloned();
        }

        match input.parse::<usize>() {
            Ok(idx) if idx < devices.len() => {
                return devices.get(idx).cloned();
            }
            _ => {
                println!(
                    "Index invalide, entre un nombre entre 0 et {}.",
                    devices.len() - 1
                );
            }
        }
    }
}

fn main() {
    let devices = capture::list_devices();

    if devices.is_empty() {
        eprintln!("❌ Aucun device réseau trouvé. (Npcap / droits admin ?)");
        return;
    }

    let device = match choose_device(&devices) {
        Some(d) => d,
        None => {
            eprintln!("❌ Pas d'interface sélectionnée.");
            return;
        }
    };

    println!("\n🔌 Capture sur {device}\n");

    let (tx, rx) = unbounded::<Packet>();

    // Thread de capture
    let device_clone = device.clone();
    thread::spawn(move || {
        capture::capture_on(&device_clone, tx);
    });

    // Thread d'affichage / analyse
    listen_to_packets(rx);
}
