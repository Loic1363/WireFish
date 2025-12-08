mod core;

use crossbeam::channel::{unbounded, Receiver};
use std::io::{self, Write};
use std::thread;
use std::time::Duration;

use crate::core::capture;
use crate::core::classifier;
use crate::core::models::Packet;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum OutputMode {
    PacketsOnly,
    DebugOnly,
    Both,
}

fn parse_mode_from_args() -> OutputMode {
    let mut mode = OutputMode::PacketsOnly; // par défaut : que les paquets

    for arg in std::env::args().skip(1) {
        match arg.as_str() {
            "--debug-only" => mode = OutputMode::DebugOnly,
            "--debug" | "--both" => mode = OutputMode::Both,
            "--packets-only" => mode = OutputMode::PacketsOnly,
            _ => {}
        }
    }

    mode
}

/// Affichage des paquets en mode "table" lisible dans le terminal
fn listen_to_packets(rx: Receiver<Packet>, iface_name: String, mode: OutputMode) {
    // Si on est en mode debug-only → on consomme juste le channel sans afficher de table
    if mode == OutputMode::DebugOnly {
        for _ in rx.iter() {
            // on lit pour ne pas bloquer le thread capture, mais on n'affiche rien ici
        }
        return;
    }

    println!();
    println!("┌──────────────────────────────────────────────────────────────────────────────┐");
    println!("│ WireFish - Live Capture                                                      │");
    println!("│ Interface : {iface_name}               │");                                                  
    println!("├───────┬──────────────────────┬──────────────────────┬────────┬───────────────┤");
    println!("│ #     │ Source IP            │ Destination IP       │ Proto  │ Size          │");
    println!("├───────┼──────────────────────┼──────────────────────┼────────┼───────────────┤");

    let mut count: usize = 0;

    for packet in rx.iter() {
        count += 1;

        let proto = classifier::classify(&packet);
        let size = packet.payload.len();

        let (src, dst, has_ip) = if let Some(ip) = &packet.ip {
            (ip.src_ip.clone(), ip.dst_ip.clone(), true)
        } else {
            ("?".to_string(), "?".to_string(), false)
        };

        // Si aucun IP et protocole inconnu → bruit, on le saute pour la vue "packets"
        if !has_ip && proto == "Unknown" {
            continue;
        }

        println!(
            "│ {:<5} │ {:<20} │ {:<20} │ {:<6} │ {:>4} B        │",
            count,
            src,
            dst,
            proto,
            size,
        );

        // petite pause pour éviter un défilement illisible si gros trafic
        thread::sleep(Duration::from_millis(5));
    }

    println!("├───────┴──────────────────────┴──────────────────────┴────────┴───────────────┤");
    println!("│ Capture terminée (Ctrl+C)                                                    │");
    println!("└───────────────────────────────────────────────────────────────────────────────┘");
}

/// Scan rapide pour afficher (~ pkts / 0.5s) par interface puis demander à l'utilisateur
fn choose_device(devices: &[String]) -> Option<String> {
    println!("🔎 Scan rapide du trafic (≈ paquets / 0.5s)...\n");

    let mut counts = Vec::new();
    for dev in devices {
        let c = capture::quick_peek(dev, 500);
        counts.push(c);
    }

    println!("🧭 Interfaces détectées :");
    for (i, (dev, c)) in devices.iter().zip(counts.iter()).enumerate() {
        println!("  {i:>2} → {dev}   (~{c} pkts / 0.5s)");
    }

    println!();
    println!("Choisis l'interface à écouter (index, ex: 10 puis Entrée) :");

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
    let mode = parse_mode_from_args();

    // 1) Récupère la liste des devices Npcap
    let devices = capture::list_devices();

    if devices.is_empty() {
        eprintln!("❌ Aucun device réseau trouvé. (Npcap / droits admin ?)");
        return;
    }

    // 2) Scan rapide + choix utilisateur
    let device = match choose_device(&devices) {
        Some(d) => d,
        None => {
            eprintln!("❌ Pas d'interface sélectionnée.");
            return;
        }
    };

    println!("\n🔌 Capture sur {device}\n");

    // 3) Channel entre le thread de capture et l'affichage
    let (tx, rx) = unbounded::<Packet>();

    // 4) Thread de capture
    let device_clone = device.clone();
    let debug_enabled = mode == OutputMode::DebugOnly || mode == OutputMode::Both;
    thread::spawn(move || {
        capture::capture_on(&device_clone, tx, debug_enabled);
    });

    // 5) Thread principal : affichage des paquets (sauf si debug-only)
    listen_to_packets(rx, device, mode);
}
