mod core;

use crossbeam::channel::{unbounded, Receiver};
use std::io::{self, Write};
use std::thread;
use std::sync::atomic::{AtomicBool, Ordering};
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

static STOP_REQUESTED: AtomicBool = AtomicBool::new(false);

fn parse_args() -> (OutputMode, Option<usize>) {
    let mut mode = OutputMode::PacketsOnly; // défaut : que les paquets
    let mut iface_index: Option<usize> = None;

    for arg in std::env::args().skip(1) {
        if arg.starts_with('-') {
            match arg.as_str() {
                "--debug-only" => mode = OutputMode::DebugOnly,
                "--debug" | "--both" => mode = OutputMode::Both,
                "--packets-only" => mode = OutputMode::PacketsOnly,
                _ => {}
            }
        } else if iface_index.is_none() {
            if let Ok(idx) = arg.parse::<usize>() {
                iface_index = Some(idx);
            }
        }
    }

    (mode, iface_index)
}

fn listen_to_packets(rx: Receiver<Packet>, iface_name: String, mode: OutputMode) {
    // Si on est en mode debug-only → on consomme juste le channel sans afficher de table
    if mode == OutputMode::DebugOnly {
        for _ in rx.iter() {
            // on lit pour ne pas bloquer le thread capture, mais on n'affiche rien ici
        }
        return;
    }

    // largeur interne du cadre (entre les deux │)
    const INNER_WIDTH: usize = 78;

    println!();
    println!("┌{}┐", "─".repeat(INNER_WIDTH));
    println!("│{:<width$}│", " WireFish - Live Capture", width = INNER_WIDTH);

    let iface_line = format!(" Interface : {iface_name}");
    let iface_trimmed = if iface_line.len() > INNER_WIDTH {
        let mut s: String = iface_line.chars().take(INNER_WIDTH - 3).collect();
        s.push_str("..");
        s
    } else {
        iface_line
    };
    println!("│{:<width$}│", iface_trimmed, width = INNER_WIDTH);

    println!("├───────┬──────────────────────┬──────────────────────┬────────┬───────────────┤");
    println!("│ #     │ Source IP            │ Destination IP       │ Proto  │ Size          │");
    println!("├───────┼──────────────────────┼──────────────────────┼────────┼───────────────┤");

    let mut count: usize = 0;

    loop {
        // si Ctrl+C → on sort proprement de la boucle
        if STOP_REQUESTED.load(Ordering::SeqCst) {
            break;
        }

        // on attend un paquet avec timeout, pour pouvoir checker STOP_REQUESTED
        match rx.recv_timeout(Duration::from_millis(100)) {
            Ok(packet) => {
                count += 1;

                let proto = classifier::classify(&packet);
                let size = packet.payload.len();

                let (src, dst, has_ip) = if let Some(ip) = &packet.ip {
                    (ip.src_ip.clone(), ip.dst_ip.clone(), true)
                } else {
                    ("?".to_string(), "?".to_string(), false)
                };

                // bruit : pas d'IP + proto OTHER → on n'affiche pas
                if !has_ip && proto == "OTHER" {
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
            Err(_timeout_or_closed) => {
                // timeout → on regarde juste si Ctrl+C a été demandé
                if STOP_REQUESTED.load(Ordering::SeqCst) {
                    break;
                }
            }
        }
    }


    println!("├───────┴──────────────────────┴──────────────────────┴────────┴───────────────┤");
    println!("│ Capture terminée (Ctrl+C)                                                    │");
    println!("└──────────────────────────────────────────────────────────────────────────────┘");
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
    let (mode, iface_index_arg) = parse_args();

    // Handler Ctrl+C : on ne fait QUE demander l'arrêt
    ctrlc::set_handler(|| {
        STOP_REQUESTED.store(true, Ordering::SeqCst);
    }).expect("Impossible d'installer le handler Ctrl+C");

    // 1) Récupère la liste des devices Npcap
    let devices = capture::list_devices();

    if devices.is_empty() {
        eprintln!("❌ Aucun device réseau trouvé. (Npcap / droits admin ?)");
        return;
    }

    // 2) Choix d'interface : arg → sinon interactif
    let device = if let Some(idx) = iface_index_arg {
        if idx < devices.len() {
            println!("🔧 Interface choisie via argument : {idx} → {}", devices[idx]);
            devices[idx].clone()
        } else {
            eprintln!("❌ Index d'interface invalide ({idx}), bascule en mode interactif.\n");
            match choose_device(&devices) {
                Some(d) => d,
                None => {
                    eprintln!("❌ Pas d'interface sélectionnée.");
                    return;
                }
            }
        }
    } else {
        match choose_device(&devices) {
            Some(d) => d,
            None => {
                eprintln!("❌ Pas d'interface sélectionnée.");
                return;
            }
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
