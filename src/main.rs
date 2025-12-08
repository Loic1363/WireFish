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

// Flag global pour Ctrl+C
static STOP_REQUESTED: AtomicBool = AtomicBool::new(false);

fn parse_args() -> (OutputMode, Option<usize>) {
    let mut mode = OutputMode::PacketsOnly; // défaut : juste la table des paquets
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

/// Tronque une chaîne pour qu’elle tienne dans `width` colonnes
/// et ajoute "…" si c’est plus long.
fn fit_cell(s: &str, width: usize) -> String {
    if s.len() <= width {
        return s.to_string();
    }
    if width <= 1 {
        return "…".to_string();
    }

    let mut tmp = s.to_string();
    // on garde width-1 caractères, on ajoute "…"
    tmp.truncate(width - 1);
    tmp.push('…');
    tmp
}

fn listen_to_packets(rx: Receiver<Packet>, iface_name: String, mode: OutputMode) {
    // En mode debug-only → on consomme juste le channel
    if mode == OutputMode::DebugOnly {
        for _ in rx.iter() {}
        return;
    }

    // Largeur interne du cadre pour coller au header :
    // "───────┬──────────────────────────────┬──────────────────────────────┬────────┬───────────────"
    const INNER_WIDTH: usize = 98;
    const COL_IP_WIDTH: usize = 30;

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

    println!("├───────┬────────────────────────────────┬────────────────────────────────┬────────┬───────────────┤");
    println!("│ #     │ Source IP                      │ Destination IP                 │ Proto  │ Size          │");
    println!("├───────┼────────────────────────────────┼────────────────────────────────┼────────┼───────────────┤");

    let mut count: usize = 0;

    loop {
        if STOP_REQUESTED.load(Ordering::SeqCst) {
            break;
        }

        match rx.recv_timeout(Duration::from_millis(100)) {
            Ok(packet) => {
                count += 1;

                let proto = classifier::classify(&packet);
                let size = packet.payload.len();

                let (src_raw, dst_raw, has_ip) = if let Some(ip) = &packet.ip {
                    (ip.src_ip.clone(), ip.dst_ip.clone(), true)
                } else {
                    ("?".to_string(), "?".to_string(), false)
                };

                // on réduit les IP à COL_IP_WIDTH pour ne pas casser le tableau
                let src = fit_cell(&src_raw, COL_IP_WIDTH);
                let dst = fit_cell(&dst_raw, COL_IP_WIDTH);

                // Filtre le bruit : pas d’IP + proto OTHER
                if !has_ip && proto == "OTHER" {
                    continue;
                }

                println!(
                    "│ {:<5} │ {:<30} │ {:<30} │ {:<6} │ {:>4} B        │",
                    count,
                    src,
                    dst,
                    proto,
                    size,
                );

                thread::sleep(Duration::from_millis(5));
            }
            Err(_) => {
                if STOP_REQUESTED.load(Ordering::SeqCst) {
                    break;
                }
            }
        }
    }

    println!("├───────┴────────────────────────────────┴────────────────────────────────┴────────┴───────────────┤");
    println!("│{:<width$}│", " Capture terminée (Ctrl+C)", width = INNER_WIDTH);
    println!("└{}┘", "─".repeat(INNER_WIDTH));
}

/// Scan rapide puis choix interactif d’interface
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

    // Handler Ctrl+C
    ctrlc::set_handler(|| {
        STOP_REQUESTED.store(true, Ordering::SeqCst);
    })
    .expect("Impossible d'installer le handler Ctrl+C");

    // 1) Liste des devices
    let devices = capture::list_devices();

    if devices.is_empty() {
        eprintln!("❌ Aucun device réseau trouvé. (Npcap / droits admin ?)");
        return;
    }

    // 2) Choix d'interface : via argument ou interactif
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

    // 3) Channel entre capture et affichage
    let (tx, rx) = unbounded::<Packet>();

    // 4) Thread de capture
    let device_clone = device.clone();
    let debug_enabled = mode == OutputMode::DebugOnly || mode == OutputMode::Both;
    thread::spawn(move || {
        capture::capture_on(&device_clone, tx, debug_enabled);
    });

    // 5) Affichage
    listen_to_packets(rx, device, mode);
}
