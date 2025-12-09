mod core;

use crossbeam::channel::{unbounded, Receiver};
use std::io::{self, Write};
use std::thread;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use crate::core::capture;
use crate::core::classifier;
use crate::core::models::Packet;
use crate::core::storage;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum OutputMode {
    PacketsOnly,
    DebugOnly,
    Both,
}

static STOP_REQUESTED: AtomicBool = AtomicBool::new(false);

fn fit_cell(s: &str, width: usize) -> String {
    if s.len() <= width {
        return s.to_string();
    }
    if width <= 1 {
        return "…".to_string();
    }
    let mut tmp = s.to_string();
    tmp.truncate(width - 1);
    tmp.push('…');
    tmp
}

fn parse_args_for_check() -> Option<u64> {
    let mut args = std::env::args().skip(1);

    let first = args.next()?;
    if first != "check" {
        return None;
    }

    let mut next = args.next();
    if let Some(ref n) = next {
        if n == "req" {
            next = args.next();
        }
    }

    let id_str = match next {
        Some(s) => s,
        None => {
            eprintln!("Usage: wirefish check <id> ou wirefish check req <id>");
            return Some(0); 
        }
    };

    match id_str.parse::<u64>() {
        Ok(id) => Some(id),
        Err(_) => {
            eprintln!("ID invalide : {id_str}");
            Some(0)
        }
    }
}

fn parse_args() -> (OutputMode, Option<usize>) {
    let mut mode = OutputMode::PacketsOnly;
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
    if mode == OutputMode::DebugOnly {
        for _ in rx.iter() {}
        return;
    }

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

                if !has_ip && proto == "OTHER" {
                    continue;
                }

                let src = fit_cell(&src_raw, COL_IP_WIDTH);
                let dst = fit_cell(&dst_raw, COL_IP_WIDTH);

                println!(
                    "│ {:<5} │ {:<30} │ {:<30} │ {:<6} │ {:>4} B        │",
                    count,
                    src,
                    dst,
                    proto,
                    size,
                );

                storage::save_packet_for_inspect(count as u64, &iface_name, &proto, &packet);

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

fn choose_device(devices: &[String]) -> Option<String> {
    use std::cmp::max;

    let mut counts = Vec::new();
    for dev in devices {
        let c = capture::quick_peek(dev, 500);
        counts.push(c);
    }

    let max_count = counts.iter().copied().fold(0usize, max);
    let bar_max_width: usize = 20;

    println!();
    println!("╔═══════════════════════════════════════════════════════════════════════════════╗");
    println!("║ WireFish – Capture interfaces                                                 ║");
    println!("╠════╤════════════════════════╤══════════════╤══════════════════════════════════╣");
    println!("║ Id │ Activity               │ pkts/0.5s    │ Interface                        ║");
    println!("╠════╪════════════════════════╪══════════════╪══════════════════════════════════╣");

    for (i, (dev, c)) in devices.iter().zip(counts.iter()).enumerate() {

        let bar_len = if max_count == 0 || *c == 0 {
            0
        } else {
            let ratio = *c as f32 / max_count as f32;
            (ratio * bar_max_width as f32).ceil() as usize
        };

        let bar = if bar_len == 0 {
            "·".to_string()
        } else {
            "█".repeat(bar_len)
        };

        println!(
            "║ {:>2} │ {:<22} │ {:>5} pkts   │ {:<32} ║",
            i,
            bar,
            c,
            dev.chars().take(32).collect::<String>()
        );
    }

    println!("╚════╧════════════════════════╧══════════════╧══════════════════════════════════╝");
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
    if let Some(id_or_zero) = parse_args_for_check() {
        if id_or_zero != 0 {
            storage::inspect_packet(id_or_zero);
        }
        return;
    }

    storage::reset_storage();

    let (mode, iface_index_arg) = parse_args();

    ctrlc::set_handler(|| {
        STOP_REQUESTED.store(true, Ordering::SeqCst);
    })
    .expect("Impossible d'installer le handler Ctrl+C");

    let devices = capture::list_devices();

    if devices.is_empty() {
        eprintln!("Aucun device réseau trouvé. (Npcap / droits admin ?)");
        return;
    }

    let device = if let Some(idx) = iface_index_arg {
        if idx < devices.len() {
            println!("Interface choisie via argument : {idx} → {}", devices[idx]);
            devices[idx].clone()
        } else {
            eprintln!("❌ Index d'interface invalide ({idx}), bascule en mode interactif.\n");
            match choose_device(&devices) {
                Some(d) => d,
                None => {
                    eprintln!("Pas d'interface sélectionnée.");
                    return;
                }
            }
        }
    } else {
        match choose_device(&devices) {
            Some(d) => d,
            None => {
                eprintln!("Pas d'interface sélectionnée.");
                return;
            }
        }
    };

    println!("\nCapture sur {device}\n");

    let (tx, rx) = unbounded::<Packet>();

    let device_clone = device.clone();
    let debug_enabled = mode == OutputMode::DebugOnly || mode == OutputMode::Both;
    thread::spawn(move || {
        capture::capture_on(&device_clone, tx, debug_enabled);
    });

    listen_to_packets(rx, device, mode);
}
