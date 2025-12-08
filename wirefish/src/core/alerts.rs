use crate::core::models::{Packet, IpReputation};

pub fn detect_suspicious(packet: &Packet, rep: Option<&IpReputation>) -> bool {
    // Nouvelle IP ?
    // Score réputation ?
    // Ports suspects ?
    
    if let Some(r) = rep {
        if r.score > 70 {
            return true;
        }
    }

    if let Some(ip) = &packet.ip {
        // FTP brut
        if ip.protocol == 21 {
            return true;
        }
    }

    false
}
