use crate::core::models::{Packet, IpReputation};

#[allow(dead_code)]
pub fn detect_suspicious(packet: &Packet, rep: Option<&IpReputation>) -> bool {
    
    if let Some(r) = rep {
        if r.score > 70 {
            return true;
        }
    }

    if let Some(ip) = &packet.ip {
        // Flag simple FTP control traffic
        if ip.protocol == 21 {
            return true;
        }
    }

    false
}
