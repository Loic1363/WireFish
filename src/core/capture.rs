use pcap::{Capture, Device};
use crate::core::parser::parse_packet;
use crate::core::models::Packet;

pub fn list_devices() -> Vec<String> {
    Device::list()
        .unwrap_or_default()
        .into_iter()
        .map(|d| d.name)
        .collect()
}

pub fn capture_on(device_name: &str, sender: crossbeam::channel::Sender<Packet>) {
    let mut cap = Capture::from_device(device_name)
        .unwrap()
        .promisc(true)
        .snaplen(65535)
        .open()
        .unwrap();

    while let Ok(packet) = cap.next_packet() {
        let parsed = parse_packet(&packet.data);
        if let Some(p) = parsed {
            let _ = sender.send(p);
        }
    }
}
