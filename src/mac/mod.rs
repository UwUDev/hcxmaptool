use crate::AccessPoint;
use log::{debug, trace};
use std::collections::HashMap;

pub fn bind_vendors_to_aps(aps: &mut Vec<AccessPoint>) {
    let macs: Vec<&[u8; 6]> = aps.iter().map(|ap| &ap.mac).collect();
    let vendor_map = lookup(macs);

    for ap in aps.iter_mut() {
        if let Some(vendor) = vendor_map.get(&ap.mac) {
            ap.vendor = Some(vendor.clone());
            trace!(
                "Bound vendor '{}' to AP {:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
                vendor, ap.mac[0], ap.mac[1], ap.mac[2], ap.mac[3], ap.mac[4], ap.mac[5]
            );
        }
    }
}

fn lookup(macs: Vec<&[u8; 6]>) -> HashMap<[u8; 6], String> {
    let csv_data = include_str!("mac-vendors.csv");
    let mut results: HashMap<[u8; 3], String> = HashMap::new();

    let mac_starts: Vec<String> = macs
        .iter()
        .map(|mac| format!("{:02X}:{:02X}:{:02X}", mac[0], mac[1], mac[2]))
        .collect();

    for line in csv_data.lines().skip(1) {
        let parts: Vec<&str> = line.split(',').collect();
        if parts.len() >= 2 {
            let prefix = parts[0].trim_matches('"');
            let vendor = parts[1].trim_matches('"').to_string();
            if mac_starts.contains(&prefix.to_string()) {
                let bytes: Vec<u8> = prefix
                    .split(':')
                    .map(|s| u8::from_str_radix(s, 16).unwrap())
                    .collect();
                if bytes.len() == 3 {
                    results.insert([bytes[0], bytes[1], bytes[2]], vendor);
                }
            }
        } else {
            debug!("ALERT: Malformed line in MAC vendors CSV: {}", line);
        }
    }

    let mut final_results: HashMap<[u8; 6], String> = HashMap::new();
    for mac in macs {
        let prefix = [mac[0], mac[1], mac[2]];
        if let Some(vendor) = results.get(&prefix) {
            final_results.insert(*mac, vendor.clone());
        }
    }
    final_results
}
