use crate::geo::{Position, get_position_at, rssi_to_distance};
use crate::{AccessPoint, Observation, WORKING_DIR};
use log::{debug, error, trace};
use pcap_file::pcapng::PcapNgReader;
use radiotap::Radiotap;
use std::collections::HashMap;
use std::fs::File;
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct Packet {
    pub timestamp: Duration,
    pub source_address: Option<[u8; 6]>,
    pub ssid: Option<String>,
    pub signal_strength: Option<i8>,
    pub channel: Option<u8>,
    pub security: Option<WifiSecurity>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum WifiSecurity {
    Open,
    WEP,
    WPA,
    WPA2,
    WPA3,
    WPA2WPA3,
    Unknown,
}

impl std::fmt::Display for WifiSecurity {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            WifiSecurity::Open => write!(f, "Open"),
            WifiSecurity::WEP => write!(f, "WEP"),
            WifiSecurity::WPA => write!(f, "WPA"),
            WifiSecurity::WPA2 => write!(f, "WPA2"),
            WifiSecurity::WPA3 => write!(f, "WPA3"),
            WifiSecurity::WPA2WPA3 => write!(f, "WPA2/WPA3"),
            WifiSecurity::Unknown => write!(f, "Unknown"),
        }
    }
}

pub fn group_packets_by_mac(packets: &[Packet], positions: &[Position]) -> Vec<AccessPoint> {
    let mut mac_map: HashMap<[u8; 6], AccessPoint> = HashMap::new();

    for packet in packets {
        if let Some(mac) = packet.source_address {
            if let Some(signal) = packet.signal_strength {
                if let Some(pos) = get_position_at(&packet.timestamp, positions) {
                    let distance = rssi_to_distance(signal);

                    let observation = Observation {
                        position: pos,
                        signal_strength: signal,
                        distance,
                    };

                    let ap = mac_map.entry(mac).or_insert_with(|| AccessPoint {
                        mac,
                        ssid: packet.ssid.clone(),
                        observations: Vec::new(),
                        estimated_position: None,
                        position_method: None,
                        security: None,
                        channel: packet.channel,
                        vendor: None,
                        password: None,
                    });

                    ap.observations.push(observation);

                    if ap.ssid.is_none() && packet.ssid.is_some() {
                        ap.ssid = packet.ssid.clone();
                    }

                    if ap.security.is_none() && packet.security.is_some() {
                        ap.security = packet.security.clone();
                    }
                }
            }
        }
    }

    mac_map.into_values().collect()
}

fn extract_mac(bytes: &[u8]) -> [u8; 6] {
    let mut mac = [0u8; 6];
    mac.copy_from_slice(bytes);
    trace!(
        "Extracted MAC: {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    );
    mac
}

fn parse_management_frame_body(frame_body: &[u8]) -> Option<String> {
    if frame_body.len() < 12 {
        return None;
    }

    let mut ssid = None;
    let mut offset = 12; // skip fixed parameters

    while offset + 2 <= frame_body.len() {
        let tag_number = frame_body[offset];
        let tag_length = frame_body[offset + 1] as usize;

        if offset + 2 + tag_length > frame_body.len() {
            break;
        }

        // SSID element (tag 0)
        if tag_number == 0 && tag_length > 0 {
            let ssid_bytes = &frame_body[offset + 2..offset + 2 + tag_length];
            if let Ok(ssid_str) = std::str::from_utf8(ssid_bytes) {
                if !ssid_str.is_empty() {
                    ssid = Some(ssid_str.to_string());
                }
            }
            break;
        }

        offset += 2 + tag_length;
    }

    ssid
}

pub fn get_packets() -> Vec<Packet> {
    let mut all_packets = Vec::new();

    let paths = std::fs::read_dir(WORKING_DIR.lock().unwrap().as_str()).unwrap();
    for path in paths {
        let path = path.unwrap().path();
        if let Some(ext) = path.extension() {
            if ext == "pcapng" {
                debug!("Reading pcapng file: {:?}", path);

                let file = File::open(&path).unwrap();
                let mut pcapng_reader = PcapNgReader::new(file).unwrap();

                while let Some(block) = pcapng_reader.next_block() {
                    match block {
                        Ok(block) => {
                            if let pcap_file::pcapng::Block::EnhancedPacket(epb) = block {
                                let data = epb.data.as_ref();

                                if let Some(packet) = parse_wifi_packet(data, epb.timestamp) {
                                    all_packets.push(packet);
                                }
                            }
                        }
                        Err(e) => {
                            error!("Error reading block: {:?}", e);
                            break;
                        }
                    }
                }
            }
        }
    }

    all_packets
}

fn parse_wifi_packet(data: &[u8], timestamp: Duration) -> Option<Packet> {
    let radiotap = Radiotap::from_bytes(data).ok()?;
    let radiotap_len = radiotap.header.length as usize;

    if data.len() < radiotap_len + 24 {
        return None;
    }

    let signal_strength = radiotap.antenna_signal.map(|s| s.value);
    let channel = radiotap.channel.and_then(|c| match c.freq {
        2412 => Some(1),
        2417 => Some(2),
        2422 => Some(3),
        2427 => Some(4),
        2432 => Some(5),
        2437 => Some(6),
        2442 => Some(7),
        2447 => Some(8),
        2452 => Some(9),
        2457 => Some(10),
        2462 => Some(11),
        2467 => Some(12),
        2472 => Some(13),
        2484 => Some(14),
        5180 => Some(36),
        5200 => Some(40),
        5220 => Some(44),
        5240 => Some(48),
        5260 => Some(52),
        5280 => Some(56),
        5300 => Some(60),
        5320 => Some(64),
        5500 => Some(100),
        5520 => Some(104),
        5540 => Some(108),
        5560 => Some(112),
        5580 => Some(116),
        5600 => Some(120),
        5620 => Some(124),
        5640 => Some(128),
        5660 => Some(132),
        5680 => Some(136),
        5700 => Some(140),
        5745 => Some(149),
        5765 => Some(153),
        5785 => Some(157),
        5805 => Some(161),
        5825 => Some(165),
        _ => None,
    }); // I want to die

    let wlan_data = &data[radiotap_len..];
    if wlan_data.len() < 24 {
        return None;
    }

    let frame_control = u16::from_le_bytes([wlan_data[0], wlan_data[1]]);
    let frame_type = (frame_control >> 2) & 0x03;
    let frame_subtype = (frame_control >> 4) & 0x0F;
    let to_ds = (frame_control >> 8) & 0x01;
    let from_ds = (frame_control >> 9) & 0x01;

    let ap_mac: Option<[u8; 6]>;
    let mut ssid: Option<String> = None;
    let mut security: Option<WifiSecurity> = None;

    // management frames (type=0)
    if frame_type == 0 {
        match frame_subtype {
            // beacon (0x08) or Probe Response (0x05)
            8 | 5 => {
                ap_mac = Some(extract_mac(&wlan_data[10..16]));

                // Extract capabilities field (at offset 34 for beacons)
                if wlan_data.len() >= 36 {
                    let capabilities = u16::from_le_bytes([wlan_data[34], wlan_data[35]]);
                    security = Some(parse_wifi_security(&wlan_data[24..], capabilities));
                    ssid = parse_management_frame_body(&wlan_data[24..]);
                }
            }
            // Association/Reassociation Response
            1 | 3 => {
                ap_mac = Some(extract_mac(&wlan_data[10..16]));
            }
            _ => {
                trace!("Unknown Wifi frame subtype: {}", frame_subtype);
                return None;
            }
        }
    }
    // data frames (type=2)
    else if frame_type == 2 {
        match (to_ds, from_ds) {
            (1, 0) => ap_mac = Some(extract_mac(&wlan_data[4..10])),
            (0, 1) => ap_mac = Some(extract_mac(&wlan_data[10..16])),
            (0, 0) => ap_mac = Some(extract_mac(&wlan_data[16..22])),
            _ => return None,
        }
    } else {
        return None;
    }

    Some(Packet {
        timestamp,
        source_address: ap_mac,
        ssid,
        signal_strength,
        channel,
        security,
    })
}

fn parse_wifi_security(frame_body: &[u8], capabilities: u16) -> WifiSecurity {
    // check privacy bit (bit 4) in capability field
    let privacy_enabled = (capabilities & 0x0010) != 0;

    if !privacy_enabled {
        return WifiSecurity::Open;
    }

    if frame_body.len() < 12 {
        return WifiSecurity::Unknown;
    }

    let mut has_rsn = false;
    let mut has_wpa = false;
    let mut has_sae = false;
    let mut has_psk = false;
    let mut offset = 12; // skip fixed parameters

    while offset + 2 <= frame_body.len() {
        let tag_number = frame_body[offset];
        let tag_length = frame_body[offset + 1] as usize;

        if offset + 2 + tag_length > frame_body.len() {
            break;
        }

        match tag_number {
            // RSN Information Element (WPA2/WPA3)
            48 => {
                has_rsn = true;

                // parse AKM suites to detect WPA2/WPA3
                if tag_length >= 8 {
                    let tag_data = &frame_body[offset + 2..offset + 2 + tag_length];

                    // skip version (2 bytes) + Group Cipher (4 bytes)
                    if tag_data.len() >= 8 {
                        // pairwise cipher suite count (2 bytes)
                        let pairwise_count =
                            u16::from_le_bytes([tag_data[6], tag_data[7]]) as usize;
                        let pairwise_size = pairwise_count * 4;

                        // AKM suite offset
                        let akm_offset = 8 + pairwise_size;
                        if tag_data.len() >= akm_offset + 2 {
                            let akm_count = u16::from_le_bytes([
                                tag_data[akm_offset],
                                tag_data[akm_offset + 1],
                            ]) as usize;

                            // check AKM suites
                            for i in 0..akm_count {
                                let suite_offset = akm_offset + 2 + (i * 4);
                                if tag_data.len() >= suite_offset + 4 {
                                    let akm_type = tag_data[suite_offset + 3];
                                    match akm_type {
                                        2 => has_psk = true, // WPA2-PSK
                                        8 => has_sae = true, // WPA3-SAE
                                        _ => {}
                                    }
                                }
                            }
                        }
                    }
                }
            }
            // vendor specific - WPA
            221 => {
                if tag_length >= 8 {
                    let tag_data = &frame_body[offset + 2..offset + 2 + tag_length];

                    // check for WPA OUI (00:50:f2) and type 1
                    if tag_data.len() >= 4
                        && tag_data[0] == 0x00
                        && tag_data[1] == 0x50
                        && tag_data[2] == 0xf2
                        && tag_data[3] == 0x01
                    {
                        has_wpa = true;
                    }
                }
            }
            _ => {}
        }

        offset += 2 + tag_length;
    }

    if has_rsn {
        if has_sae && has_psk {
            return WifiSecurity::WPA2WPA3; // transition mode
        } else if has_sae {
            return WifiSecurity::WPA3;
        } else {
            return WifiSecurity::WPA2;
        }
    } else if has_wpa {
        return WifiSecurity::WPA;
    } else if privacy_enabled {
        return WifiSecurity::WEP;
    }

    WifiSecurity::Unknown
}
