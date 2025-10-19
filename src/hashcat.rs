use crate::packets::WifiSecurity;
use crate::{AccessPoint, WORKING_DIR};
use log::{debug, error, trace, warn};
use std::collections::HashSet;
use std::fs;
use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::process::Command;

struct APPassword {
    mac: [u8; 6],
    ssid: String,
    password: String,
    security: WifiSecurity,
}

pub fn bind_passwords_to_aps(aps: &mut Vec<AccessPoint>) {
    let passwords = get_passwords();
    for ap in aps.iter_mut() {
        for pwd in &passwords {
            if ap.mac == pwd.mac {
                if ap.ssid.is_none() {
                    ap.ssid = Some(pwd.ssid.clone());
                    ap.password = Some(pwd.password.clone());
                    if ap.security.is_none() {
                        ap.security = Some(pwd.security.clone());
                    }
                } else if ap.ssid.as_ref().unwrap() == &pwd.ssid {
                    ap.password = Some(pwd.password.clone());
                    if ap.security.is_none() {
                        ap.security = Some(pwd.security.clone());
                    }
                }
            }
        }
    }
}

fn get_passwords() -> Vec<APPassword> {
    let mut passwords: Vec<APPassword> = Vec::new();

    let hashcat_bin = get_hashcat_bin();
    if hashcat_bin.is_none() {
        warn!("Hashcat binary not found in PATH. Skipping password retrieval.");
        return passwords;
    }
    let hashcat_bin = hashcat_bin.unwrap();

    let hash_files: Vec<PathBuf> = match fs::read_dir(WORKING_DIR.lock().unwrap().as_str()) {
        Ok(entries) => entries
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.path())
            .filter(|path| path.extension().and_then(|s| s.to_str()) == Some("22000"))
            .collect(),
        Err(e) => {
            error!("Failed to read dumps directory: {}", e);
            return passwords;
        }
    };

    if hash_files.is_empty() {
        warn!("No .22000 files found in dumps directory.");
        return passwords;
    }

    let security_info = parse_22000_files(&hash_files);

    let mut seen_hashes = HashSet::new();

    for file in &hash_files {
        let mut cmd = Command::new(&hashcat_bin);
        cmd.arg("--show").arg("-m").arg("22000").arg(file);

        let output = match cmd.output() {
            Ok(output) => output,
            Err(e) => {
                error!("Failed to execute hashcat for file {:?}: {}", file, e);
                continue;
            }
        };

        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            for line in stdout.lines() {
                if seen_hashes.contains(line) {
                    continue;
                }
                seen_hashes.insert(line.to_string());

                let parts: Vec<&str> = line.split(':').collect();
                if parts.len() >= 5 {
                    let mac_str = parts[1];
                    let ssid = parts[3].to_string();
                    let password = parts[4].to_string();
                    if mac_str.len() == 12 {
                        let mut mac = [0u8; 6];
                        for i in 0..6 {
                            mac[i] =
                                u8::from_str_radix(&mac_str[i * 2..i * 2 + 2], 16).unwrap_or(0);
                        }

                        let security = security_info
                            .get(&mac)
                            .cloned()
                            .unwrap_or(WifiSecurity::Unknown);

                        passwords.push(APPassword {
                            mac,
                            ssid,
                            password,
                            security,
                        });
                    }
                }
            }
        } else {
            error!("Hashcat command failed for file {:?}", file);
            error!("Exit code: {:?}", output.status.code());
            let stderr = String::from_utf8_lossy(&output.stderr);
            if !stderr.is_empty() {
                error!("Error output: {}", stderr);
            }
        }
    }

    passwords
}

fn parse_22000_files(files: &[PathBuf]) -> std::collections::HashMap<[u8; 6], WifiSecurity> {
    use std::collections::HashMap;
    let mut security_map = HashMap::new();

    for file_path in files {
        if let Ok(file) = fs::File::open(file_path) {
            debug!("Parsing security info from file {:?}", file_path);
            let reader = BufReader::new(file);
            for line in reader.lines() {
                if let Ok(line) = line {
                    if let Some(security_info) = parse_22000_line(&line) {
                        security_map.insert(security_info.0, security_info.1);
                    }
                }
            }
        }
    }

    security_map
}

fn parse_22000_line(line: &str) -> Option<([u8; 6], WifiSecurity)> {
    // format: WPA*TYPE*PMKID/MIC*MAC_AP*MAC_CLIENT*ESSID*ANONCE*EAPOL*MESSAGEPAIR
    // TYPE: 01 = PMKID, 02 = EAPOL (handshake)
    let parts: Vec<&str> = line.split('*').collect();

    if parts.len() < 5 || parts[0] != "WPA" {
        return None;
    }

    let capture_type = parts[1]; // 01 = PMKID, 02 = EAPOL

    let mac_str = parts[3];
    if mac_str.len() != 12 {
        return None;
    }

    let mut mac = [0u8; 6];
    for i in 0..6 {
        mac[i] = u8::from_str_radix(&mac_str[i * 2..i * 2 + 2], 16).ok()?;
    }

    let security = if capture_type == "02" && parts.len() >= 9 {
        // TYPE 02 = EAPOL handshake, analyse EAPOL (index 7)
        parse_security_from_eapol(parts[7])
    } else {
        // TYPE 01 = PMKID, no way to know for sure, assume WPA2
        WifiSecurity::WPA2
    };

    Some((mac, security))
}

fn parse_security_from_eapol(eapol: &str) -> WifiSecurity {
    // 000fac01 = WPA (802.1X)
    // 000fac02 = WPA2-PSK (le plus commun)
    // 000fac06 = WPA2-PSK-SHA256
    // 000fac08 = SAE (WPA3)
    // 000fac0c = WPA3-192bit

    let eapol_start = &eapol[..48.min(eapol.len())];

    if eapol.contains("000fac08") || eapol.contains("000fac0c") {
        trace!("Detected WPA3 security from EAPOL data: {}...", eapol_start);
        return WifiSecurity::WPA3;
    }

    if eapol.contains("000fac02") || eapol.contains("000fac06") {
        trace!("Detected WPA2 security from EAPOL data: {}...", eapol_start);
        return WifiSecurity::WPA2;
    }

    if eapol.contains("000fac01") {
        trace!("Detected WPA security from EAPOL data: {}...", eapol_start);
        return WifiSecurity::WPA;
    }

    if eapol.contains("0050f202") {
        trace!("Detected WPA security from EAPOL data: {}...", eapol_start);
        return WifiSecurity::WPA;
    }

    warn!(
        "Unable to determine security type from EAPOL data: {}...",
        eapol_start
    );

    // Default fallback
    WifiSecurity::WPA2
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn get_hashcat_bin() -> Option<String> {
    let output = Command::new("which")
        .arg("hashcat")
        .output()
        .expect("Failed to execute 'which' command");
    if output.status.success() {
        let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
        Some(path)
    } else {
        None
    }
}

#[cfg(target_os = "windows")]
fn get_hashcat_bin() -> Option<String> {
    let output = Command::new("where.exe")
        .arg("hashcat")
        .output()
        .expect("Failed to execute 'where' command");

    if output.status.success() {
        let paths = String::from_utf8_lossy(&output.stdout)
            .lines()
            .next()
            .unwrap_or("")
            .trim()
            .to_string();

        let path = paths.split('\n').next().unwrap_or("").trim().to_string();
        if !path.is_empty() { Some(path) } else { None }
    } else {
        None
    }
}

#[cfg(test)]
mod tests_hashcat {
    use super::*;

    #[test]
    fn test_get_passwords() {
        let bin = get_hashcat_bin();
        println!("Hashcat binary path: {:?}", bin);

        let passwords = get_passwords();
        for ap in passwords {
            println!(
                "MAC: {:02x?}, SSID: {}, Password: {}",
                ap.mac, ap.ssid, ap.password
            );
        }
    }
}
