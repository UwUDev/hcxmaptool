mod cli;
mod geo;
mod hashcat;
mod kml;
mod mac;
mod packets;

use crate::cli::*;
use crate::geo::*;
use crate::hashcat::bind_passwords_to_aps;
use crate::kml::export_to_kml;
use crate::mac::bind_vendors_to_aps;
use crate::packets::*;
use clap::{CommandFactory, Parser};
use clap_help::Printer;
use log::{debug, info, trace, warn};
use once_cell::sync::Lazy;
use std::collections::HashMap;
use std::fs::File;
use std::io::Write;
use std::sync::Mutex;

static WORKING_DIR: Lazy<Mutex<String>> = Lazy::new(|| Mutex::new(".".to_string()));

#[derive(Debug, Clone)]
pub struct AccessPoint {
    pub mac: [u8; 6],
    pub ssid: Option<String>,
    pub observations: Vec<Observation>,
    pub estimated_position: Option<Position>,
    pub position_method: Option<String>,
    pub security: Option<WifiSecurity>,
    pub channel: Option<u8>,
    pub vendor: Option<String>,
    pub password: Option<String>,
}

fn main() {
    let args: Args = Args::parse();
    if args.help {
        Printer::new(Args::command())
            .with("introduction", INTRO)
            .print_help();

        return;
    }

    pretty_env_logger::formatted_builder()
        .filter_module(env!("CARGO_CRATE_NAME"), args.log_level)
        .init();

    if let Some(dir) = &args.directory {
        let mut dir = dir.clone();
        while dir.ends_with('/') {
            dir.pop();
        }
        let mut working_dir = WORKING_DIR.lock().unwrap();
        debug!("Set working directory to {}", dir);
        *working_dir = dir;
    }

    let pos = get_positions();
    info!("Found {} positions", pos.len());

    let packets = get_packets();
    info!("Found {} beacon packets", packets.len());

    let mut access_points = group_packets_by_mac(&packets, &pos);
    info!("Found {} unique access points", access_points.len());

    bind_vendors_to_aps(&mut access_points);
    let aps_with_vendors: usize = access_points
        .iter()
        .filter(|ap| ap.vendor.is_some())
        .count();
    info!("Bound vendors to {} access points", aps_with_vendors);

    if !args.no_hashcat {
        bind_passwords_to_aps(&mut access_points);
        let aps_with_passwords: usize = access_points
            .iter()
            .filter(|ap| ap.password.is_some())
            .count();
        info!("Bound passwords to {} access points", aps_with_passwords);
    }

    print_observation_statistics(&access_points);

    for ap in access_points.iter_mut() {
        filter_close_observations(&mut ap.observations);

        match ap.observations.len() {
            0 => {}
            1 => {
                // TODO: I think we can use last position + velocity te prodict the AP potential direction and then une the dBm to estimate distance
                ap.estimated_position = Some(ap.observations[0].position.clone());
                ap.position_method = Some("single".to_string());
            }
            2 => {
                ap.estimated_position = weighted_centroid(&ap.observations);
                ap.position_method = Some("weighted_centroid".to_string());
            }
            _ => {
                ap.estimated_position = trilateration(&ap.observations);
                ap.position_method = Some("trilateration".to_string());
            }
        }

        trace!(
            "AP {:02x?} estimated position: {} using method: {}",
            ap.mac,
            ap.estimated_position
                .as_ref()
                .map_or("None".to_string(), |p| format!(
                    "{:.6}, {:.6}",
                    p.latitude, p.longitude
                )),
            ap.position_method
                .as_ref()
                .unwrap_or(&"unknown".to_string())
        );
    }

    if args.csv || args.csv_output.is_some() {
        export_to_csv(
            &access_points,
            args.csv_output.as_deref().unwrap_or("wifi_aps.csv"),
        );
    }
    if args.kml || args.kml_output.is_some() {
        export_to_kml(
            &access_points,
            args.kml_output.as_deref().unwrap_or("wifi_aps.kml"),
        )
        .unwrap();
    }

    if args.filter
        && (args.csv || args.csv_output.is_some() || args.kml || args.kml_output.is_some())
    {
        let filtered_aps: Vec<AccessPoint> = access_points
            .into_iter()
            .filter(|ap| match ap.security {
                Some(WifiSecurity::Open) | Some(WifiSecurity::WEP) => true,
                Some(WifiSecurity::WPA)
                | Some(WifiSecurity::WPA2)
                | Some(WifiSecurity::WPA3)
                | Some(WifiSecurity::WPA2WPA3) => ap.password.is_some(),
                Some(WifiSecurity::Unknown) => false,
                None => false,
            })
            .collect();

        if args.csv || args.csv_output.is_some() {
            let out_filename = match args.csv_output.as_deref() {
                Some(name) => {
                    let parts: Vec<&str> = name.rsplitn(2, '.').collect();
                    if parts.len() == 2 {
                        format!("{}_filtered.{}", parts[1], parts[0])
                    } else {
                        format!("{}_filtered", name)
                    }
                }
                None => "wifi_aps_filtered.csv".to_string(),
            };
            export_to_csv(&filtered_aps, &out_filename);
        }
        if args.kml || args.kml_output.is_some() {
            let out_filename = match args.kml_output.as_deref() {
                Some(name) => {
                    let parts: Vec<&str> = name.rsplitn(2, '.').collect();
                    if parts.len() == 2 {
                        format!("{}_filtered.{}", parts[1], parts[0])
                    } else {
                        format!("{}_filtered", name)
                    }
                }
                None => "wifi_aps_filtered.kml".to_string(),
            };
            export_to_kml(&filtered_aps, &out_filename).unwrap();
        }
    }
}

fn print_observation_statistics(access_points: &[AccessPoint]) {
    let mut obs_counts: HashMap<usize, usize> = HashMap::new();

    for ap in access_points {
        *obs_counts.entry(ap.observations.len()).or_insert(0) += 1;
    }

    let count_single_ap = obs_counts.get(&1).copied().unwrap_or(0);
    let count_weighted_centroid_ap = obs_counts.get(&2).copied().unwrap_or(0);
    let count_trilateration_ap = access_points.len() - count_single_ap - count_weighted_centroid_ap;

    if count_single_ap > 0 {
        warn!(
            "{} access points have only a single observation. Position estimates for these APs may be inaccurate.",
            count_single_ap
        );
    }
    if count_weighted_centroid_ap > 0 {
        warn!(
            "{} access points have only two observations. Position estimates for these APs may be inaccurate.",
            count_weighted_centroid_ap
        );
    }
    info!(
        "Using trilateration for {} access points with three or more observations.",
        count_trilateration_ap
    );
}

fn export_to_csv(access_points: &[AccessPoint], filename: &str) {
    let mut file = File::create(filename).unwrap();

    writeln!(
        file,
        "MAC,SSID,Security,Latitude,Longitude,Observations,Method,MinRSSI,MaxRSSI,AvgRSSI"
    )
    .unwrap();

    for ap in access_points
        .iter()
        .filter(|ap| ap.estimated_position.is_some())
    {
        let mac = format!(
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            ap.mac[0], ap.mac[1], ap.mac[2], ap.mac[3], ap.mac[4], ap.mac[5]
        );
        let ssid = ap
            .ssid
            .as_ref()
            .map(|s| s.replace(",", ";"))
            .unwrap_or_else(|| "".to_string());
        let security = ap
            .security
            .as_ref()
            .map(|s| s.to_string())
            .unwrap_or_else(|| "Unknown".to_string());

        if let Some(ref pos) = ap.estimated_position {
            let signals: Vec<i8> = ap.observations.iter().map(|o| o.signal_strength).collect();
            let min_rssi = signals.iter().min().unwrap_or(&0);
            let max_rssi = signals.iter().max().unwrap_or(&0);
            let avg_rssi = signals.iter().map(|&s| s as f64).sum::<f64>() / signals.len() as f64;

            writeln!(
                file,
                "{},{},{},{:.6},{:.6},{},{},{},{},{:.1}",
                mac,
                ssid,
                security,
                pos.latitude,
                pos.longitude,
                ap.observations.len(),
                ap.position_method
                    .as_ref()
                    .unwrap_or(&"unknown".to_string()),
                min_rssi,
                max_rssi,
                avg_rssi
            )
            .unwrap();
        }
    }

    info!("Exported results to {}", filename);
}
