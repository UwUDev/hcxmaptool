use crate::WORKING_DIR;
use chrono::Datelike;
use chrono::{NaiveDate, NaiveDateTime};
use log::trace;
use nmea::Nmea;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::time::Duration;

const RSSI_AT_1M: f64 = -35.0;
const PATH_LOSS_EXPONENT: f64 = 2.5;
const MIN_DISTANCE_BETWEEN_OBS: f64 = 5.0; // meters

#[derive(Debug, Clone)]
pub struct Position {
    pub latitude: f64,
    pub longitude: f64,
    pub timestamp: i64,
}

#[derive(Debug, Clone)]
pub struct Observation {
    pub position: Position,
    pub signal_strength: i8,
    pub distance: f64,
}

pub fn haversine_distance(lat1: f64, lon1: f64, lat2: f64, lon2: f64) -> f64 {
    const R: f64 = 6378000.0; // earth radius in meters

    let lat1_rad = lat1.to_radians();
    let lat2_rad = lat2.to_radians();
    let dlat = (lat2 - lat1).to_radians();
    let dlon = (lon2 - lon1).to_radians();

    let a =
        (dlat / 2.0).sin().powi(2) + lat1_rad.cos() * lat2_rad.cos() * (dlon / 2.0).sin().powi(2);
    let c = 2.0 * a.sqrt().atan2((1.0 - a).sqrt());

    R * c
}

pub fn weighted_centroid(observations: &[Observation]) -> Option<Position> {
    if observations.is_empty() {
        return None;
    }

    // convert RSSI to weights (stronger signal = higher weight)
    // Map -100 to 0 dBm --> 0 to 100 scale
    let mut total_weight = 0.0;
    let mut weighted_lat = 0.0;
    let mut weighted_lon = 0.0;

    for obs in observations {
        // linear mapping: -100 dBm --> 0, -25 dBm --> 100
        let weight = ((obs.signal_strength as f64 + 100.0) / 75.0 * 100.0).max(0.0);
        total_weight += weight;
        weighted_lat += obs.position.latitude * weight;
        weighted_lon += obs.position.longitude * weight;
    }

    if total_weight == 0.0 {
        // "classic" centroid fallback
        let lat = observations
            .iter()
            .map(|o| o.position.latitude)
            .sum::<f64>()
            / observations.len() as f64;
        let lon = observations
            .iter()
            .map(|o| o.position.longitude)
            .sum::<f64>()
            / observations.len() as f64;
        return Some(Position {
            latitude: lat,
            longitude: lon,
            timestamp: observations[0].position.timestamp,
        });
    }

    Some(Position {
        latitude: weighted_lat / total_weight,
        longitude: weighted_lon / total_weight,
        timestamp: observations[0].position.timestamp,
    })
}

pub fn trilateration(observations: &[Observation]) -> Option<Position> {
    if observations.len() < 3 {
        return weighted_centroid(observations);
    }

    // start from weighted centroid
    let initial = weighted_centroid(observations)?;
    let mut est_lat = initial.latitude;
    let mut est_lon = initial.longitude;

    const MAX_ITERATIONS: usize = 100;
    const LEARNING_RATE: f64 = 0.001;
    const CONVERGENCE_THRESHOLD: f64 = 0.000001;

    for _ in 0..MAX_ITERATIONS {
        let mut grad_lat = 0.0;
        let mut grad_lon = 0.0;
        let mut total_weight = 0.0;

        for obs in observations {
            let cos_lat = est_lat.to_radians().cos();
            // prevent division by zero
            if cos_lat.abs() < 0.01 {
                continue;
            }

            let dx = (est_lon - obs.position.longitude) * 111320.0 * cos_lat;
            let dy = (est_lat - obs.position.latitude) * 110540.0;
            let calculated_distance = (dx * dx + dy * dy).sqrt();

            if calculated_distance < 0.1 {
                continue;
            }

            let error = calculated_distance - obs.distance;

            // higher weight for stronger signals (less negative RSSI)
            // -100 dBm --> 0.0, -30 dBm --> 1.0
            let weight = ((obs.signal_strength as f64 + 100.0) / 70.0).clamp(0.0, 1.0);
            let weight_sq = weight * weight; // Square for more emphasis

            grad_lat += weight_sq * error * dy / calculated_distance / 110540.0;
            grad_lon += weight_sq * error * dx / calculated_distance / (111320.0 * cos_lat);
            total_weight += weight_sq;
        }

        // fallback to weighted centroid
        if total_weight == 0.0 {
            return Some(initial);
        }

        // normalize gradients by total weight
        grad_lat /= total_weight;
        grad_lon /= total_weight;

        let update_lat = grad_lat * LEARNING_RATE;
        let update_lon = grad_lon * LEARNING_RATE;

        est_lat -= update_lat;
        est_lon -= update_lon;

        if update_lat.abs() < CONVERGENCE_THRESHOLD && update_lon.abs() < CONVERGENCE_THRESHOLD {
            break;
        }
    }

    Some(Position {
        latitude: est_lat,
        longitude: est_lon,
        timestamp: observations.first()?.position.timestamp,
    })
}

pub fn get_position_at(timestamp: &Duration, positions: &[Position]) -> Option<Position> {
    let timestamp_secs = timestamp.as_secs() as i64;

    if positions.is_empty() {
        return None;
    }

    if positions.len() == 1 {
        return Some(positions[0].clone());
    }

    for i in 0..positions.len() - 1 {
        let pos1 = &positions[i];
        let pos2 = &positions[i + 1];

        if timestamp_secs >= pos1.timestamp && timestamp_secs <= pos2.timestamp {
            let ratio = if pos2.timestamp != pos1.timestamp {
                (timestamp_secs - pos1.timestamp) as f64 / (pos2.timestamp - pos1.timestamp) as f64
            } else {
                0.0
            };

            let latitude = pos1.latitude + (pos2.latitude - pos1.latitude) * ratio;
            let longitude = pos1.longitude + (pos2.longitude - pos1.longitude) * ratio;

            return Some(Position {
                latitude,
                longitude,
                timestamp: timestamp_secs,
            });
        }
    }
    None
}

pub fn rssi_to_distance(rssi: i8) -> f64 {
    let rssi_f64 = rssi as f64;
    let distance = 10_f64.powf((RSSI_AT_1M - rssi_f64) / (10.0 * PATH_LOSS_EXPONENT));
    trace!(
        "Estimated distance for RSSI {} dBm: {:.2} meters",
        rssi, distance
    );
    distance
}

pub fn filter_close_observations(observations: &mut Vec<Observation>) {
    if observations.len() <= 1 {
        return;
    }

    observations.sort_by(|a, b| b.signal_strength.cmp(&a.signal_strength));

    let mut filtered = Vec::new();
    filtered.push(observations[0].clone());

    for obs in observations.iter().skip(1) {
        let mut keep = true;
        for existing in &filtered {
            let dist = haversine_distance(
                obs.position.latitude,
                obs.position.longitude,
                existing.position.latitude,
                existing.position.longitude,
            );
            if dist < MIN_DISTANCE_BETWEEN_OBS {
                keep = false;
                break;
            }
        }
        if keep {
            filtered.push(obs.clone());
        }
    }

    *observations = filtered;
}

pub fn get_positions() -> Vec<Position> {
    let mut nmea = Nmea::default();
    let mut positions: Vec<Position> = Vec::new();

    let paths = std::fs::read_dir(WORKING_DIR.lock().unwrap().as_str()).unwrap();
    for path in paths {
        let path = path.unwrap().path();
        if path.is_file() && path.extension().and_then(|s| s.to_str()) == Some("nmea") {
            let mut input = BufReader::new(File::open(path).unwrap());
            loop {
                let mut buffer = String::new();
                let size = input.read_line(&mut buffer).unwrap();

                if size == 0 {
                    break;
                }

                if buffer.starts_with("{") {
                    continue;
                }

                let res = nmea.parse(&buffer);
                if res.is_err() {
                    continue;
                }
                res.unwrap();

                if let Some(fix_time) = nmea.fix_time {
                    if let Some(latitude) = nmea.latitude {
                        if let Some(longitude) = nmea.longitude {
                            if let Some(fix_date) = nmea.fix_date {
                                let datetime = NaiveDateTime::new(
                                    NaiveDate::from_ymd_opt(
                                        fix_date.year() as i32,
                                        fix_date.month() as u32,
                                        fix_date.day() as u32,
                                    )
                                    .unwrap(),
                                    fix_time,
                                );

                                let timestamp = datetime.and_utc().timestamp();

                                positions.push(Position {
                                    latitude,
                                    longitude,
                                    timestamp,
                                });
                            }
                        }
                    }
                }
            }
        }
    }

    positions.sort_by_key(|p| p.timestamp);

    positions
}
