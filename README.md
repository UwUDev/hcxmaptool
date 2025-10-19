# hxcmaptool

HCX Map tool is a WiFi access point mapping utility that processes packet capture files (.pcapng)
and GPS position (.nmea) logs to estimate the geographical locations of detected WiFi access
points. It can also bind known passwords to access points using Hashcat.

*Note:*
If there is less than 3 observations for an access point, the position is estimated using a simple
weighted centroid method based on signal strength or the last known position.

## Features
- KML output for easy visualization in mapping applications like Google Earth.
- CSV output for further data analysis.
- Hashcat-found password binding to access points.
- Filter interesting access points.

## Installation

`TODO`

## Building

This tool require cargo to build, if you don't have it installed, please refer to [the rustbook's installation guide](https://doc.rust-lang.org/cargo/getting-started/installation.html)

```bash
git clone https://github.com/UwUDev/hxcmaptool.git
cd hxcmaptool
cargo build --release
```

The binary will be located in `target/release/hxcmaptool(.exe)`.

## Usage

Usage:  hcxmaptool [options]


Options:

```
┌─────┬────────────┬─────────────────┬────────────────────────────────────────────────────────┐
│short│    long    │      value      │description                                             │
├─────┼────────────┼─────────────────┼────────────────────────────────────────────────────────┤
│ -h  │--help      │                 │                                                        │
│ -d  │--directory │WORKING DIRECTORY│Example: ./dumps                                        │
│ -f  │--filter    │                 │Filter interesting APs                                  │
│ -k  │--kml       │                 │Export the map to a KML file                            │
│     │--kml-output│    FILE PATH    │Path to output KML file                                 │
│ -c  │--csv       │                 │Export the access points to a CSV file                  │
│     │--csv-output│    FILE PATH    │Path to output CSV file                                 │
│     │--no-hashcat│                 │Disable hashcat password binding                        │
│     │--log-level │    LOG LEVEL    │Set the log level (off, error, warn, info, debug, trace)│
│     │            │                 │ Default: INFO                                          │
│ -V  │--version   │                 │Print version                                           │
└─────┴────────────┴─────────────────┴────────────────────────────────────────────────────────┘
```

Example:

```bash
hcxmaptool -d ./dumps -f -k --kml-output ./output/map.kml -c --csv-output ./output/aps.csv
```

A MKL will be generated only if the `-k|--kml` flag is provided or if `--kml-output` is used.
Similarly, a CSV will be generated only if the `-c|--csv` flag is provided or if `--csv-output` is used.