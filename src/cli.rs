use clap::Parser;

#[derive(Parser, Debug)]
#[command(
    name = env!("CARGO_PKG_NAME"),
    author = env!("CARGO_PKG_AUTHORS"),
    version,
    about,
    disable_help_flag = true
)]
pub struct Args {
    #[arg(long, short)]
    pub help: bool,

    #[arg(
        short = 'd',
        long,
        value_name = "WORKING DIRECTORY",
        help = "Example: `./dumps`"
    )]
    pub directory: Option<String>,

    #[arg(short, long, help = "Filter interesting APs")]
    pub filter: bool,

    // kml export options
    #[arg(short, long, help = "Export the map to a KML file")]
    pub kml: bool,

    #[arg(long, help = "Path to output KML file", value_name = "FILE PATH")]
    pub kml_output: Option<String>,

    // csv export options
    #[arg(short, long, help = "Export the access points to a CSV file")]
    pub csv: bool,

    #[arg(long, help = "Path to output CSV file", value_name = "FILE PATH")]
    pub csv_output: Option<String>,

    // hashcat options
    #[arg(long, help = "Disable hashcat password binding")]
    pub no_hashcat: bool,

    // log level logging
    #[arg(
        long,
        help = "Set the log level (off, error, warn, info, debug, trace)",
        default_value_t = log::LevelFilter::Info,
        value_name = "LOG LEVEL"
    )]
    pub log_level: log::LevelFilter,
}

pub static INTRO: &str = "
HCX Map tool is a WiFi access point mapping utility that processes packet capture files (.pcapng)
and GPS position (.nmea) logs to estimate the geographical locations of detected WiFi access
points. It can also bind known passwords to access points using Hashcat.

*Note:*
If there is less than 3 observations for an access point, the position is estimated using a simple
weighted centroid method based on signal strength or the last known position.
";
