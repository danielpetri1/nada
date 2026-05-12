use clap::ValueEnum;
use foundations::telemetry::settings::LogVerbosity;
use foundations::telemetry::settings::LoggingSettings;
use foundations::telemetry::settings::MetricsSettings;
use foundations::telemetry::settings::TelemetrySettings;
use foundations::telemetry::settings::TracingSettings;
use foundations::telemetry::TelemetryConfig;

/// Initialize telemetry with the specified log verbosity level.
/// Logging is turned off when the verbosity is None.
pub fn init(verbosity: Option<LogVerbosity>) {
    if let Some(verbosity) = verbosity {
        foundations::telemetry::init(TelemetryConfig {
            service_info: &foundations::service_info!(),
            settings: &TelemetrySettings {
                logging: LoggingSettings {
                    output: Default::default(),
                    format: Default::default(),
                    verbosity,
                    redact_keys: Default::default(),
                    rate_limit: Default::default(),
                    log_volume_metrics: Default::default(),
                },
                metrics: MetricsSettings::default(),
                tracing: TracingSettings::default(),
            },
        })
        .expect("Failed to initialize the Telemetry config");
    }
}

#[derive(Clone, Debug, ValueEnum)]
pub enum LogLevel {
    Info,
    Debug,
    Trace,
    Off,
}

impl From<LogLevel> for Option<LogVerbosity> {
    fn from(arg: LogLevel) -> Self {
        match arg {
            LogLevel::Info => Some(LogVerbosity::Info),
            LogLevel::Debug => Some(LogVerbosity::Debug),
            LogLevel::Trace => Some(LogVerbosity::Trace),
            LogLevel::Off => None,
        }
    }
}
