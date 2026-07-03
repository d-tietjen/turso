use fast_telemetry::{Counter, DeriveLabel, ExportMetrics, LabeledCounter, LabeledHistogram};

/// Endpoints served by [`crate::sync_server::TursoSyncServer`].
#[derive(Copy, Clone, Debug, DeriveLabel)]
#[label_name = "endpoint"]
pub enum SyncEndpoint {
    Pipeline,
    PullUpdates,
    Metrics,
    #[label = "other"]
    Unknown,
}

/// Prometheus metrics for [`crate::sync_server::TursoSyncServer`].
///
/// Counters are sharded by CPU count since the accept loop may move to a
/// thread (or task) per connection; a single shared atomic would otherwise
/// become a point of contention as concurrency grows.
#[derive(ExportMetrics)]
#[metric_prefix = "turso_sync_server"]
pub struct SyncServerMetrics {
    #[help = "Total sync server requests handled"]
    requests_total: Counter,

    #[help = "Requests by endpoint"]
    requests_by_endpoint: LabeledCounter<SyncEndpoint>,

    #[help = "Request latency by endpoint, in microseconds"]
    latency_by_endpoint: LabeledHistogram<SyncEndpoint>,

    #[help = "Requests that returned a 4xx or 5xx status"]
    errors_total: Counter,

    #[help = "Total bytes received from clients"]
    bytes_received: Counter,

    #[help = "Total bytes sent to clients"]
    bytes_sent: Counter,
}

impl Default for SyncServerMetrics {
    fn default() -> Self {
        Self::new()
    }
}

impl SyncServerMetrics {
    pub fn new() -> Self {
        let shards = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1);
        Self {
            requests_total: Counter::new(shards),
            requests_by_endpoint: LabeledCounter::new(shards),
            latency_by_endpoint: LabeledHistogram::with_latency_buckets(shards),
            errors_total: Counter::new(shards),
            bytes_received: Counter::new(shards),
            bytes_sent: Counter::new(shards),
        }
    }

    pub fn record_request(&self, endpoint: SyncEndpoint, status: u16, elapsed_micros: u64) {
        self.requests_total.inc();
        self.requests_by_endpoint.inc(endpoint);
        self.latency_by_endpoint.record(endpoint, elapsed_micros);
        if status >= 400 {
            self.errors_total.inc();
        }
    }

    pub fn record_bytes_received(&self, bytes: usize) {
        self.bytes_received.add(bytes as isize);
    }

    pub fn record_bytes_sent(&self, bytes: usize) {
        self.bytes_sent.add(bytes as isize);
    }

    pub fn render_prometheus(&self) -> String {
        let mut output = String::new();
        self.export_prometheus(&mut output);
        output
    }
}
