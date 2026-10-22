-- ClickHouse Initialization Script for JDP Route Intelligence Platform
-- Database: jdp_flow_analytics

CREATE DATABASE IF NOT EXISTS jdp_flow_analytics;

USE jdp_flow_analytics;

-- 1. Raw Flow Telemetry Table (Partitioned by Month, High Compression)
CREATE TABLE IF NOT EXISTS flow_records
(
    timestamp DateTime64(3, 'UTC') CODEC(DoubleDelta, ZSTD(1)),
    site_id LowCardinality(String) CODEC(ZSTD(1)),
    exporter_ip String CODEC(ZSTD(1)),
    src_ip String CODEC(ZSTD(1)),
    dst_ip String CODEC(ZSTD(1)),
    src_port UInt16 CODEC(DoubleDelta, ZSTD(1)),
    dst_port UInt16 CODEC(DoubleDelta, ZSTD(1)),
    protocol UInt8 CODEC(ZSTD(1)),
    tcp_flags UInt8 CODEC(ZSTD(1)),
    packets UInt64 CODEC(T64, ZSTD(1)),
    bytes UInt64 CODEC(T64, ZSTD(1)),
    input_snmp UInt32 CODEC(T64, ZSTD(1)),
    output_snmp UInt32 CODEC(T64, ZSTD(1)),
    next_hop String CODEC(ZSTD(1)),
    src_as UInt32 CODEC(T64, ZSTD(1)),
    dst_as UInt32 CODEC(T64, ZSTD(1)),
    sampling_rate UInt32 DEFAULT 1 CODEC(T64, ZSTD(1)),
    flow_format LowCardinality(String) CODEC(ZSTD(1)),
    is_demo UInt8 DEFAULT 0 CODEC(ZSTD(1))
)
ENGINE = MergeTree()
PARTITION BY toYYYYMM(timestamp)
PRIMARY KEY (site_id, exporter_ip, protocol)
ORDER BY (site_id, exporter_ip, protocol, timestamp, src_ip, dst_ip)
TTL toDateTime(timestamp) + INTERVAL 30 DAY;

-- 2. Hourly Materialized Aggregate Table for Fast Trend Queries
CREATE TABLE IF NOT EXISTS flow_hourly_agg
(
    hour_bucket DateTime('UTC'),
    site_id LowCardinality(String),
    exporter_ip String,
    protocol UInt8,
    src_as UInt32,
    dst_as UInt32,
    total_packets SimpleAggregateFunction(sum, UInt64),
    total_bytes SimpleAggregateFunction(sum, UInt64),
    record_count SimpleAggregateFunction(sum, UInt64)
)
ENGINE = AggregatingMergeTree()
PARTITION BY toYYYYMM(hour_bucket)
PRIMARY KEY (site_id, protocol)
ORDER BY (site_id, protocol, hour_bucket, exporter_ip, src_as, dst_as)
TTL hour_bucket + INTERVAL 90 DAY;

-- 3. Materialized View feeding flow_hourly_agg
CREATE MATERIALIZED VIEW IF NOT EXISTS flow_hourly_agg_mv
TO flow_hourly_agg AS
SELECT
    toStartOfHour(timestamp) AS hour_bucket,
    site_id,
    exporter_ip,
    protocol,
    src_as,
    dst_as,
    sum(packets) AS total_packets,
    sum(bytes) AS total_bytes,
    count() AS record_count
FROM flow_records
GROUP BY
    hour_bucket,
    site_id,
    exporter_ip,
    protocol,
    src_as,
    dst_as;
