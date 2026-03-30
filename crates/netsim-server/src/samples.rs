use axum::{Router, Json, extract::Path, routing::get};
use serde::Serialize;
use serde_json::Value;

use netsim_core::model::scenario::Scenario;

use crate::error::ApiError;

struct Sample {
    name: &'static str,
    description: &'static str,
    json: &'static str,
}

const SAMPLES: &[Sample] = &[
    Sample {
        name: "sample-basic-forward",
        description: "Basic packet forwarding between two interfaces (ip_forward=true)",
        json: include_str!("../samples/sample-basic-forward.json"),
    },
    Sample {
        name: "sample-dnat-port-forward",
        description: "DNAT port forwarding: external :80 → internal 192.168.1.100:8080",
        json: include_str!("../samples/sample-dnat-port-forward.json"),
    },
    Sample {
        name: "sample-snat-masquerade",
        description: "SNAT/Masquerade: internal client accessing internet through NAT",
        json: include_str!("../samples/sample-snat-masquerade.json"),
    },
    Sample {
        name: "sample-firewall-drop",
        description: "Firewall DROP: nftables input chain drops non-SSH traffic",
        json: include_str!("../samples/sample-firewall-drop.json"),
    },
    Sample {
        name: "sample-icmp-ping",
        description: "ICMP Ping: echo request to local address (LOCAL_DELIVERY)",
        json: include_str!("../samples/sample-icmp-ping.json"),
    },
    Sample {
        name: "sample-policy-routing",
        description: "Policy routing: fwmark-based routing via alternate table for HTTPS",
        json: include_str!("../samples/sample-policy-routing.json"),
    },
    Sample {
        name: "sample-xdp-filter",
        description: "XDP filter: drops packets from specific source IP before network stack",
        json: include_str!("../samples/sample-xdp-filter.json"),
    },
    Sample {
        name: "sample-bridge-forward",
        description: "Bridge L2 forwarding between member interfaces",
        json: include_str!("../samples/sample-bridge-forward.json"),
    },
    Sample {
        name: "sample-local-delivery",
        description: "Local delivery: TCP packet to local address reaches application",
        json: include_str!("../samples/sample-local-delivery.json"),
    },
    Sample {
        name: "sample-ttl-exceeded",
        description: "TTL exceeded: forwarded packet with TTL=1 is dropped",
        json: include_str!("../samples/sample-ttl-exceeded.json"),
    },
    Sample {
        name: "sample-mtu-exceeded",
        description: "MTU exceeded: large packet with DF flag exceeds egress MTU",
        json: include_str!("../samples/sample-mtu-exceeded.json"),
    },
    Sample {
        name: "sample-tproxy",
        description: "TPROXY: transparent proxy redirects HTTP to local Squid proxy",
        json: include_str!("../samples/sample-tproxy.json"),
    },
];

#[derive(Serialize)]
struct SampleListItem {
    name: String,
    description: String,
}

#[derive(Serialize)]
struct SampleListResponse {
    samples: Vec<SampleListItem>,
}

async fn list_samples() -> Json<Value> {
    let items: Vec<SampleListItem> = SAMPLES
        .iter()
        .map(|s| SampleListItem {
            name: s.name.to_string(),
            description: s.description.to_string(),
        })
        .collect();
    Json(serde_json::to_value(SampleListResponse { samples: items }).unwrap())
}

async fn get_sample(Path(name): Path<String>) -> Result<Json<Value>, ApiError> {
    let sample = SAMPLES
        .iter()
        .find(|s| s.name == name)
        .ok_or_else(|| ApiError::NotFound(format!("Sample '{}' not found", name)))?;

    let scenario: Scenario = serde_json::from_str(sample.json)
        .map_err(|e| ApiError::Internal(format!("Failed to parse sample: {}", e)))?;

    let value = serde_json::to_value(scenario)
        .map_err(|e| ApiError::Internal(format!("Failed to serialize sample: {}", e)))?;
    Ok(Json(value))
}

async fn simulate_sample(Path(name): Path<String>) -> Result<Json<Value>, ApiError> {
    let sample = SAMPLES
        .iter()
        .find(|s| s.name == name)
        .ok_or_else(|| ApiError::NotFound(format!("Sample '{}' not found", name)))?;

    let scenario: Scenario = serde_json::from_str(sample.json)
        .map_err(|e| ApiError::Internal(format!("Failed to parse sample: {}", e)))?;

    let result = netsim_core::engine::run(&scenario);

    let value = serde_json::to_value(&result)
        .map_err(|e| ApiError::Internal(format!("Failed to serialize result: {}", e)))?;
    Ok(Json(value))
}

pub fn routes() -> Router {
    Router::new()
        .route("/samples", get(list_samples))
        .route("/samples/{name}", get(get_sample))
        .route("/samples/{name}/simulate", axum::routing::post(simulate_sample))
}
