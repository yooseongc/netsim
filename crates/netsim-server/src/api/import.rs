use std::sync::Arc;

use axum::extract::{Path, State};
use axum::routing::post;
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{json, Value};

use netsim_core::model::scenario::Scenario;
use netsim_core::model::packet::PacketDef;
use netsim_parser::{SystemConfigInput, parse_system_config};

use crate::error::ApiError;
use crate::state::AppState;

#[derive(Debug, Deserialize)]
pub struct ParseRequest {
    #[serde(default)]
    pub ip_addr: Option<String>,
    #[serde(default)]
    pub ip_rule: Option<String>,
    #[serde(default)]
    pub ip_route: Option<String>,
    #[serde(default)]
    pub nft_list_ruleset: Option<String>,
    #[serde(default)]
    pub iptables_save: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct ImportRequest {
    #[serde(default)]
    pub ip_addr: Option<String>,
    #[serde(default)]
    pub ip_rule: Option<String>,
    #[serde(default)]
    pub ip_route: Option<String>,
    #[serde(default)]
    pub nft_list_ruleset: Option<String>,
    #[serde(default)]
    pub iptables_save: Option<String>,
    #[serde(default = "default_merge_strategy")]
    pub merge_strategy: String,
}

fn default_merge_strategy() -> String {
    "replace".to_string()
}

pub fn routes(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/import/parse", post(parse_config))
        .route("/import/preview", post(preview_config))
        .route("/projects/{name}/import", post(import_to_project))
        .with_state(state)
}

fn to_system_config_input(req: &ParseRequest) -> SystemConfigInput {
    SystemConfigInput {
        ip_addr: req.ip_addr.clone(),
        ip_rule: req.ip_rule.clone(),
        ip_route: req.ip_route.clone(),
        nft_list_ruleset: req.nft_list_ruleset.clone(),
        iptables_save: req.iptables_save.clone(),
    }
}

fn to_system_config_input_from_import(req: &ImportRequest) -> SystemConfigInput {
    SystemConfigInput {
        ip_addr: req.ip_addr.clone(),
        ip_rule: req.ip_rule.clone(),
        ip_route: req.ip_route.clone(),
        nft_list_ruleset: req.nft_list_ruleset.clone(),
        iptables_save: req.iptables_save.clone(),
    }
}

async fn parse_config(
    Json(req): Json<ParseRequest>,
) -> Result<Json<Value>, ApiError> {
    let input = to_system_config_input(&req);
    let result = parse_system_config(&input);

    let partial = &result.data;
    Ok(Json(json!({
        "scenario": {
            "interfaces": partial.interfaces,
            "routing_tables": partial.routing_tables,
            "ip_rules": partial.ip_rules,
            "netfilter": partial.netfilter,
        },
        "validation": result.report,
    })))
}

async fn preview_config(
    Json(req): Json<ParseRequest>,
) -> Result<Json<Value>, ApiError> {
    // Same as parse for now
    let input = to_system_config_input(&req);
    let result = parse_system_config(&input);

    let partial = &result.data;
    Ok(Json(json!({
        "scenario": {
            "interfaces": partial.interfaces,
            "routing_tables": partial.routing_tables,
            "ip_rules": partial.ip_rules,
            "netfilter": partial.netfilter,
        },
        "validation": result.report,
    })))
}

async fn import_to_project(
    State(state): State<Arc<AppState>>,
    Path(name): Path<String>,
    Json(req): Json<ImportRequest>,
) -> Result<Json<Value>, ApiError> {
    // Verify project exists
    state.storage.get_project(&name)?;

    let input = to_system_config_input_from_import(&req);
    let result = parse_system_config(&input);
    let partial = result.data;

    let scenario = if req.merge_strategy == "merge" {
        // Try to load existing scenario and merge
        match state.storage.get_scenario(&name) {
            Ok(mut existing) => {
                // Merge: extend existing with imported data
                if !partial.interfaces.is_empty() {
                    // Replace interfaces that share the same name, add new ones
                    for iface in partial.interfaces {
                        if let Some(pos) = existing.interfaces.iter().position(|i| i.name == iface.name) {
                            existing.interfaces[pos] = iface;
                        } else {
                            existing.interfaces.push(iface);
                        }
                    }
                }
                if !partial.routing_tables.is_empty() {
                    for rt in partial.routing_tables {
                        if let Some(pos) = existing.routing_tables.iter().position(|t| t.id == rt.id) {
                            existing.routing_tables[pos] = rt;
                        } else {
                            existing.routing_tables.push(rt);
                        }
                    }
                }
                if !partial.ip_rules.is_empty() {
                    existing.ip_rules = partial.ip_rules;
                }
                if partial.netfilter.nftables.is_some() {
                    existing.netfilter.nftables = partial.netfilter.nftables;
                }
                if partial.netfilter.iptables.is_some() {
                    existing.netfilter.iptables = partial.netfilter.iptables;
                }
                existing
            }
            Err(_) => {
                // No existing scenario, create new one from partial
                build_scenario_from_partial(&name, partial)
            }
        }
    } else {
        // Replace strategy: build new scenario from partial
        build_scenario_from_partial(&name, partial)
    };

    state.storage.save_scenario(&name, &scenario)?;

    Ok(Json(json!({
        "scenario": scenario,
        "validation": result.report,
    })))
}

fn build_scenario_from_partial(
    project_name: &str,
    partial: netsim_parser::PartialScenario,
) -> Scenario {
    // Determine a default ingress interface
    let ingress = partial
        .interfaces
        .first()
        .map(|i| i.name.clone())
        .unwrap_or_else(|| "eth0".to_string());

    Scenario {
        version: "1.0".to_string(),
        name: project_name.to_string(),
        description: None,
        interfaces: partial.interfaces,
        routing_tables: partial.routing_tables,
        ip_rules: partial.ip_rules,
        netfilter: partial.netfilter,
        xdp: Default::default(),
        sysctl: Default::default(),
        packet: PacketDef {
            ingress_interface: ingress,
            ethertype: Default::default(),
            vlan_id: None,
            src_mac: None,
            dst_mac: None,
            src_ip: None,
            dst_ip: None,
            protocol: Default::default(),
            src_port: None,
            dst_port: None,
            tcp_flags: None,
            icmp_type: None,
            icmp_code: None,
            arp: None,
            packet_length: None,
            df_flag: false,
            dscp: None,
            ttl: None,
            initial_mark: 0,
            initial_ct_mark: 0,
            conntrack_state: Default::default(),
        },
    }
}
