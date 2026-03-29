//! Flow expansion logic
//!
//! Converts TrafficFlow definitions (endpoint-to-endpoint) into concrete
//! simulation runs (ingress or output path).

use crate::model::endpoint::{Endpoint, EndpointRole, TrafficFlow};
use crate::model::packet::PacketDef;
use crate::model::scenario::Scenario;

/// A single simulation run derived from a traffic flow
#[derive(Debug, Clone)]
pub enum SimulationRun {
    /// Ingress packet — run through engine::run()
    Ingress(PacketDef),
    /// Output packet — run through engine::run_output()
    Output(PacketDef),
}

/// Expand a TrafficFlow into a sequence of simulation runs.
///
/// Each flow between endpoints produces one or more simulation runs
/// depending on the endpoint roles:
///
/// - RemoteClient → LocalServer: Ingress
/// - LocalClient → RemoteServer: Output
/// - RemoteClient → LocalProxy → RemoteServer: Ingress + Output
/// - RemoteClient → LocalTProxy → RemoteServer: Ingress + Output
pub fn expand_flow(
    scenario: &Scenario,
    flow: &TrafficFlow,
) -> Vec<(String, SimulationRun)> {
    let topology = match &scenario.topology {
        Some(t) => t,
        None => return vec![],
    };

    let source = topology.endpoints.iter().find(|e| e.name == flow.source);
    let dest = topology.endpoints.iter().find(|e| e.name == flow.destination);

    let (source, dest) = match (source, dest) {
        (Some(s), Some(d)) => (s, d),
        _ => return vec![],
    };

    match (&source.role, &dest.role) {
        // Remote → Local: ingress packet
        (EndpointRole::RemoteClient, EndpointRole::LocalServer)
        | (EndpointRole::RemoteClient, EndpointRole::LocalProxy)
        | (EndpointRole::RemoteClient, EndpointRole::LocalTProxy) => {
            let packet = build_packet_def(source, dest, flow);
            vec![(
                format!("{}: {} → {}", flow.name, source.name, dest.name),
                SimulationRun::Ingress(packet),
            )]
        }

        // Local → Remote: output packet
        (EndpointRole::LocalClient, EndpointRole::RemoteServer) => {
            let packet = build_output_packet_def(source, dest, flow);
            vec![(
                format!("{}: {} → {}", flow.name, source.name, dest.name),
                SimulationRun::Output(packet),
            )]
        }

        // Proxy flows: ingress (Remote→Proxy) + output (Proxy→Remote)
        (EndpointRole::RemoteClient, EndpointRole::RemoteServer) => {
            // Check if there's an intermediate proxy by looking at other endpoints
            // For direct remote-to-remote through this host, it's a forwarding scenario
            let packet = build_packet_def(source, dest, flow);
            vec![(
                format!("{}: {} → {} (forward)", flow.name, source.name, dest.name),
                SimulationRun::Ingress(packet),
            )]
        }

        // LocalProxy/LocalTProxy → RemoteServer: output leg of a proxy flow
        (EndpointRole::LocalProxy, EndpointRole::RemoteServer)
        | (EndpointRole::LocalTProxy, EndpointRole::RemoteServer) => {
            let packet = build_output_packet_def(source, dest, flow);
            vec![(
                format!("{}: {} → {} (proxy output)", flow.name, source.name, dest.name),
                SimulationRun::Output(packet),
            )]
        }

        // LocalServer → RemoteClient: output response
        (EndpointRole::LocalServer, EndpointRole::RemoteClient) => {
            let packet = build_output_packet_def(source, dest, flow);
            vec![(
                format!("{}: {} → {} (response)", flow.name, source.name, dest.name),
                SimulationRun::Output(packet),
            )]
        }

        _ => vec![],
    }
}

/// Build a PacketDef for ingress traffic (from remote endpoint)
fn build_packet_def(source: &Endpoint, dest: &Endpoint, flow: &TrafficFlow) -> PacketDef {
    let protocol = parse_protocol(flow.protocol.as_deref());
    PacketDef {
        ingress_interface: source.interface.clone().unwrap_or_default(),
        src_ip: Some(source.ip),
        dst_ip: Some(dest.ip),
        src_port: source.port,
        dst_port: dest.port,
        protocol,
        ..PacketDef::default()
    }
}

/// Build a PacketDef for output traffic (from local endpoint)
fn build_output_packet_def(source: &Endpoint, dest: &Endpoint, flow: &TrafficFlow) -> PacketDef {
    let protocol = parse_protocol(flow.protocol.as_deref());
    PacketDef {
        ingress_interface: source.interface.clone().unwrap_or_else(|| "lo".to_string()),
        src_ip: Some(source.ip),
        dst_ip: Some(dest.ip),
        src_port: source.port,
        dst_port: dest.port,
        protocol,
        ..PacketDef::default()
    }
}

fn parse_protocol(proto: Option<&str>) -> crate::model::packet::IpProtocol {
    match proto {
        Some("tcp") | Some("TCP") => crate::model::packet::IpProtocol::Tcp,
        Some("udp") | Some("UDP") => crate::model::packet::IpProtocol::Udp,
        Some("icmp") | Some("ICMP") => crate::model::packet::IpProtocol::Icmp,
        _ => crate::model::packet::IpProtocol::Tcp,
    }
}
