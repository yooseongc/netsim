use thiserror::Error;

#[derive(Debug, Error)]
pub enum SimulationError {
    #[error("Invalid scenario: {0}")]
    InvalidScenario(String),

    #[error("Interface not found: {0}")]
    InterfaceNotFound(String),

    #[error("Routing table not found: {0}")]
    RoutingTableNotFound(u32),

    #[error("No route to host: {0}")]
    NoRouteToHost(String),

    #[error("Chain not found: {table}.{chain}")]
    ChainNotFound { table: String, chain: String },

    #[error("Simulation engine error: {0}")]
    EngineError(String),
}
