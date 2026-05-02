//! Pair clients ↔ servers ↔ specs by `(method, normalised_path)`.

use super::{spec::DiscoveredSpec, ClientCall, Method, ServerEndpoint, ServiceLink};

pub fn pair_clients_to_handlers(
    clients: &[ClientCall],
    handlers: &[ServerEndpoint],
    specs: &[DiscoveredSpec],
) -> Vec<ServiceLink> {
    let mut links = Vec::new();
    for client in clients {
        // First try exact handler match.
        if let Some(handler) = find_matching_handler(client, handlers) {
            links.push(ServiceLink {
                client:      client.clone(),
                handler:     Some(handler.clone()),
                matched_via: "direct".into(),
            });
            continue;
        }
        // Fall back to OpenAPI/Protobuf spec match.
        if let Some((spec_file, op)) = find_matching_spec(client, specs) {
            // Try to find a handler that matches the spec's path even
            // if it didn't directly match the client (different
            // normalised path styles).
            let handler = handlers.iter().find(|h| {
                h.method == op.method && h.normalised_path == op.normalised_path
            }).cloned();
            links.push(ServiceLink {
                client:      client.clone(),
                handler,
                matched_via: format!("spec:{}", spec_file.display()),
            });
            continue;
        }
        // Unmatched — still record the client so reviewers see the
        // out-of-repo call surface. Useful for "this controller hits an
        // external API" investigations.
        links.push(ServiceLink {
            client:      client.clone(),
            handler:     None,
            matched_via: "unmatched".into(),
        });
    }
    links
}

fn find_matching_handler<'a>(
    client: &ClientCall,
    handlers: &'a [ServerEndpoint],
) -> Option<&'a ServerEndpoint> {
    handlers.iter().find(|h| {
        h.normalised_path == client.normalised_path
            && (h.method == client.method
                || h.method == Method::Any
                || client.method == Method::Any)
    })
}

fn find_matching_spec<'a>(
    client: &ClientCall,
    specs: &'a [DiscoveredSpec],
) -> Option<(&'a std::path::Path, super::spec::SpecOperation)> {
    for spec in specs {
        if let Some(op) = spec.operations.iter().find(|op| {
            op.normalised_path == client.normalised_path
                && (op.method == client.method
                    || op.method == Method::Any
                    || client.method == Method::Any)
        }) {
            return Some((spec.file.as_path(), op.clone()));
        }
    }
    None
}
