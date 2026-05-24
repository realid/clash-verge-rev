use anyhow::{Context as _, Result};
use base64::{Engine as _, engine::general_purpose};
use percent_encoding::percent_decode_str;
use serde_json::Value as JsonValue;
use serde_yaml_ng::{Mapping, Value};

fn decode_base64_any(input: &str) -> Option<String> {
    let mut text: String = input.trim().chars().filter(|c| !c.is_whitespace()).collect();
    if text.is_empty() {
        return None;
    }

    let padding = (4 - text.len() % 4) % 4;
    if padding > 0 {
        text.extend(std::iter::repeat_n('=', padding));
    }

    let decoded = general_purpose::STANDARD.decode(text).ok()?;
    let decoded = String::from_utf8(decoded).ok()?;
    let decoded = decoded.trim().to_owned();
    if decoded.is_empty() {
        return None;
    }
    Some(decoded)
}

fn split_subscription_lines(body: &str) -> Vec<&str> {
    body.lines()
        .map(str::trim)
        .filter(|line| line.starts_with("ss://") || line.starts_with("vmess://"))
        .collect()
}

fn to_yaml_string_value(value: &str) -> Value {
    Value::String(value.to_owned())
}

fn insert_yaml_value(mapping: &mut Mapping, key: &str, value: Value) {
    mapping.insert(Value::String(key.to_owned()), value);
}

fn mapping_get_str<'a>(mapping: &'a Mapping, key: &str) -> Option<&'a str> {
    mapping
        .iter()
        .find_map(|(k, v)| if k.as_str()? == key { v.as_str() } else { None })
}

fn parse_ss_node(line: &str) -> Option<Mapping> {
    let payload = line.strip_prefix("ss://")?;
    let (payload, tag) = payload.split_once('#').unwrap_or((payload, ""));
    let decoded = decode_base64_any(payload)?;
    let (method_password, server_port) = decoded.rsplit_once('@')?;
    let (cipher, password) = method_password.split_once(':')?;
    let (server, port_text) = server_port.rsplit_once(':')?;
    let port: i64 = port_text.parse().ok()?;

    let tag = percent_decode_str(tag).decode_utf8_lossy();
    let name = if tag.is_empty() {
        format!("ss@{server}:{port}")
    } else {
        tag.into_owned()
    };

    let mut node = Mapping::new();
    insert_yaml_value(&mut node, "name", to_yaml_string_value(&name));
    insert_yaml_value(&mut node, "type", to_yaml_string_value("ss"));
    insert_yaml_value(&mut node, "server", to_yaml_string_value(server));
    insert_yaml_value(&mut node, "port", Value::from(port));
    insert_yaml_value(&mut node, "cipher", to_yaml_string_value(cipher));
    insert_yaml_value(&mut node, "password", to_yaml_string_value(password));
    insert_yaml_value(&mut node, "udp", Value::from(true));
    Some(node)
}

fn parse_vmess_node(line: &str) -> Option<Mapping> {
    let payload = line.strip_prefix("vmess://")?;
    let decoded = decode_base64_any(payload)?;
    let data: JsonValue = serde_json::from_str(&decoded).ok()?;

    let port = data
        .get("port")
        .and_then(|v| {
            v.as_str()
                .map(str::to_owned)
                .or_else(|| v.as_i64().map(|n| n.to_string()))
        })
        .and_then(|v| v.parse::<i64>().ok())?;
    let server = data.get("add")?.as_str()?.to_owned();
    let name = data
        .get("ps")
        .and_then(|v| v.as_str())
        .filter(|v| !v.is_empty())
        .map(|v| v.to_owned())
        .unwrap_or_else(|| format!("vmess@{server}:{port}"));
    let uuid = data.get("id")?.as_str()?.to_owned();
    let alter_id = data
        .get("aid")
        .and_then(|v| {
            v.as_str()
                .map(str::to_owned)
                .or_else(|| v.as_i64().map(|n| n.to_string()))
        })
        .as_deref()
        .unwrap_or("0")
        .parse::<i64>()
        .unwrap_or(0);

    let mut node = Mapping::new();
    insert_yaml_value(&mut node, "name", to_yaml_string_value(&name));
    insert_yaml_value(&mut node, "type", to_yaml_string_value("vmess"));
    insert_yaml_value(&mut node, "server", to_yaml_string_value(&server));
    insert_yaml_value(&mut node, "port", Value::from(port));
    insert_yaml_value(&mut node, "uuid", to_yaml_string_value(&uuid));
    insert_yaml_value(&mut node, "alterId", Value::from(alter_id));
    insert_yaml_value(&mut node, "cipher", to_yaml_string_value("auto"));
    insert_yaml_value(&mut node, "udp", Value::from(true));

    let network = data.get("net").and_then(|v| v.as_str()).unwrap_or("tcp");
    if network != "tcp" {
        insert_yaml_value(&mut node, "network", to_yaml_string_value(network));
    }

    let tls_enabled = data
        .get("tls")
        .and_then(|v| v.as_str())
        .map(|v| matches!(v.to_ascii_lowercase().as_str(), "tls" | "true" | "1"))
        .unwrap_or(false);
    if tls_enabled {
        insert_yaml_value(&mut node, "tls", Value::from(true));
    }

    if network == "ws" {
        let mut ws_opts = Mapping::new();
        if let Some(path) = data.get("path").and_then(|v| v.as_str()).filter(|v| !v.is_empty()) {
            insert_yaml_value(&mut ws_opts, "path", to_yaml_string_value(path));
        }
        if let Some(host) = data.get("host").and_then(|v| v.as_str()).filter(|v| !v.is_empty()) {
            let mut headers = Mapping::new();
            insert_yaml_value(&mut headers, "Host", to_yaml_string_value(host));
            insert_yaml_value(&mut ws_opts, "headers", Value::Mapping(headers));
        }
        if !ws_opts.is_empty() {
            insert_yaml_value(&mut node, "ws-opts", Value::Mapping(ws_opts));
        }
    }

    Some(node)
}

fn parse_nodes(body: &str) -> Vec<Mapping> {
    split_subscription_lines(body)
        .into_iter()
        .filter_map(|line| parse_ss_node(line).or_else(|| parse_vmess_node(line)))
        .collect()
}

fn build_clash_yaml(nodes: Vec<Mapping>) -> Result<String> {
    if nodes.is_empty() {
        return Err(anyhow::anyhow!("JMS subscription parsed to zero nodes"));
    }

    let proxy_names = nodes
        .iter()
        .map(|node| {
            mapping_get_str(node, "name")
                .map(to_yaml_string_value)
                .unwrap_or_else(|| to_yaml_string_value("unknown"))
        })
        .collect::<Vec<_>>();

    let mut manual_group = Mapping::new();
    insert_yaml_value(&mut manual_group, "name", to_yaml_string_value("MANUAL"));
    insert_yaml_value(&mut manual_group, "type", to_yaml_string_value("select"));
    insert_yaml_value(&mut manual_group, "proxies", Value::Sequence(proxy_names));

    let mut config = Mapping::new();
    insert_yaml_value(&mut config, "port", Value::from(1082_i64));
    insert_yaml_value(&mut config, "socks-port", Value::from(1083_i64));
    insert_yaml_value(&mut config, "allow-lan", Value::from(true));
    insert_yaml_value(&mut config, "mode", to_yaml_string_value("rule"));
    insert_yaml_value(&mut config, "log-level", to_yaml_string_value("warning"));
    insert_yaml_value(
        &mut config,
        "external-controller",
        to_yaml_string_value("127.0.0.1:9090"),
    );
    insert_yaml_value(
        &mut config,
        "proxies",
        Value::Sequence(nodes.into_iter().map(Value::Mapping).collect()),
    );
    insert_yaml_value(
        &mut config,
        "proxy-groups",
        Value::Sequence(vec![Value::Mapping(manual_group)]),
    );
    insert_yaml_value(
        &mut config,
        "rules",
        Value::Sequence(vec![
            to_yaml_string_value("GEOIP,LAN,DIRECT,no-resolve"),
            to_yaml_string_value("GEOIP,CN,DIRECT"),
            to_yaml_string_value("MATCH,MANUAL"),
        ]),
    );
    insert_yaml_value(&mut config, "bind-address", to_yaml_string_value("*"));

    serde_yaml_ng::to_string(&Value::Mapping(config)).context("failed to serialize JMS subscription to YAML")
}

pub fn convert_jms_subscription_body(body: &str) -> Result<Option<String>> {
    let normalized = body.trim().trim_start_matches('\u{feff}');
    if normalized.is_empty() {
        return Ok(None);
    }

    let raw_nodes = parse_nodes(normalized);
    if !raw_nodes.is_empty() {
        return build_clash_yaml(raw_nodes).map(Some);
    }

    if let Some(decoded) = decode_base64_any(normalized) {
        let nodes = parse_nodes(&decoded);
        if !nodes.is_empty() {
            return build_clash_yaml(nodes).map(Some);
        }
    }

    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::convert_jms_subscription_body;

    #[test]
    fn converts_base64_subscription_body() {
        let body = "c3M6Ly9ZV1Z6TFRJMU5pMW5ZMjA2Y0dGemMwQmxlR0Z0Y0d4bExtTnZiVG8wTkRNPQojZGVtbw==";

        let yaml = convert_jms_subscription_body(body)
            .expect("conversion should succeed")
            .expect("should produce yaml");

        assert!(yaml.contains("proxies:"));
        assert!(yaml.contains("demo"));
        assert!(yaml.contains("MANUAL"));
    }

    #[test]
    fn converts_plain_text_subscription_body() {
        let body = "ss://YWVzLTI1Ni1nY206cGFzc0BleGFtcGxlLmNvbTo0NDM=#demo\nnot-a-node\n";

        let yaml = convert_jms_subscription_body(body)
            .expect("conversion should succeed")
            .expect("should produce yaml");

        assert!(yaml.contains("demo"));
        assert!(yaml.contains("proxies:"));
    }

    #[test]
    fn returns_none_for_unrecognized_content() {
        let result = convert_jms_subscription_body("not-a-subscription");
        assert!(result.expect("conversion should succeed").is_none());
    }
}
