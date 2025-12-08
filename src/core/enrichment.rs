use crate::core::models::IpReputation;
use reqwest::blocking::Client;

pub fn query_ip_info(ip: &str) -> Option<IpReputation> {
    let client = Client::new();

    // Exemple : services publics gratuits
    let url = format!("https://ipapi.co/{}/json/", ip);

    let resp = client.get(&url).send().ok()?.json::<serde_json::Value>().ok()?;

    Some(IpReputation {
        ip: ip.into(),
        country: resp["country_name"].as_str().map(|s| s.to_string()),
        score: 0,
        tags: vec![]
    })
}
