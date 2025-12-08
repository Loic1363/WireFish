# WireFish

WireFish is a Rust-powered network capture and inspection tool with a lightweight Tauri UI scaffold. It sits on top of libpcap/Npcap for packet capture, parses Ethernet/IP/TCP/UDP/ICMP headers, classifies flows, and leaves room for enrichment (GeoIP/reputation) and alerting.

## Features
- Live capture via libpcap/Npcap with a quick traffic scan per interface to help you pick the right NIC.
- Table-style terminal view (or debug-only mode) with protocol classification (HTTP/HTTPS/DNS/SSH/ARP/ICMP/other).
- Pluggable alert stub (see `src/core/alerts.rs`) and IP enrichment hook using a public API example (`src/core/enrichment.rs`).
- Serializable packet models (Serde) ready to feed the UI or an API layer.
- Early-stage Tauri/Vue scaffold under `ui/tauri` for dashboards, packet lists, alerts, and IP detail panes.

## Project Layout
- `src/main.rs` — CLI entrypoint, argument parsing, interactive interface selection, and console rendering.
- `src/core/` — capture, parsing, classification, enrichment, alerting, and shared models.
- `ui/tauri/` — front-end scaffold (Vue entry in `src/main.js`, React-style JSX pages under `pages/`).
- `Cargo.toml` — Rust workspace manifest and dependencies.

## Requirements
- Rust toolchain (stable).
- Packet capture driver:
  - Windows: [Npcap](https://nmap.org/npcap/) installed.
  - Linux/macOS: libpcap available on the system.
- (Optional) Node.js + npm/yarn for the Tauri front-end.

## CLI Usage
Build and run:

```bash
cargo run --release -- [options] [interface_index]
```

Options:
- `--packets-only` (default): show the packet table only.
- `--debug` or `--both`: show the table and debug logs from the capture loop.
- `--debug-only`: suppress the table; consume packets and emit debug logs only.

Interface selection:
- Provide an `interface_index` to pick an interface directly (index is from the quick scan list).
- If omitted or invalid, the app performs a short capture (~0.5s) per interface, displays counts, and prompts interactively.

Examples:
```bash
# Interactive selection, default display
cargo run --release --

# Force interface #3 and show both table + debug logs
cargo run --release -- --both 3
```

Runtime notes:
- Press `Ctrl+C` to stop capture cleanly.
- The debug mode logs raw capture events to help troubleshoot driver/setup issues.

## Alerts and Enrichment
- Alert stub: `src/core/alerts.rs` contains `detect_suspicious` as a starting point (port-based and reputation-based).
- Enrichment: `src/core/enrichment.rs` demonstrates a blocking IP lookup against `ipapi.co`. Replace with your provider of choice and add rate limiting/caching as needed.

## UI (Tauri) Quickstart
The UI is a scaffold you can build on:
```bash
cd ui/tauri
npm install
npm run tauri dev    # or: npm run tauri build
```

The entrypoint is `ui/tauri/src/main.js`; page components live in `ui/tauri/pages/`. Wire it to your data source (IPC, HTTP, or a JSON feed) to render live captures/alerts.

## Development
- Format: `cargo fmt`
- Lint: `cargo clippy -- -D warnings`
- Test: `cargo test`
- Build release: `cargo build --release`

## Roadmap Ideas
- Deeper protocol decoders (TLS, HTTP/2, DNS payloads).
- Persistent storage (pcap dump, SQLite) and export pipelines.
- Enrichment cache + async lookups; rules engine for alerts.
- Tight UI integration (live streaming via Tauri commands).

## License
This project is licensed under the MIT License (see `LICENSE`).
