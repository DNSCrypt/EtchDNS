<p align="center">
  <img src="https://raw.github.com/dnscrypt/etchdns/master/img/logo.png" alt="EtchDNS Logo" width="300">
</p>

<h1 align="center">EtchDNS</h1>

<p align="center">
  <strong>A caching DNS proxy with advanced security features</strong>
</p>

<p align="center">
  <strong>You'll find the full documentation on the <a href="https://etchdns.dnscrypt.info">EtchDNS</a> website.</strong>
</p>

<p align="center">
  <a href="#key-features">Key Features</a> •
  <a href="#quickstart">Quickstart</a> •
  <a href="#installation">Installation</a> •
  <a href="#configuration">Configuration</a> •
  <a href="#use-cases">Use Cases</a> •
  <a href="#advanced-features">Advanced Features</a> •
  <a href="#performance-tuning">Performance Tuning</a> •
  <a href="#security">Security</a> •
  <a href="#development">Development</a> •
  <a href="#license">License</a>
</p>

---

## What is EtchDNS?

EtchDNS is a caching DNS proxy.

It sits between your clients and upstream DNS servers to make DNS more secure and reliable.
It caches responses, spreads queries across servers, and protects your DNS traffic.

**Where is this useful?**

- Deploying zero-setup, maintenance-free secondary DNS servers
- Improving DNS performance and security for an organization
- Protecting a network you manage from DNS-based attacks
- Taking DNS traffic off primary servers as a service provider
- Getting more control over DNS resolution when you care about privacy
- Building your own DNS processing with WebAssembly
- Running a secondary authoritative DNS server with any provider, without zone transfers
- Putting a public or local DNS cache in front of a resolver
- Sitting between a DNSCrypt server proxy and a resolver

## Quickstart

1. Download or clone the repository.
2. Edit a copy of the [`etchdns.toml`](etchdns.toml) configuration file.
3. Run EtchDNS:

```sh
etchdns -c /path/to/etchdns.toml
```

## Key Features

### Performance

- **Caching**: Uses the SIEVE algorithm to make the best use of memory
- **Query aggregation**: Combines duplicate queries that are still waiting for a response, so upstream servers do less work
- **Load balancing**: Spreads queries across servers using your choice of strategy:

  - fastest
  - p2
  - random

- **EDNS-Client-Subnet**: Improves CDN and location-based DNS responses
- **Protocols**:

  - UDP/TCP (standard DNS)
  - Basic DoH (DNS-over-HTTP)

- **Planned protocols** for better security and privacy:

  - DNSCrypt
  - PQDNSCrypt
  - Anonymized DNSCrypt

### Security

- **Domain filtering**: Allow or block domains with allowed/NX zones
- **IP validation**: Blocks suspicious IP ranges, checks client ports, and prevents address spoofing
- **Rate limiting**: Gives you fine-grained control for each protocol:

  - UDP
  - TCP
  - DoH

- **Transaction ID masking**: Protects against cache poisoning attacks
- **Privilege dropping**: Runs with minimal system access after startup, with settings for:

  - user
  - group
  - chroot

- **Request validation**: Checks DNS packets thoroughly

### Reliability

- **Automatic failover**: Detects server outages immediately and keeps routing queries without interruption
- **Serve stale**: Keeps serving expired cache entries when upstream servers fail, without making clients wait for them
- **Health monitoring**: Checks upstream servers regularly, at intervals you set
- **Latency guarantees**: Keeps response times consistent even when upstream servers slow down
- **Connection limits**: Gives you separate limits for each protocol and for queries still waiting for a response

### Monitoring

- **Prometheus metrics**: Gives you a full view of server activity through a Prometheus endpoint
- **Remote control API**: Lets you check server status and manage the cache over HTTP
- **Query logging**: Lets you choose which query details to log
- **Log rotation**: Rotates logs by size or time, with compression support

### Extensibility (WebAssembly)

- **Plugins**: Write custom plugins in any language that compiles to WebAssembly, including:

  - C/C++
  - Zig
  - AssemblyScript

- **Custom filters**: Write filtering rules that go beyond static blocklists
- **Response changes**: Change DNS responses based on your own business rules
- **Stateful processing**: Keep state across DNS queries to enforce complex policies

## Use Cases

### Secondary DNS server

```toml
# Secondary DNS server mode
authoritative_dns = true

# Keep answering for a week if the primary server goes down
serve_stale_grace_time = 604800
```

This makes EtchDNS a secondary authoritative DNS server for your zones.
It handles client requests, takes load off your primary servers, and keeps service running while protecting against common attacks.

You can use it with any DNS provider. No zone transfers needed.

### Local or public DNS cache

```toml
# Cache mode
authoritative_dns = false
```

Point your devices at EtchDNS as their DNS resolver.
It caches responses and spreads queries across multiple upstream servers to improve performance, reliability, and security.
You can run it as a cache for your local network or as a public DNS service.

### DNS Firewall

```toml
# Domain blocklist configuration
nx_zones_file = "nx_zones.txt"

# IP address validation and filtering
enable_strict_ip_validation = true
block_private_ips = true
block_loopback_ips = true
blocked_ip_ranges = ["203.0.113.0/24", "198.51.100.0/24"]
min_client_port = 1024
```

This puts a protective layer in front of your network.
Add domains to `nx_zones.txt` to return NXDOMAIN responses for them, blocking:

- Malicious domains
- Ads
- Unwanted content

You can also use IP validation to block connections from suspicious or problematic IP ranges.

EtchDNS can sit between a DNSCrypt server proxy, such as [encrypted-dns-server](https://github.com/DNSCrypt/encrypted-dns-server), and your resolver to reduce load and improve reliability.

### Custom DNS processing with WebAssembly

```toml
# WebAssembly hooks
hooks_wasm_file = "hooks.wasm"
hooks_wasm_wasi = false  # Set to true if your plugin needs WASI support
```

These settings let you use WebAssembly for custom DNS processing:

- Custom filtering rules
- Monitoring
- Changes to DNS queries and responses

## Installation

### From release binaries

Download the latest release from the [releases page](https://github.com/dnscrypt/etchdns/releases).

### From source

1. Make sure you have Rust and Cargo installed.
2. Clone this repository.
3. Build the release version:

```sh
cargo build --release
```

You'll find the executable at `target/release/etchdns`.

#### Building with WebAssembly hooks support

EtchDNS builds without WebAssembly hooks by default to keep the binary smaller.
To enable them, use the `hooks` feature flag:

```sh
cargo build --release --features hooks
```

This adds a WebAssembly runtime and makes the binary significantly larger.
Only enable it if you plan to use WebAssembly extensions.

## Configuration

You control all of EtchDNS's behavior through a TOML configuration file.
The included [`etchdns.toml`](etchdns.toml) has a complete, documented example.

Here's what you can configure:

- **Basic server settings**:

  - Listen addresses
  - Log level
  - Packet size limits

- **Upstream DNS servers**: Servers to forward queries to
- **Load balancing**: Strategy and probe interval
- **Rate limiting**: Settings for each protocol
- **Caching**: Cache size and TTL settings
- **Domain filtering**: Allowed and blocked zones
- **IP validation**: Filtering and security options for client source IP addresses
- **EDNS-client-subnet**: Whether it's enabled and which prefix lengths to use
- **Security**: Settings for dropping privileges

### Domain filtering

#### Allowed zones

Put the domains you want to allow in a text file:

```
# Company domains
example.com
example.org

# Third-party services
github.com
google.com
```

#### NX zones (blocklist)

Put the domains that should return NXDOMAIN in a text file:

```
# Advertising domains
ads.example.com
analytics.example.com

# Known malicious domains
malware.example.net
```

## Advanced Features

### EDNS-Client-Subnet support

EtchDNS supports EDNS-client-subnet (ECS), as defined in RFC 7871.
When enabled, ECS shares client IP information with upstream servers to improve CDN and location-based DNS responses.

```toml
# EDNS-Client-Subnet configuration
enable_ecs = true
ecs_prefix_v4 = 24  # Send first 24 bits of IPv4 address (hide last 8 bits)
ecs_prefix_v6 = 56  # Send first 56 bits of IPv6 address (hide last 72 bits)
```

These settings enable ECS, so upstream queries include client IP information and DNS providers can tailor responses to the client's location.
The prefix lengths set how much of the client's IP address you share with upstream servers.
That's the tradeoff between performance and privacy.

### Remote Control API

```toml
# Control API setup
control_listen_addresses = ["127.0.0.1:8080"]
control_path = "/control"
```

These settings enable the HTTP API for remote management.
You can use these endpoints:

- `GET /control/status`: Get full server status, including:

  - Uptime
  - Connection stats
  - Health information

- `GET /control/cache`: Get cache status, including:

  - Size
  - Hit/miss rates
  - Entry counts

- `DELETE /control/cache`: Clear the entire cache
- `DELETE /control/cache/zone/<example.com>`: Clear all entries for a specific zone
- `DELETE /control/cache/name/<example.com>`: Clear a specific entry by name

### WebAssembly Extensions (WIP)

> **Note**: WebAssembly extensions work, but they're still under active development.
> Expect API changes and more features in future releases.

You can write your own DNS processing logic as a WebAssembly module.
Any language that compiles to WebAssembly works, including:

- C/C++
- Zig
- AssemblyScript
- Go/TinyGo
- Many others, through Extism

> **Important**: You must build EtchDNS with the `hooks` feature flag to use WebAssembly extensions:
> ```sh
> cargo build --release --features hooks
> ```
> This adds the Extism WebAssembly runtime and makes the binary significantly larger.

#### What WebAssembly extensions give you

- **Language choice**: Write extensions in the language you prefer
- **Sandboxing**: Extensions run in a secure sandbox with minimal overhead
- **Hot reloading**: Update extensions without restarting EtchDNS
- **Stateful processing**: Keep state across DNS queries to enforce complex policies
- **Extism**: Uses the Extism plugin system, with optional WASI support

#### Available hooks

The current implementation supports this hook:

- `hook_client_query_received`: Called when a client query is received, before checking the cache

  - Return code 0: Continue normal processing
  - Return code -1: Return a minimal response with the REFUSED response code (rcode)

Hooks receive query information as structured JSON.
You can process that data in any language that compiles to WebAssembly.

#### Example plugin

You'll find an example WebAssembly plugin in [`webassembly-plugins`](webassembly-plugins/).
It shows how to write a simple plugin that changes how DNS queries are processed.

Set the path to your compiled WASM file in the configuration:

```toml
# WebAssembly hooks
hooks_wasm_file = "hooks.wasm"
hooks_wasm_wasi = false  # Set to true if your plugin needs WASI support
```

#### Building your own extensions

See the [WebAssembly Extension Guide](#building-webassembly-hooks) in Development for details on building your own extensions.

## Performance Tuning

To get the best performance, start with these settings:

1. **Cache size**: Increase `cache_size` to match the memory you have available
2. **Client limits**: Adjust these for your environment:

   - `max_udp_clients`
   - `max_tcp_clients`

3. **Load balancing**: Choose:

   - `fastest` for the highest performance
   - `p2` for a good balance

4. **Serve stale**: Enable `serve_stale_grace_time` to improve reliability
5. **Rate limiting**: Set limits that prevent DoS while letting legitimate traffic through
6. **In-flight queries**: Adjust `max_inflight_queries` to make query aggregation more efficient
7. **TTL settings**: Adjust the TTL settings to get the most out of the cache
8. **Probe interval**: Set `probe_interval` to balance load balancer accuracy against network overhead

## Security

You can use these features to protect both clients and upstream servers:

- **Run with minimal privileges**: Use the privilege dropping feature
- **Domain filtering**: Choose which queries are processed
- **IP validation**: Block connections from suspicious or problematic source addresses
- **Rate limiting**: Prevent abuse by limiting queries per client
- **Transaction ID masking**: Protect against cache poisoning attacks

### IP validation

IP validation lets you choose which client IP addresses can use your server:

```toml
# Enable strict IP validation
enable_strict_ip_validation = true

# Block private IP address ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
block_private_ips = true

# Block loopback IP address ranges (127.0.0.0/8, ::1)
block_loopback_ips = true

# Minimum port to allow from clients (ports below this will be rejected)
min_client_port = 1024

# List of blocked IP ranges
blocked_ip_ranges = ["203.0.113.0/24", "198.51.100.0/24"]
```

These settings help protect against:

- IP spoofing
- Abuse from internal networks
- Connections from known problematic IP ranges

Client port validation also blocks connections from privileged ports, which are commonly used in spoofing attacks.

## Development

### Running tests

```sh
cargo test
```

This runs the standard unit tests.

### Fuzzing tests

EtchDNS has a full set of fuzzing tests for its DNS parsers.

1. Install cargo-fuzz:
   ```sh
   cargo install cargo-fuzz
   ```

2. Run a specific fuzz target:
   ```sh
   cargo fuzz run validate_dns_packet
   ```

See [fuzz/README.md](fuzz/README.md) for more details on the available targets.

### Building WebAssembly Hooks

To build your own WebAssembly extension:

1. Make sure you've compiled EtchDNS with hooks support:
   ```sh
   cargo build --release --features hooks
   ```

2. Add the WebAssembly target to your Rust toolchain:
   ```sh
   rustup target add wasm32-unknown-unknown
   ```

3. Build the example Rust plugin or your own extension:
   ```sh
   cd webassembly-plugins/rust
   cargo build --target wasm32-unknown-unknown --release
   ```

4. You'll find the compiled WebAssembly module at `webassembly-plugins/rust/target/wasm32-unknown-unknown/release/hooks_plugin.wasm`

5. Copy the WebAssembly module to your EtchDNS directory and update the configuration:
   ```sh
   cp target/wasm32-unknown-unknown/release/hooks_plugin.wasm /path/to/etchdns/hooks.wasm
   ```

Or you can build the Zig example plugin:

1. Go to the Zig plugin directory:
   ```sh
   cd webassembly-plugins/zig
   ```

2. Build the Zig plugin:
   ```sh
   zig build
   ```

3. You'll find the compiled WebAssembly module in `zig-out/bin/`

For other languages, check their WebAssembly build guides.
Your WASM module must export functions that match EtchDNS's hook interface.

#### WASI support

If your WebAssembly plugin needs system resources, you can enable WASI support.
Those resources include:

- The file system
- Environment variables

```toml
# Enable WASI for WebAssembly hooks
hooks_wasm_wasi = true
```

This lets your plugin use WASI system calls, but it increases the security risk.
Only enable it if your plugin specifically needs those capabilities.

> **Note**: If your EtchDNS binary was built without the `hooks` feature, WebAssembly hooks won't work.
> Any hook-related configuration will be ignored.

## License

EtchDNS is licensed under the MIT License.

---

## Future Plans

- **Protocols**: Future versions may support:

  - DNSCrypt
  - Anonymized DNS

  This may involve porting functionality from [encrypted-dns-server](https://github.com/DNSCrypt/encrypted-dns-server).

> **Note**: DoH support is currently limited to traditional DoH, not Oblivious DoH (ODoH).
> If you need a mature DoH server that's been tested in real use, consider [doh-server](https://github.com/DNSCrypt/doh-server) instead.
