> [!WARNING]
> This is a fork of the original [WireMCP](https://github.com/0xKoda/WireMCP) repo, and it is not maintained by the original author. This fork transforms the local MCP server into a **remote MCP server** running in TypeScript with Docker support. Use at your own risk.

![Wire-MCP Banner](Wire-MCP.png)

# WireMCP Remote Server

WireMCP is a Model Context Protocol (MCP) server designed to empower Large Language Models (LLMs) with real-time network traffic analysis capabilities. By leveraging tools built on top of Wireshark's `tshark`, WireMCP captures and processes live network data, providing LLMs with structured context to assist in tasks like threat hunting, network diagnostics, and anomaly detection.

This fork extends WireMCP to run as a **remote MCP server**, allowing it to be deployed on separate infrastructure and accessed over HTTP, making it ideal for enterprise deployments and containerized environments.

# Features

WireMCP exposes the following tools to MCP clients, enhancing LLM understanding of network activity:

- **`capture_packets`**: Captures live traffic and returns raw packet data as JSON, enabling LLMs to analyze packet-level details (e.g., IP addresses, ports, HTTP methods).
- **`get_summary_stats`**: Provides protocol hierarchy statistics, giving LLMs an overview of traffic composition (e.g., TCP vs. UDP usage).
- **`get_conversations`**: Delivers TCP/UDP conversation statistics, allowing LLMs to track communication flows between endpoints.
- **`check_threats`**: Captures IPs and checks them against the URLhaus blacklist, equipping LLMs with threat intelligence context for identifying malicious activity.
- **`check_ip_threats`**: Performs targeted threat intelligence lookups for specific IP addresses against multiple threat feeds, providing detailed reputation and threat data.
- **`analyze_pcap`**: Analyzes PCAP files to provide comprehensive packet data in JSON format, enabling detailed post-capture analysis of network traffic.
- **`extract_credentials`**: Scans PCAP files for potential credentials from various protocols (HTTP Basic Auth, FTP, Telnet), aiding in security audits and forensic analysis.

## How It Helps LLMs

WireMCP bridges the gap between raw network data and LLM comprehension by:
- **Contextualizing Traffic**: Converts live packet captures into structured outputs (JSON, stats) that LLMs can parse and reason about.
- **Threat Detection**: Integrates IOCs (currently URLhaus) to flag suspicious IPs, enhancing LLM-driven security analysis.
- **Diagnostics**: Offers detailed traffic insights, enabling LLMs to assist with troubleshooting or identifying anomalies.
- **Narrative Generation**: LLMs can transform complex packet captures into coherent stories, making network analysis accessible to non-technical users.

# Installation

## Prerequisites
- Docker and Docker Compose (recommended)
- OR Node.js (v18+ recommended) and pnpm for local development
- [Wireshark](https://www.wireshark.org/download.html) with `tshark` (included in Docker image)

## Docker Deployment (Recommended)

### 1. Build the Docker Image

```bash
git clone https://github.com/frgarciames/WireMCP.git
cd WireMCP
docker build -t wiremcp:latest .
```

### 2. Run the Container

```bash
docker run -d \
  --name wiremcp \
  --cap-add=NET_RAW \
  --cap-add=NET_ADMIN \
  -p 3001:3001 \
  -e PORT=3001 \
  -e HOST=0.0.0.0 \
  wiremcp:latest
```

**Important**: The `--cap-add=NET_RAW` and `--cap-add=NET_ADMIN` flags are required for packet capture capabilities.

### 3. Verify the Server is Running

```bash
curl http://localhost:3001/health
```

You should receive a response indicating the server is healthy.

## Local Development Setup

1. Clone the repository:
   ```bash
   git clone https://github.com/frgarciames/WireMCP.git
   cd WireMCP
   ```

2. Install dependencies:
   ```bash
   pnpm install
   ```

3. Build the TypeScript code:
   ```bash
   pnpm run build
   ```

4. Run the server:
   ```bash
   pnpm run start
   ```

   Or for development with auto-reload:
   ```bash
   pnpm run dev
   ```

> **Note**: Ensure `tshark` is in your PATH. On macOS, it's typically at `/Applications/Wireshark.app/Contents/MacOS/tshark`.

# Usage with MCP Clients

WireMCP now runs as a remote MCP server accessible via HTTP. Configure your MCP client to connect to the server endpoint.

## Example: Claude Desktop

Edit your Claude Desktop configuration file:

**macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`

**Windows**: `%APPDATA%\Claude\claude_desktop_config.json`

**Linux**: `~/.config/Claude/claude_desktop_config.json`

Add the following configuration:

```json
{
  "mcpServers": {
    "wiremcp": {
      "url": "http://localhost:3001/mcp"
    }
  }
}
```

If running on a remote server, replace `localhost` with your server's IP address or hostname:

```json
{
  "mcpServers": {
    "wiremcp": {
      "url": "http://YOUR_SERVER_IP:3001/mcp"
    }
  }
}
```

## Example: Cursor

Edit `mcp.json` in Cursor Settings → MCP:

```json
{
  "mcpServers": {
    "wiremcp": {
      "url": "http://localhost:3001/mcp"
    }
  }
}
```

## Other MCP Clients

Any MCP-compliant client that supports remote servers can connect to WireMCP using the endpoint `http://YOUR_HOST:3001/mcp`.

# Configuration

The server can be configured using environment variables:

- `PORT`: Server port (default: 3001)
- `HOST`: Bind address (default: 0.0.0.0)
- `NODE_ENV`: Environment mode (production/development)

Example with custom configuration:

```bash
docker run -d \
  --name wiremcp \
  --cap-add=NET_RAW \
  --cap-add=NET_ADMIN \
  -p 8080:8080 \
  -e PORT=8080 \
  -e HOST=0.0.0.0 \
  wiremcp:latest
```

# Example Output

Running `check_threats` might yield:

```
Captured IPs:
174.67.0.227
52.196.136.253

Threat check against URLhaus blacklist:
No threats detected in URLhaus blacklist.
```

Running `analyze_pcap` on a capture file:

```json
{
  "content": [{
    "type": "text",
    "text": "Analyzed PCAP: ./capture.pcap\n\nUnique IPs:\n192.168.0.2\n192.168.0.1\n\nProtocols:\neth:ethertype:ip:tcp\neth:ethertype:ip:tcp:telnet\n\nPacket Data:\n[{\"layers\":{\"frame.number\":[\"1\"],\"ip.src\":[\"192.168.0.2\"],\"ip.dst\":[\"192.168.0.1\"],\"tcp.srcport\":[\"1550\"],\"tcp.dstport\":[\"23\"]}}]"
  }]
}
```

LLMs can use these outputs to:
- Provide natural language explanations of network activity
- Identify patterns and potential security concerns
- Offer context-aware recommendations
- Generate human-readable reports

# Security Considerations

When deploying WireMCP as a remote server:

1. **Network Security**: Use firewall rules to restrict access to trusted clients only
2. **Authentication**: Consider adding authentication middleware for production deployments
3. **TLS/HTTPS**: Use a reverse proxy (nginx, Caddy) to add HTTPS support
4. **Container Security**: Run with minimal required capabilities
5. **Network Isolation**: Deploy in isolated network segments when analyzing sensitive traffic

# Troubleshooting

## Permission Issues

If you encounter permission errors when capturing packets:

- Ensure the container runs with `NET_RAW` and `NET_ADMIN` capabilities
- Verify `tshark` has proper capabilities: `getcap /usr/bin/dumpcap`

## Connection Issues

- Verify the server is running: `docker ps | grep wiremcp`
- Check logs: `docker logs wiremcp`
- Test connectivity: `curl http://localhost:3001/health`
- Ensure port 3001 is not blocked by firewall

# Roadmap

- **Authentication & Authorization**: Add API key or OAuth support for production deployments
- **Expand IOC Providers**: Integrate additional threat intelligence sources (IPsum, Emerging Threats)
- **TLS Support**: Native HTTPS support without requiring reverse proxy
- **Multi-interface Capture**: Support for capturing from multiple network interfaces simultaneously
- **Enhanced Filtering**: Advanced packet filtering and analysis capabilities

# Contributing

Contributions are welcome! Please feel free to submit a Pull Request. For major changes, please open an issue first to discuss what you would like to change.

# License

[MIT](LICENSE)

# Acknowledgments

- Original [WireMCP](https://github.com/0xKoda/WireMCP) by 0xKoda
- Wireshark/tshark team for their excellent packet analysis tools
- Model Context Protocol community for the framework and specifications
- URLhaus for providing threat intelligence data
