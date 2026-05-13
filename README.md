# Netskope MCP Server

A [Model Context Protocol (MCP)](https://modelcontextprotocol.io) server that exposes the full [Netskope REST API v2](https://github.com/netskopeoss/netskope-py-sdk) to AI assistants like Claude. Built with [FastMCP](https://gofastmcp.com).

## Features

39 tools covering all Netskope API modules:

| Module | Tools |
|---|---|
| **Alerts** | `list_alerts`, `get_alert` |
| **Events** | `list_events` |
| **Incidents** | `list_incidents`, `update_incident`, `get_incident_forensics`, `get_user_confidence_index`, `get_anomalies` |
| **URL Lists** | `list_url_lists`, `get_url_list`, `create_url_list`, `update_url_list`, `delete_url_list`, `deploy_url_lists` |
| **Publishers** | `list_publishers`, `get_publisher`, `create_publisher`, `update_publisher`, `delete_publisher` |
| **Private Apps (ZTNA)** | `list_private_apps`, `get_private_app`, `create_private_app`, `update_private_app`, `delete_private_app` |
| **SCIM Users** | `list_scim_users`, `get_scim_user`, `create_scim_user`, `update_scim_user`, `delete_scim_user` |
| **SCIM Groups** | `list_scim_groups`, `get_scim_group`, `create_scim_group`, `update_scim_group`, `delete_scim_group` |
| **Steering / Infra** | `get_steering_config`, `update_steering_config`, `list_pops`, `list_tunnels`, `get_tunnel` |

## Requirements

- Python 3.11+
- A Netskope tenant with a REST API v2 token

## Installation

```bash
git clone https://github.com/adrig-geek/netskope-mcp.git
cd netskope-mcp
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
```

## Configuration

Copy the example env file and fill in your credentials:

```bash
cp .env.example .env
```

Edit `.env`:

```env
NETSKOPE_TENANT=yourcompany.goskope.com
NETSKOPE_API_TOKEN=your_api_token_here
```

Your API token can be generated in the Netskope console under **Settings → Tools → REST API v2**.

## Usage with Claude Code

Add the server to your project's `.mcp.json`:

```json
{
  "mcpServers": {
    "netskope": {
      "command": "/path/to/netskope-mcp/.venv/bin/python3",
      "args": ["/path/to/netskope-mcp/server.py"]
    }
  }
}
```

Then open a Claude Code session in the project directory and ask naturally:

- *"List my recent HIGH severity alerts"*
- *"Show all SCIM users in the Engineering group"*
- *"Create a URL blocklist with these domains: ..."*
- *"What private apps are configured for ZTNA?"*
- *"Get the User Confidence Index for john@example.com"*

## Running manually (for testing)

```bash
.venv/bin/python3 server.py
```

The server uses `stdio` transport and is designed to be launched automatically by Claude Code via `.mcp.json`. Running it manually is useful to verify it starts without errors.

## Dependencies

- [`netskope-py-sdk`](https://github.com/netskopeoss/netskope-py-sdk) — Official Netskope Python SDK
- [`fastmcp`](https://gofastmcp.com) — FastMCP framework
- [`python-dotenv`](https://github.com/theskumar/python-dotenv) — `.env` file loading
