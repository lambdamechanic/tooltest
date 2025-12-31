# pctx MCP Configuration for Claude Code

## Overview

This document describes the pctx MCP server configuration for Claude Code, which provides the same MCP tools that are available in codex.

## Configuration

The pctx MCP server is configured globally for all Claude Code sessions via `~/.claude.json`:

```json
{
  "mcpServers": {
    "pctx": {
      "type": "stdio",
      "command": "/bin/sh",
      "args": [
        "-lc",
        "if [ -f \"$HOME/.config/codex.env\" ]; then set -a; . \"$HOME/.config/codex.env\"; set +a; fi; root=\"$(git -C \"${PWD}\" rev-parse --show-toplevel 2>/dev/null)\"; if [ -n \"$root\" ] && [ -f \"$root/.env\" ]; then set -a; . \"$root/.env\"; set +a; fi; cfg=\"$root/pctx.json\"; if [ -f \"$cfg\" ]; then :; else cfg=\"$HOME/.config/pctx/pctx.json\"; fi; pctx mcp start --stdio --config \"$cfg\" 2>> /home/mark/logs/pctx.log"
      ]
    }
  }
}
```

## How It Works

The configuration:

1. **Sources environment variables** from `~/.config/codex.env` if it exists
2. **Detects the git repository root** of the current working directory
3. **Sources project-specific environment** from `<git-root>/.env` if it exists
4. **Selects configuration file**:
   - Uses `<git-root>/pctx.json` if it exists (project-specific)
   - Falls back to `~/.config/pctx/pctx.json` (global default)
5. **Starts pctx MCP server** in stdio mode with the selected config
6. **Logs errors** to `~/logs/pctx.log`

## Available MCP Servers

The global pctx configuration (`~/.config/pctx/pctx.json`) exposes the following MCP servers:

- **beads** - bd (beads) issue tracking integration (http://127.0.0.1:43101/mcp)
- **circleci** - CircleCI integration (http://127.0.0.1:43102/mcp)
- **dumbwaiter** - Dumbwaiter integration (http://127.0.0.1:43103/mcp)
- **github** - GitHub integration (http://127.0.0.1:43104/mcp)
- **sk** - sk integration (http://127.0.0.1:43105/mcp)
- **exa** - Exa search (https://mcp.exa.ai/mcp)

## Backend Proxies

The stdio MCP servers (beads, circleci, dumbwaiter, github, sk) are wrapped with HTTP proxies using the `codex-mcp-proxies` script located at `~/.config/pctx/bin/codex-mcp-proxies`.

### Managing Proxies

```bash
# Start all proxies
~/.config/pctx/bin/codex-mcp-proxies start

# Stop all proxies
~/.config/pctx/bin/codex-mcp-proxies stop

# Check status
~/.config/pctx/bin/codex-mcp-proxies status
```

## Verification

After starting a new Claude Code session, you can verify the pctx tools are available by checking the available tools. The pctx MCP server aggregates all the configured servers and makes their tools available.

## Troubleshooting

- **MCP servers not available**: Make sure the proxy servers are running with `codex-mcp-proxies status`
- **Check logs**: Error logs are written to `~/logs/pctx.log`
- **Restart Claude Code**: MCP servers are loaded at session startup
