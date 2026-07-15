# /jupyter-mcp — Start or Verify the Jupyter MCP Connection

Ensure the local Jupyter server backing the `jupyter` MCP connector (used to run playbook notebooks) is up, and confirm this session actually has a working `mcp__jupyter__*` tool connection to it.

## Steps

1. **Start or reuse the server**:
   ```bash
   bash scripts/start_jupyter_mcp.sh
   ```
   This is idempotent — if a server is already running on `127.0.0.1:8888` it does nothing, otherwise it starts one using the token stored in `.mcp.json` (single source of truth, so `.mcp.json` and VS Code's remembered connection never drift).

2. **Check this session has the tools loaded** — MCP servers are only loaded at session startup, so a server being "up" doesn't mean *this* conversation can call it. Verify with:
   ```
   ToolSearch: select:mcp__jupyter__list_kernels
   ```
   - If the tool schema comes back, proceed to step 3.
   - If not found, the `jupyter` MCP server isn't registered/connected for this session. Tell the user to check `claude mcp list` / `/mcp` and that a session restart is required after registering or editing `.mcp.json` — do not try to work around this by spawning a subprocess `claude` call.

3. **Confirm the connection actually works** (not just that the tool exists) by calling `mcp__jupyter__list_kernels` directly. A JSON/table result (even an empty kernel list) confirms live connectivity end-to-end.

4. **Report** concisely: server state (was already running / just started), whether the tool was found, and the `list_kernels` result.

## Notes
- Never mass-delete kernels found via `list_kernels` without the user's explicit go-ahead — idle kernels may belong to the user's own VS Code session sharing the same server.
- The server is bound to `127.0.0.1` only (not exposed to the network); the token in `.mcp.json` is a local secret — never commit it (it's gitignored).
- To point VS Code at the same server (shared kernels/notebooks with Claude), run VS Code command `Jupyter: Specify Jupyter Server for Connections` and paste the URL printed by `start_jupyter_mcp.sh`.
