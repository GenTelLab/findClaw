local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Detects OpenClaw / AutoClaw / MiniClaw gateway services by probing
the real HTTP endpoints exposed on the gateway port (default 18789).

Key probe targets based on official OpenClaw Gateway protocol:
  - GET /              → Control UI page (contains "openclaw" branding)
  - GET /tools/invoke  → 405 Method Not Allowed (POST-only endpoint)
  - GET /v1/chat/completions → 405 (OpenAI-compatible API)
  - GET /v1/responses  → 405 (OpenResponses API)
  - GET /health        → Health snapshot (channel status JSON)
  - GET /status,/ready,/live,/version → supplemental status/version clues
]]

author = "FindClaw Project"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

portrule = shortport.http

local function lower(value)
  if not value then
    return ""
  end

  return string.lower(value)
end

local function contains(value, keyword)
  return string.find(lower(value), lower(keyword), 1, true) ~= nil
end

local function extract_title(body)
  if not body then
    return ""
  end

  local title = string.match(body, "<title>(.-)</title>")
  if not title then
    title = string.match(body, "<TITLE>(.-)</TITLE>")
  end

  return title or ""
end

local function request(host, port, path, options)
  local ok, response = pcall(http.get, host, port, path, options)
  if not ok or not response then
    return nil
  end

  return response
end

action = function(host, port)
  local output_list = {}
  local seen_map = {}

  local function add_output(item)
    if item and item ~= "" and not seen_map[item] then
      seen_map[item] = true
      table.insert(output_list, item)
    end
  end

  local root_response = request(host, port, "/")
  local health_response = request(host, port, "/health")
  local status_response = request(host, port, "/status")
  local ready_response = request(host, port, "/ready")
  local live_response = request(host, port, "/live")
  local version_response = request(host, port, "/version")
  local tools_invoke_response = request(host, port, "/tools/invoke")
  local mcp_response = request(host, port, "/mcp")
  local v1_completions_response = request(host, port, "/v1/chat/completions")
  local v1_responses_response = request(host, port, "/v1/responses")

  if root_response and root_response.body then
    local body_lower = lower(root_response.body)
    local title = extract_title(root_response.body)

    if (contains(body_lower, "openclaw") or contains(title, "openclaw")) and not contains(body_lower, "findclaw") then
      add_output("claw_detect=openclaw")
      add_output("signal=root:openclaw")
    end

    if contains(body_lower, "clawdbot") or contains(title, "clawdbot") then
      add_output("claw_detect=clawdbot")
      add_output("claw_detect=openclaw")
      add_output("signal=root:clawdbot")
    end

    if contains(body_lower, "moltbot") or contains(title, "moltbot") then
      add_output("claw_detect=moltbot")
      add_output("claw_detect=openclaw")
      add_output("signal=root:moltbot")
    end

    if (contains(body_lower, "autoclaw") or contains(body_lower, "autoglm") or contains(body_lower, "zhipu")) and not contains(body_lower, "findclaw") then
      add_output("claw_detect=autoclaw")
      add_output("signal=root:autoclaw_branding")
    end

    if contains(body_lower, "miniclaw") and not contains(body_lower, "findclaw") then
      add_output("claw_detect=miniclaw")
      add_output("signal=root:miniclaw")
    end

    if contains(body_lower, "gateway") and contains(body_lower, "claw") and not contains(body_lower, "findclaw") then
      add_output("claw_detect=generic")
      add_output("signal=root:gateway+claw")
    end

    if contains(body_lower, "operator") and contains(body_lower, "claw") and not contains(body_lower, "findclaw") then
      add_output("signal=root:operator")
    end
  end

  if tools_invoke_response then
    if tools_invoke_response.status == 405 then
      add_output("signal=tools_invoke:405")
      add_output("claw_detect=openclaw_gateway")
    elseif tools_invoke_response.status == 401 then
      add_output("signal=tools_invoke:401")
      add_output("claw_detect=openclaw_gateway")
    end
  end

  if v1_completions_response then
    if v1_completions_response.status == 405 then
      add_output("signal=v1_completions:405")
    elseif v1_completions_response.status == 401 then
      add_output("signal=v1_completions:401")
    end
  end

  if v1_responses_response then
    if v1_responses_response.status == 405 then
      add_output("signal=v1_responses:405")
    elseif v1_responses_response.status == 401 then
      add_output("signal=v1_responses:401")
    end
  end

  if mcp_response then
    if mcp_response.status == 200 or mcp_response.status == 401 or mcp_response.status == 403 then
      add_output("signal=mcp:" .. mcp_response.status)
    end
    if mcp_response.header then
      local mcp_type = lower(mcp_response.header["content-type"] or "")
      if contains(mcp_type, "event-stream") then
        add_output("signal=mcp:event-stream")
      end
    end
  end

  local function inspect_status_response(label, response)
    if not response then
      return
    end
    if response.status == 200 or response.status == 401 or response.status == 403 then
      add_output("signal=" .. label .. ":" .. response.status)
    end
    if not response.body then
      return
    end

    local body_lower = lower(response.body)
    if contains(body_lower, "channel") and contains(body_lower, "running") then
      add_output("signal=" .. label .. ":channel_status")
      add_output("claw_detect=openclaw_gateway")
    end
    if contains(body_lower, "probe") and contains(body_lower, "elapsedms") then
      add_output("signal=" .. label .. ":probe_metrics")
    end
    if contains(body_lower, "openclaw") and not contains(body_lower, "findclaw") then
      add_output("claw_detect=openclaw")
      add_output("signal=" .. label .. ":openclaw")
    end
    if contains(body_lower, "clawdbot") then
      add_output("claw_detect=clawdbot")
      add_output("claw_detect=openclaw")
      add_output("signal=" .. label .. ":clawdbot")
    end
    if contains(body_lower, "moltbot") then
      add_output("claw_detect=moltbot")
      add_output("claw_detect=openclaw")
      add_output("signal=" .. label .. ":moltbot")
    end
    if (contains(body_lower, "autoclaw") or contains(body_lower, "autoglm") or contains(body_lower, "zhipu")) and not contains(body_lower, "findclaw") then
      add_output("claw_detect=autoclaw")
      add_output("signal=" .. label .. ":autoclaw")
    end
    if contains(body_lower, "miniclaw") and not contains(body_lower, "findclaw") then
      add_output("claw_detect=miniclaw")
      add_output("signal=" .. label .. ":miniclaw")
    end
  end

  inspect_status_response("health", health_response)
  inspect_status_response("status", status_response)
  inspect_status_response("ready", ready_response)
  inspect_status_response("live", live_response)
  inspect_status_response("version", version_response)

  local response_list = {
    root_response, health_response, status_response, ready_response, live_response,
    version_response, tools_invoke_response, mcp_response,
    v1_completions_response, v1_responses_response
  }

  for _, response in ipairs(response_list) do
    if response and response.header then
      local header_map = response.header

      local claw_version = header_map["x-claw-version"] or header_map["X-Claw-Version"]
      if claw_version then
        add_output("signal=header:x-claw-version=" .. claw_version)
      end

      local openclaw_token_header = header_map["x-openclaw-token"]
      if openclaw_token_header then
        add_output("signal=header:x-openclaw-token")
        add_output("claw_detect=openclaw_gateway")
      end
    end
  end

  if #output_list == 0 then
    return nil
  end

  return stdnse.format_output(true, output_list)
end
