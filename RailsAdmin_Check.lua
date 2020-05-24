-- Lua single line comments.
-- HEAD SECTION

-- Brief description/purpose
description=[[
	Simple NMAP script to enumerate Rails Admins page
]]

-- Author
author = "OP"

-- Usage
---
-- nmap -p <port> --script rail_admins.nse <host>
--
-- @output
-- PORT		STATE	SERVICE
-- 3000/tcp	open	ppp
-- | rails-admins:
-- | <td>PeterBenjamin</td>
-- | <td>MySuperSecr3t</td> 
--

-- Imports
local nmap = require "nmap"
local http = require "http"
local stdnse = require "stdnse"

-- RULE SECTION
-- Will tell if script is allowed to run
portrule = function(host, port)
  local right_port = { number=3000, protocol="tcp" }
  local identify = nmap.get_port_state(host, right_port)

  return identify ~= nil
    and identify.state == "open"
    and port.protocol == "tcp"
    and port.state == "open"
end

-- ACTION SECTION
-- Will perform the action 

-- Helper function to check if response contains string "password" or not
local DEFAULT_ADMIN_URI = "/admins"
local function check_admin(host, port, path)
	local response = http.get(host, port, path)
	if not http.response_contains(response, "password") then
		return false
	end
	return response
end

-- Will call helper function to check if it's vulnerable Rails app
action = function(host, port)
	local vuln_railsApp = check_admin(host, port, DEFAULT_ADMIN_URI)
  local output = {}
	if not vuln_railsApp then
		stdnse.print_debug(1,"%s: This does not look like a vulnerable Rails app", SCRIPT_NAME)
		return
  else
    output = string.match(vuln_railsApp["body"], "%<td%>.*%<%/td%>")
	end
  return output
end