package evaluator

import (
	"net/url"
	"regexp"
	"strings"
)

var (
	identPattern    = regexp.MustCompile(`^[a-zA-Z0-9_\-\.]+$`)
	stripTokenPunct = regexp.MustCompile(`[()'"\s]`)
)

// ComputePermissionOverrides generates granular, strictly-scoped Antigravity permissionOverrides tokens.
func ComputePermissionOverrides(toolName string, toolArgs map[string]interface{}) []string {
	if toolArgs == nil {
		return nil
	}

	cleanTool := strings.TrimSpace(toolName)

	// 1. Generic MCP dispatch (call_mcp_tool)
	if cleanTool == "call_mcp_tool" {
		server, _ := toolArgs["ServerName"].(string)
		subTool, _ := toolArgs["ToolName"].(string)
		server = strings.TrimSpace(server)
		subTool = strings.TrimSpace(subTool)

		if server != "" && subTool != "" && identPattern.MatchString(server) && identPattern.MatchString(subTool) {
			return []string{
				"mcp(" + server + "/" + subTool + ")",
				"mcp_tool(" + server + "/" + subTool + ")",
				"call_mcp_tool(" + server + "/" + subTool + ")",
			}
		}
		return nil
	}

	// 2. Eager / direct MCP tools (e.g. mcp_linear_get_issue)
	if strings.HasPrefix(cleanTool, "mcp_") {
		cleanName, server, subTool := ParseMCPToolName(cleanTool)
		overrides := []string{"mcp(" + cleanName + ")"}
		if server != "" && subTool != "" {
			overrides = append(overrides, "mcp("+server+"/"+subTool+")")
			overrides = append(overrides, "mcp_tool("+server+"/"+subTool+")")
		}
		return overrides
	}

	// 3. Web URL fetching (read_url_content)
	if cleanTool == "read_url_content" {
		rawURL, _ := toolArgs["Url"].(string)
		rawURL = strings.TrimSpace(rawURL)
		if rawURL != "" {
			u, err := url.Parse(rawURL)
			if err == nil && (u.Scheme == "http" || u.Scheme == "https") && u.Host != "" {
				domain := u.Host
				safeDomain := stripTokenPunct.ReplaceAllString(domain, "")
				safeURL := stripTokenPunct.ReplaceAllString(rawURL, "")
				if safeDomain != "" && safeURL != "" {
					return []string{
						"read_url(" + safeDomain + ")",
						"read_url(" + safeURL + ")",
						"url(" + safeDomain + ")",
						"url(" + safeURL + ")",
					}
				}
			}
		}
		return nil
	}

	// 4. Terminal commands (run_command)
	if cleanTool == "run_command" {
		cmd, _ := toolArgs["CommandLine"].(string)
		cmd = strings.TrimSpace(cmd)
		if cmd != "" {
			return []string{"command(" + cmd + ")"}
		}
		return nil
	}

	// 5. File modifications (write_to_file, replace_file_content)
	if cleanTool == "write_to_file" || cleanTool == "replace_file_content" {
		target, _ := toolArgs["TargetFile"].(string)
		if target == "" {
			target, _ = toolArgs["AbsolutePath"].(string)
		}
		target = strings.TrimSpace(target)
		if target != "" {
			return []string{"write_file(" + target + ")"}
		}
		return nil
	}

	return nil
}
