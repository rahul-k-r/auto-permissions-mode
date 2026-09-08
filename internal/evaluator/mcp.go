package evaluator

import (
	"regexp"
	"strings"
)

// Mutating verbs for MCP heuristic gating.
var MutatingVerbs = []string{
	"delete", "remove", "drop", "purge", "prune", "create", "save", "update",
	"modify", "exec", "execute", "run", "write", "set", "apply", "destroy",
	"kill", "wipe", "clean", "reset", "revert", "merge", "commit", "push",
	"retire", "restore", "archive", "unshare",
}

var SafeMcpReadPrefixes = []string{
	"get_", "list_", "search_", "read_", "fetch_", "describe_", "find_", "extract_",
}

var SafeMcpReadExact = map[string]bool{
	"get": true, "list": true, "search": true, "read": true,
	"fetch": true, "describe": true, "find": true, "ping": true, "status": true,
}

var cleanIdentPattern = regexp.MustCompile(`[^a-zA-Z0-9_]`)

// ParseMCPToolName splits an eager MCP tool name (e.g. mcp_linear_get_issue or mcp_google_drive_search_files)
// into (cleanName, server, subTool).
func ParseMCPToolName(toolName string) (cleanName, server, subTool string) {
	cleanName = strings.ToLower(cleanIdentPattern.ReplaceAllString(toolName, ""))
	if !strings.HasPrefix(cleanName, "mcp_") {
		return cleanName, "", ""
	}

	remainder := cleanName[4:]
	parts := strings.Split(remainder, "_")
	if len(parts) < 2 {
		return cleanName, "", ""
	}

	// Try split points from right to left, looking for known verb prefixes or exact read matches
	for i := len(parts) - 1; i > 0; i-- {
		candidateTool := strings.Join(parts[i:], "_")
		for _, prefix := range SafeMcpReadPrefixes {
			if strings.HasPrefix(candidateTool, prefix) {
				return cleanName, strings.Join(parts[:i], "_"), candidateTool
			}
		}
		if SafeMcpReadExact[candidateTool] {
			return cleanName, strings.Join(parts[:i], "_"), candidateTool
		}
		for _, verb := range MutatingVerbs {
			if strings.HasPrefix(candidateTool, verb+"_") {
				return cleanName, strings.Join(parts[:i], "_"), candidateTool
			}
		}
	}

	// Fallback to first underscore
	return cleanName, parts[0], strings.Join(parts[1:], "_")
}

// IsSafeReadOnlyMCP checks if an MCP call is purely read-only and safe for fast-path.
func IsSafeReadOnlyMCP(server, subTool string) bool {
	server = strings.TrimSpace(server)
	subTool = strings.ToLower(strings.TrimSpace(subTool))
	if server == "" || subTool == "" {
		return false
	}

	isRead := false
	for _, prefix := range SafeMcpReadPrefixes {
		if strings.HasPrefix(subTool, prefix) {
			isRead = true
			break
		}
	}
	if !isRead && SafeMcpReadExact[subTool] {
		isRead = true
	}

	if !isRead {
		return false
	}

	// Make sure no mutating verb is embedded
	for _, verb := range MutatingVerbs {
		if strings.Contains(subTool, verb) {
			return false
		}
	}

	return true
}
