package evaluator

import (
	"strings"
)

var SafeLocalGitPrefixes = []string{
	"git add", "git commit", "git status", "git diff", "git log",
	"git branch", "git checkout", "git switch", "git stash", "git show", "git tag",
}

var RemoteOrRiskyGitFlags = []string{
	"push", "--force", "-f", "-D", "-d", "--delete", "--hard",
	"clean", "reset", "rebase", "remote", "restore", "clear", "drop", "--discard-changes",
}

const ShellMetachars = ";&|`$><\n\r()"

// IsSafeLocalGitCommand checks whether a command is a safe, non-destructive, non-remote local git operation.
func IsSafeLocalGitCommand(commandLine string) bool {
	cmd := strings.TrimSpace(commandLine)
	if !strings.HasPrefix(cmd, "git ") {
		return false
	}

	// Disallow shell chaining, subshells, or redirection from bypassing LLM evaluation
	if strings.ContainsAny(cmd, ShellMetachars) {
		return false
	}

	tokens := strings.Fields(cmd)
	if len(tokens) == 0 || tokens[0] != "git" {
		return false
	}

	// Check against risky flags
	tokenSet := make(map[string]bool)
	for _, tok := range tokens {
		tokenSet[tok] = true
	}
	for _, risky := range RemoteOrRiskyGitFlags {
		if tokenSet[risky] {
			return false
		}
	}

	// Check destructive checkout:
	// `git checkout <anything>` without `--` and without `-b`/`-B` is ambiguous between a branch
	// switch and `git checkout <file>` (which silently discards uncommitted changes to that file).
	if tokenSet["checkout"] {
		for i, tok := range tokens {
			if tok == "checkout" {
				checkoutArgs := tokens[i+1:]
				for _, arg := range checkoutArgs {
					if arg == "." || arg == "--" {
						return false // destructive discard
					}
				}
				hasNewBranchFlag := false
				for _, arg := range checkoutArgs {
					if arg == "-b" || arg == "-B" {
						hasNewBranchFlag = true
						break
					}
				}
				if !hasNewBranchFlag {
					for _, arg := range checkoutArgs {
						if !strings.HasPrefix(arg, "-") {
							// Any positional arg without -b/-B could be a destructive file target
							return false
						}
					}
				}
				break
			}
		}
	}

	// Ensure it starts with one of the safe prefixes
	for _, prefix := range SafeLocalGitPrefixes {
		if strings.HasPrefix(cmd, prefix) {
			return true
		}
	}

	return false
}
