package evaluator

import (
	"strings"
)

// shellSplit tokenizes a command line the way Python's shlex.split does: quoted regions
// (single or double) become one token with the quote characters stripped, so a commit
// message like `git commit -m "reset the counter"` produces the token `reset the counter`
// rather than shattering into separate words. A naive strings.Fields split does the
// latter, which lets an ordinary English word inside a quoted argument (e.g. "reset",
// "clean", "drop" — all of which are also risky git flags) spuriously match the risky-flag
// check below, and can also let a quoted "." or "--" checkout argument dodge the
// destructive-checkout check by leaving quote characters glued to the token.
func shellSplit(s string) []string {
	var tokens []string
	var cur strings.Builder
	hasToken := false
	inSingle, inDouble := false, false

	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case inSingle:
			if c == '\'' {
				inSingle = false
			} else {
				cur.WriteByte(c)
			}
		case inDouble:
			if c == '"' {
				inDouble = false
			} else if c == '\\' && i+1 < len(s) && (s[i+1] == '"' || s[i+1] == '\\') {
				i++
				cur.WriteByte(s[i])
			} else {
				cur.WriteByte(c)
			}
		case c == '\'':
			inSingle = true
			hasToken = true
		case c == '"':
			inDouble = true
			hasToken = true
		case c == ' ' || c == '\t':
			if hasToken {
				tokens = append(tokens, cur.String())
				cur.Reset()
				hasToken = false
			}
		case c == '\\' && i+1 < len(s):
			i++
			cur.WriteByte(s[i])
			hasToken = true
		default:
			cur.WriteByte(c)
			hasToken = true
		}
	}
	if hasToken {
		tokens = append(tokens, cur.String())
	}
	return tokens
}

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

	tokens := shellSplit(cmd)
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
