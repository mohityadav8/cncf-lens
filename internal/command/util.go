package command

import "strings"

// truncateStr shortens a string to n runes, appending an ellipsis. Rune-aware
// so multi-byte log output is never cut mid-character.
func truncateStr(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	if n <= 1 {
		return string(r[:n])
	}
	return string(r[:n-1]) + "…"
}

// oneLineStr collapses whitespace so a multi-line log entry occupies one row.
func oneLineStr(s string) string {
	return strings.Join(strings.Fields(strings.ReplaceAll(s, "\n", " ")), " ")
}
