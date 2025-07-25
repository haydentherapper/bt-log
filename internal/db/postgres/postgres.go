package postgres

import (
	"fmt"
	"strings"
)

// Rebind takes a query with '?' placeholders and rewrites it for postgres's '$N' placeholders.
// Ignores an edge case of '?' characters inside single-quoted strings.
func Rebind(query string) string {
	var b strings.Builder
	n := 1
	inQuote := false
	for _, r := range query {
		if r == '\'' {
			inQuote = !inQuote
		}
		if r == '?' && !inQuote {
			fmt.Fprintf(&b, "$%d", n)
			n++
		} else {
			b.WriteRune(r)
		}
	}
	return b.String()
}
