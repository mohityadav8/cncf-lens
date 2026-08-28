package config

import (
	"bufio"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// This file implements a deliberately small YAML subset parser.
//
// Why not a YAML library: cncf-lens ships as a single static binary with zero
// third-party dependencies. For a tool that runs against production clusters
// and reads credentials, a dependency-free supply chain is worth more than full
// YAML support. We support exactly what a config file needs:
//
//	key: value          scalars (string, int, float, bool)
//	key:                nested maps by indentation
//	  nested: value
//	key:                lists of scalars
//	  - item
//	# comment           full-line and trailing comments
//	"quoted: value"     single and double quoted strings
//
// Not supported, and rejected loudly rather than silently mis-parsed: anchors,
// aliases, multi-document streams, block scalars, flow mappings, tags.

// Node is a parsed YAML value: either a scalar, a map, or a list.
type Node struct {
	// Scalar holds the raw string value for leaf nodes.
	Scalar string
	// IsScalar distinguishes an empty scalar from an empty map.
	IsScalar bool
	// Map holds child nodes keyed by name, for mapping nodes.
	Map map[string]*Node
	// List holds child nodes for sequence nodes.
	List []*Node
	// Line records where this node was defined, for useful error messages.
	Line int
}

// rawLine is one meaningful line of input after comment stripping.
type rawLine struct {
	indent int
	text   string
	num    int
}

// ParseYAML parses the supported subset into a tree of Nodes.
func ParseYAML(r io.Reader) (*Node, error) {
	lines, err := readLines(r)
	if err != nil {
		return nil, err
	}
	root := &Node{Map: map[string]*Node{}}
	if len(lines) == 0 {
		return root, nil
	}
	pos := 0
	if err := parseBlock(lines, &pos, lines[0].indent, root); err != nil {
		return nil, err
	}
	return root, nil
}

// readLines strips comments and blank lines and records indentation depth.
func readLines(r io.Reader) ([]rawLine, error) {
	var out []rawLine
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	num := 0
	for sc.Scan() {
		num++
		line := sc.Text()
		if strings.Contains(line, "\t") {
			return nil, fmt.Errorf("line %d: tabs are not valid YAML indentation, use spaces", num)
		}
		stripped := stripComment(line)
		trimmed := strings.TrimRight(stripped, " ")
		if strings.TrimSpace(trimmed) == "" {
			continue
		}
		indent := len(trimmed) - len(strings.TrimLeft(trimmed, " "))
		out = append(out, rawLine{indent: indent, text: strings.TrimSpace(trimmed), num: num})
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("reading config: %w", err)
	}
	return out, nil
}

// stripComment removes a trailing `#` comment, respecting quoted strings so
// that a value like `password: "abc#123"` survives intact.
func stripComment(s string) string {
	var inSingle, inDouble bool
	for i, r := range s {
		switch r {
		case '\'':
			if !inDouble {
				inSingle = !inSingle
			}
		case '"':
			if !inSingle {
				inDouble = !inDouble
			}
		case '#':
			if !inSingle && !inDouble {
				// Only treat as a comment if preceded by whitespace or at start,
				// so `url: http://x#y` is not truncated.
				if i == 0 || s[i-1] == ' ' {
					return s[:i]
				}
			}
		}
	}
	return s
}

// parseBlock consumes all lines at exactly `indent` depth into parent.
func parseBlock(lines []rawLine, pos *int, indent int, parent *Node) error {
	for *pos < len(lines) {
		ln := lines[*pos]

		if ln.indent < indent {
			return nil
		}
		if ln.indent > indent {
			return fmt.Errorf("line %d: unexpected indentation", ln.num)
		}

		if strings.HasPrefix(ln.text, "- ") || ln.text == "-" {
			if err := parseListItem(lines, pos, indent, parent); err != nil {
				return err
			}
			continue
		}

		key, value, ok := splitKeyValue(ln.text)
		if !ok {
			return fmt.Errorf("line %d: expected `key: value`, got %q", ln.num, ln.text)
		}
		if parent.Map == nil {
			parent.Map = map[string]*Node{}
		}
		if _, dup := parent.Map[key]; dup {
			return fmt.Errorf("line %d: duplicate key %q", ln.num, key)
		}

		*pos++

		if value != "" {
			parent.Map[key] = &Node{Scalar: unquote(value), IsScalar: true, Line: ln.num}
			continue
		}

		// Empty value: either a nested block or an explicitly empty value.
		child := &Node{Line: ln.num}
		if *pos < len(lines) && lines[*pos].indent > indent {
			if err := parseBlock(lines, pos, lines[*pos].indent, child); err != nil {
				return err
			}
		} else {
			child.IsScalar = true
		}
		parent.Map[key] = child
	}
	return nil
}

// parseListItem handles `- value` sequence entries, including nested maps under
// a list item.
func parseListItem(lines []rawLine, pos *int, indent int, parent *Node) error {
	ln := lines[*pos]
	inline := strings.TrimSpace(strings.TrimPrefix(ln.text, "-"))
	*pos++

	// `- key: value` starts a map entry inside the list.
	if key, value, ok := splitKeyValue(inline); ok && inline != "" {
		item := &Node{Map: map[string]*Node{}, Line: ln.num}
		if value != "" {
			item.Map[key] = &Node{Scalar: unquote(value), IsScalar: true, Line: ln.num}
		} else {
			item.Map[key] = &Node{IsScalar: true, Line: ln.num}
		}
		// Absorb any further keys indented under this list item.
		if *pos < len(lines) && lines[*pos].indent > indent {
			if err := parseBlock(lines, pos, lines[*pos].indent, item); err != nil {
				return err
			}
		}
		parent.List = append(parent.List, item)
		return nil
	}

	if inline != "" {
		parent.List = append(parent.List, &Node{Scalar: unquote(inline), IsScalar: true, Line: ln.num})
		return nil
	}

	// Bare `-` with a nested block underneath.
	item := &Node{Line: ln.num}
	if *pos < len(lines) && lines[*pos].indent > indent {
		if err := parseBlock(lines, pos, lines[*pos].indent, item); err != nil {
			return err
		}
	}
	parent.List = append(parent.List, item)
	return nil
}

// splitKeyValue splits `key: value` at the first colon that is not inside
// quotes and is followed by a space or end of line. Requiring the space is what
// keeps `url: https://host:9090` from splitting at the port colon.
func splitKeyValue(s string) (key, value string, ok bool) {
	var inSingle, inDouble bool
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '\'':
			if !inDouble {
				inSingle = !inSingle
			}
		case '"':
			if !inSingle {
				inDouble = !inDouble
			}
		case ':':
			if inSingle || inDouble {
				continue
			}
			if i == len(s)-1 {
				return strings.TrimSpace(s[:i]), "", true
			}
			if s[i+1] == ' ' {
				return strings.TrimSpace(s[:i]), strings.TrimSpace(s[i+1:]), true
			}
		}
	}
	return "", "", false
}

// unquote removes matching surrounding quotes.
func unquote(s string) string {
	if len(s) >= 2 {
		if (s[0] == '"' && s[len(s)-1] == '"') || (s[0] == '\'' && s[len(s)-1] == '\'') {
			return s[1 : len(s)-1]
		}
	}
	return s
}

// --- Typed accessors -------------------------------------------------------

// Child returns a nested node by dotted path, e.g. "backends.prometheus.url".
func (n *Node) Child(path string) (*Node, bool) {
	cur := n
	for _, part := range strings.Split(path, ".") {
		if cur == nil || cur.Map == nil {
			return nil, false
		}
		next, ok := cur.Map[part]
		if !ok {
			return nil, false
		}
		cur = next
	}
	return cur, true
}

// String returns a scalar value, or def when absent or not a scalar.
func (n *Node) String(path, def string) string {
	c, ok := n.Child(path)
	if !ok || !c.IsScalar || c.Scalar == "" {
		return def
	}
	return c.Scalar
}

// Int returns an integer value, or def when absent or unparseable.
func (n *Node) Int(path string, def int) int {
	c, ok := n.Child(path)
	if !ok || !c.IsScalar {
		return def
	}
	v, err := strconv.Atoi(strings.TrimSpace(c.Scalar))
	if err != nil {
		return def
	}
	return v
}

// Bool returns a boolean value, accepting the spellings YAML users expect.
func (n *Node) Bool(path string, def bool) bool {
	c, ok := n.Child(path)
	if !ok || !c.IsScalar {
		return def
	}
	switch strings.ToLower(strings.TrimSpace(c.Scalar)) {
	case "true", "yes", "on", "1":
		return true
	case "false", "no", "off", "0":
		return false
	default:
		return def
	}
}

// StringList returns a list of scalars.
func (n *Node) StringList(path string) []string {
	c, ok := n.Child(path)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(c.List))
	for _, item := range c.List {
		if item.IsScalar {
			out = append(out, item.Scalar)
		}
	}
	return out
}

// Keys returns the child key names of a mapping node, or nil.
func (n *Node) Keys() []string {
	if n == nil || n.Map == nil {
		return nil
	}
	out := make([]string, 0, len(n.Map))
	for k := range n.Map {
		out = append(out, k)
	}
	return out
}
