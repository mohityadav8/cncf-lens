// Package cli provides a small subcommand framework.
//
// Replaces cobra to keep the binary dependency-free. It covers what lens needs:
// subcommands, per-command flags via the standard library's flag package,
// grouped help output, and consistent error handling.
package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"text/tabwriter"
)

// Command is one lens subcommand.
type Command struct {
	// Name is the word the user types, e.g. "diagnose".
	Name string
	// Summary is the one-line description shown in `lens --help`.
	Summary string
	// Usage is the argument shape, e.g. "lens trace --pod=NAME".
	Usage string
	// Long is the extended help shown by `lens help <command>`.
	Long string
	// Examples are shown at the end of the command's help.
	Examples []string
	// Group buckets the command in help output.
	Group string
	// SetupFlags registers command-specific flags.
	SetupFlags func(fs *flag.FlagSet)
	// Run executes the command. args are the positional arguments remaining
	// after flag parsing.
	Run func(ctx context.Context, args []string) error
}

// App is the root command dispatcher.
type App struct {
	Name        string
	Version     string
	Description string

	commands map[string]*Command
	order    []string

	// GlobalFlags registers flags accepted by every subcommand.
	GlobalFlags func(fs *flag.FlagSet)

	Out io.Writer
	Err io.Writer
}

// NewApp constructs an App.
func NewApp(name, version, description string) *App {
	return &App{
		Name:        name,
		Version:     version,
		Description: description,
		commands:    map[string]*Command{},
		Out:         os.Stdout,
		Err:         os.Stderr,
	}
}

// Add registers a command.
func (a *App) Add(c *Command) {
	a.commands[c.Name] = c
	a.order = append(a.order, c.Name)
}

// ErrUsage signals that the user made a usage mistake, so main can exit 2
// (conventionally "usage error") rather than 1 ("the operation failed").
// Scripts wrapping lens rely on that distinction.
var ErrUsage = errors.New("usage error")

// Run dispatches to a subcommand. Returns the exit code.
func (a *App) Run(ctx context.Context, argv []string) int {
	if len(argv) == 0 {
		a.printHelp()
		return 0
	}

	switch argv[0] {
	case "-h", "--help", "help":
		if len(argv) > 1 {
			return a.printCommandHelp(argv[1])
		}
		a.printHelp()
		return 0
	case "-v", "--version", "version":
		fmt.Fprintf(a.Out, "%s %s\n", a.Name, a.Version)
		return 0
	}

	cmd, ok := a.commands[argv[0]]
	if !ok {
		fmt.Fprintf(a.Err, "%s: unknown command %q\n", a.Name, argv[0])
		if suggestion := a.suggest(argv[0]); suggestion != "" {
			fmt.Fprintf(a.Err, "\nDid you mean `%s %s`?\n", a.Name, suggestion)
		}
		fmt.Fprintf(a.Err, "\nRun `%s --help` for the command list.\n", a.Name)
		return 2
	}

	fs := flag.NewFlagSet(cmd.Name, flag.ContinueOnError)
	fs.SetOutput(a.Err)
	fs.Usage = func() { _ = a.printCommandHelp(cmd.Name) }

	if a.GlobalFlags != nil {
		a.GlobalFlags(fs)
	}
	if cmd.SetupFlags != nil {
		cmd.SetupFlags(fs)
	}

	if err := fs.Parse(argv[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}

	if err := cmd.Run(ctx, fs.Args()); err != nil {
		if errors.Is(err, ErrUsage) {
			fmt.Fprintf(a.Err, "%s\n\n", err)
			_ = a.printCommandHelp(cmd.Name)
			return 2
		}
		if errors.Is(err, context.Canceled) {
			fmt.Fprintln(a.Err, "\ninterrupted")
			return 130 // 128 + SIGINT, the shell convention
		}
		fmt.Fprintf(a.Err, "error: %s\n", err)
		return 1
	}
	return 0
}

// suggest offers the closest command name for a typo, using edit distance.
func (a *App) suggest(input string) string {
	best, bestDist := "", 1<<30
	for name := range a.commands {
		d := editDistance(input, name)
		if d < bestDist {
			best, bestDist = name, d
		}
	}
	// Only suggest when the typo is plausibly a typo, not a different word.
	if bestDist <= 3 && bestDist < len(input) {
		return best
	}
	return ""
}

// editDistance is standard Levenshtein with a rolling single-row buffer.
func editDistance(a, b string) int {
	if a == b {
		return 0
	}
	prev := make([]int, len(b)+1)
	cur := make([]int, len(b)+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= len(a); i++ {
		cur[0] = i
		for j := 1; j <= len(b); j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			cur[j] = min3(cur[j-1]+1, prev[j]+1, prev[j-1]+cost)
		}
		prev, cur = cur, prev
	}
	return prev[len(b)]
}

func min3(a, b, c int) int {
	m := a
	if b < m {
		m = b
	}
	if c < m {
		m = c
	}
	return m
}

func (a *App) printHelp() {
	fmt.Fprintf(a.Out, "%s — %s\n\n", a.Name, a.Description)
	fmt.Fprintf(a.Out, "Usage:\n  %s <command> [flags]\n\n", a.Name)

	groups := map[string][]*Command{}
	for _, name := range a.order {
		c := a.commands[name]
		g := c.Group
		if g == "" {
			g = "Commands"
		}
		groups[g] = append(groups[g], c)
	}

	groupNames := make([]string, 0, len(groups))
	for g := range groups {
		groupNames = append(groupNames, g)
	}
	sort.Strings(groupNames)

	tw := tabwriter.NewWriter(a.Out, 0, 0, 3, ' ', 0)
	for _, g := range groupNames {
		fmt.Fprintf(tw, "%s:\n", g)
		cmds := groups[g]
		sort.Slice(cmds, func(i, j int) bool { return cmds[i].Name < cmds[j].Name })
		for _, c := range cmds {
			fmt.Fprintf(tw, "  %s\t%s\n", c.Name, c.Summary)
		}
		fmt.Fprintln(tw)
	}
	_ = tw.Flush()

	fmt.Fprintf(a.Out, "Run `%s help <command>` for details on a command.\n", a.Name)
}

func (a *App) printCommandHelp(name string) int {
	cmd, ok := a.commands[name]
	if !ok {
		fmt.Fprintf(a.Err, "unknown command %q\n", name)
		return 2
	}

	fmt.Fprintf(a.Out, "%s\n\n", cmd.Summary)
	if cmd.Usage != "" {
		fmt.Fprintf(a.Out, "Usage:\n  %s\n\n", cmd.Usage)
	}
	if cmd.Long != "" {
		fmt.Fprintf(a.Out, "%s\n\n", strings.TrimSpace(cmd.Long))
	}

	fs := flag.NewFlagSet(cmd.Name, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	if a.GlobalFlags != nil {
		a.GlobalFlags(fs)
	}
	if cmd.SetupFlags != nil {
		cmd.SetupFlags(fs)
	}

	var flagLines []string
	fs.VisitAll(func(f *flag.Flag) {
		def := ""
		if f.DefValue != "" && f.DefValue != "false" {
			def = fmt.Sprintf(" (default %s)", f.DefValue)
		}
		flagLines = append(flagLines, fmt.Sprintf("  --%s\t%s%s", f.Name, f.Usage, def))
	})
	if len(flagLines) > 0 {
		fmt.Fprintln(a.Out, "Flags:")
		tw := tabwriter.NewWriter(a.Out, 0, 0, 3, ' ', 0)
		for _, l := range flagLines {
			fmt.Fprintln(tw, l)
		}
		_ = tw.Flush()
		fmt.Fprintln(a.Out)
	}

	if len(cmd.Examples) > 0 {
		fmt.Fprintln(a.Out, "Examples:")
		for _, ex := range cmd.Examples {
			fmt.Fprintf(a.Out, "  %s\n", ex)
		}
		fmt.Fprintln(a.Out)
	}
	return 0
}
