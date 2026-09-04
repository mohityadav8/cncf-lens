// Command lens is a unified observability CLI for the CNCF stack.
//
// It queries Kubernetes, Prometheus, Loki, Jaeger and any registered plugin
// concurrently, then correlates the results onto a single timeline so that a
// metric spike, the deployment that caused it and the resulting log errors can
// be seen together instead of across five browser tabs.
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/mohityadav8/cncf-lens/internal/adapter"
	"github.com/mohityadav8/cncf-lens/internal/cli"
	"github.com/mohityadav8/cncf-lens/internal/command"
)

// version is overridden at build time:
//
//	go build -ldflags "-X main.version=$(git describe --tags)"
var version = "v0.0.2"

func main() {
	// Propagate the build version into the packages that report it.
	command.Version = version
	adapter.Version = version

	// Ctrl-C cancels in-flight backend queries rather than leaving them to time
	// out, so the tool exits immediately when an engineer changes their mind.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	app := cli.NewApp("lens", version,
		"unified observability and correlation across the CNCF stack")
	app.GlobalFlags = command.RegisterGlobals

	app.Add(command.Diagnose())
	app.Add(command.Trace())
	app.Add(command.Watch())
	app.Add(command.Audit())
	app.Add(command.Cost())
	app.Add(command.Init())
	app.Add(command.Doctor())
	app.Add(command.Completion())

	os.Exit(app.Run(ctx, os.Args[1:]))
}
