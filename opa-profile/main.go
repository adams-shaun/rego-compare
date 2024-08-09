package main

import (
	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/metrics"
	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/storage"
	"github.com/open-policy-agent/opa/storage/inmem"
	"github.com/open-policy-agent/opa/util"
	"github.com/urfave/cli/v2"

	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"
)

// Save on allocations and instrumentation overhead
var (
	noopMetrics     metrics.Metrics     = new(NoopEvalMetrics)
	noopTimer       metrics.Timer       = new(NoopEvalTimer)
	noopTransaction storage.Transaction = new(NoopTransaction)
)

type (
	NoopEvalMetrics struct{}
	NoopEvalTimer   struct{}
	NoopTransaction struct{}
)

func (m *NoopEvalMetrics) Info() metrics.Info                      { return metrics.Info{Name: "NoopMetrics"} }
func (m *NoopEvalMetrics) Timer(name string) metrics.Timer         { return noopTimer }
func (m *NoopEvalMetrics) Histogram(name string) metrics.Histogram { return nil }
func (m *NoopEvalMetrics) Counter(name string) metrics.Counter     { return nil }
func (m *NoopEvalMetrics) All() map[string]interface{}             { return nil }
func (m *NoopEvalMetrics) Clear()                                  {}
func (m *NoopEvalMetrics) MarshalJSON() ([]byte, error)            { return nil, nil }

func (t *NoopEvalTimer) Value() interface{} { return nil }
func (t *NoopEvalTimer) Int64() int64       { return 0 }
func (t *NoopEvalTimer) Start()             {}
func (t *NoopEvalTimer) Stop() int64        { return 0 }

func (tx *NoopTransaction) ID() uint64 { return 0 }

func action(cCtx *cli.Context) error {
	ctx := context.Background()
	var options []func(r *rego.Rego)

	for _, file := range cCtx.StringSlice("data") {
		contents, err := os.ReadFile(file)
		if strings.HasSuffix(file, "json") {
			var data map[string]interface{}
			if err := json.Unmarshal(contents, &data); err != nil {
				return err
			}
			store := inmem.NewFromObject(data)
			options = append(options, rego.Store(store))
			continue
		}
		if err != nil {
			return err
		}
		d := rego.Module(file, string(contents))
		options = append(options, d)
	}

	args := cCtx.Args()
	if !args.Present() || args.Get(1) != "" {
		return errors.New("exactly 1 query must be specified")
	}

	options = append(options, rego.Query(args.Get(0)))
	r := rego.New(options...)
	query, err := r.PrepareForEval(ctx)
	if err != nil {
		return err
	}

	inputJson, err := os.ReadFile(cCtx.String("input"))
	if err != nil {
		return err
	}
	var input interface{}
	if err := json.Unmarshal(inputJson, &input); err != nil {
		return err
	}

	var rs interface{}
	numIterations := cCtx.Int("num-iterations")
	if numIterations == 0 {
		return errors.New("num-iterations must be specified")
	}

	rawPtr := util.Reference(input)
	parsedInput, _ := ast.InterfaceToValue(*rawPtr)

	start := time.Now()
	for i := 0; i < numIterations; i++ {
		rs, err = query.Eval(ctx, rego.EvalParsedInput(parsedInput)) //, rego.EvalMetrics(noopMetrics), rego.EvalTransaction(noopTransaction))
		if err != nil {
			return err
		}
	}

	rsJson, err := json.MarshalIndent(rs, "", "  ")
	if err != nil {
		return err
	}
	if cCtx.Bool("show-output") {
		fmt.Println("", string(rsJson))
	}

	elapsed := time.Since(start)
	average := float64(elapsed.Microseconds()) / float64(numIterations)
	fmt.Printf("average eval time = %.2f microseconds\n", average)
	return nil

}

func main() {
	app := cli.NewApp()
	app.Name = "opa-profile"
	app.Description = "Profile OPA execution time"
	app.Flags = []cli.Flag{
		&cli.StringSliceFlag{
			Name:    "data",
			Aliases: []string{"d"},
			Usage:   "Rego policy or data json",
		},
		&cli.StringFlag{
			Name:    "input",
			Aliases: []string{"i"},
			Usage:   "input json",
		},
		&cli.IntFlag{
			Name:    "num-iterations",
			Aliases: []string{"n"},
			Usage:   "numer of iterations",
		},
		&cli.IntFlag{
			Name:    "show-output",
			Aliases: []string{"s"},
			Usage:   "show eval output",
		},
	}
	app.Action = action

	if err := app.Run(os.Args); err != nil {
		fmt.Printf("%v", err)
	}
}
