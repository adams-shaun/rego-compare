package main

import (
	"opa-profile/regorus"

	"github.com/open-policy-agent/opa/metrics"
	"github.com/open-policy-agent/opa/storage"
	"github.com/urfave/cli/v2"

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
	// ctx := context.Background()
	// var options []func(r *rego.Rego)
	data := make([]byte, 160000)
	eng := regorus.NewEngine()

	for _, file := range cCtx.StringSlice("data") {
		if strings.HasSuffix(file, "rego") {
			_, err := eng.AddPolicyFromFile(file)
			if err != nil {
				return err
			}
			continue
		}
	}

	args := cCtx.Args()
	if !args.Present() || args.Get(1) != "" {
		return errors.New("exactly 1 query must be specified")
	}

	q := args.Get(0)
	// options = append(options, rego.Query(args.Get(0)))
	// r := rego.New(options...)
	// query, err := r.PrepareForEval(ctx)
	// if err != nil {
	// 	return err
	// }

	err := eng.SetInputFromJsonFile(cCtx.String("input"))
	if err != nil {
		return err
	}

	var rs interface{}
	numIterations := cCtx.Int("num-iterations")
	if numIterations == 0 {
		return errors.New("num-iterations must be specified")
	}

	// rawPtr := util.Reference(input)
	// parsedInput, _ := ast.InterfaceToValue(*rawPtr)

	start := time.Now()
	for i := 0; i < numIterations; i++ {
		rs, err = eng.EvalRule(q) //, rego.EvalMetrics(noopMetrics), rego.EvalTransaction(noopTransaction))
		if err != nil {
			return err
		}
	}
	elapsed := time.Since(start)
	// rsJson, err := json.MarshalIndent(rs, "", "  ")
	// if err != nil {
	// 	return err
	// }
	if cCtx.Bool("show-output") {
		// fmt.Println("", string(rsJson))
		fmt.Println("", rs)
	}

	// fmt.Println("", len(data))
	// elapsed := time.Since(start)
	average := float64(elapsed.Microseconds()) / float64(numIterations)
	fmt.Printf("average eval time = %.2f microseconds, stack data %d bytes\n", average, len(data))
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
