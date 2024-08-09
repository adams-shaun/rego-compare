package main

import (
	"opa-profile/regorus"

	"github.com/urfave/cli/v2"

	"errors"
	"fmt"
	"os"
	"strings"
	"time"
)

func action(cCtx *cli.Context) error {
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

	input, err := os.ReadFile(cCtx.String("input"))
	if err != nil {
		return err
	}
	parsedInput, err := regorus.ParseInput(string(input))
	if err != nil {
		return err
	}
	// err := eng.SetInputFromJsonFile(cCtx.String("input"))
	// if err != nil {
	// 	return err
	// }

	var rs interface{}
	numIterations := cCtx.Int("num-iterations")
	if numIterations == 0 {
		return errors.New("num-iterations must be specified")
	}
	asQuery := cCtx.Bool("as-query")

	var act, rule string
	start := time.Now()
	for i := 0; i < numIterations; i++ {
		if asQuery {
			rs, err = eng.EvalQuery(q)
			if err != nil {
				return err
			}
			continue
		}
		act, rule, err = eng.SetInputEvalRule2(parsedInput, q)
		if err != nil {
			return err
		}
	}
	elapsed := time.Since(start)
	if cCtx.Bool("show-output") {
		if asQuery {
			fmt.Println("", rs)
		} else {
			fmt.Printf("'action' : %s 'rule' : %s\n", act, rule)
		}
	}

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
		&cli.BoolFlag{
			Name:    "as-query",
			Aliases: []string{"q"},
			Usage:   "use eval query instead of rule",
		},
	}
	app.Action = action

	if err := app.Run(os.Args); err != nil {
		fmt.Printf("%v", err)
	}
}
