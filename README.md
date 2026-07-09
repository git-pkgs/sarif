# sarif

Go library for reading, writing, and validating SARIF (Static Analysis Results Interchange Format) 2.1.0 logs.

Ported from [github.com/andrew/sarif](https://github.com/andrew/sarif).

## Installation

```
go get github.com/git-pkgs/sarif
```

## Usage

```go
import "github.com/git-pkgs/sarif"

log := &sarif.Log{
    Version: "2.1.0",
    Runs: []sarif.Run{
        {
            Tool: sarif.Tool{
                Driver: sarif.ToolComponent{
                    Name:    "my-linter",
                    Version: "1.0.0",
                },
            },
            Results: []sarif.Result{
                {
                    RuleID: "no-unused-vars",
                    Level:  "warning",
                    Message: sarif.Message{
                        Text: "Variable 'x' is unused",
                    },
                    Locations: []sarif.Location{
                        {
                            PhysicalLocation: sarif.PhysicalLocation{
                                ArtifactLocation: sarif.ArtifactLocation{URI: "src/main.go"},
                                Region:           sarif.Region{StartLine: 10, StartColumn: 5},
                            },
                        },
                    },
                },
            },
        },
    },
}

if err := sarif.Validate(log); err != nil {
    log.Fatal(err)
}

sarif.Dump(log, os.Stdout, true)
```

## Parsing

```go
data, _ := os.ReadFile("results.sarif")
log, err := sarif.Parse(data)
if err != nil {
    log.Fatal(err)
}

for _, run := range log.Runs {
    fmt.Println(run.Tool.Driver.Name)
    for _, result := range run.Results {
        fmt.Println(result.RuleID, result.Message.Text)
    }
}
```

## Validation

`Validate` checks a `*sarif.Log` against the bundled SARIF 2.1.0 JSON schema using `github.com/santhosh-tekuri/jsonschema/v6`.

```go
if sarif.Valid(log) {
    // log is valid SARIF 2.1.0
}
```

## Regenerating Types

Types are generated from the bundled SARIF JSON schema:

```
go generate ./...
```

The generator lives in `cmd/sarifgen` and writes `types_gen.go`.

## License

MIT
