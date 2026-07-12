# sarif

Go library for reading, writing, and validating SARIF (Static Analysis Results Interchange Format) 2.1.0 logs.

Ported from [github.com/andrew/sarif](https://github.com/andrew/sarif).

## Installation

```
go get github.com/git-pkgs/sarif
```

## Usage

```go
import (
    "log"
    "os"

    "github.com/git-pkgs/sarif"
)

artifactLocation := sarif.NewArtifactLocation()
artifactLocation.URI = "src/main.go"

region := sarif.NewRegion()
region.StartLine = 10
region.StartColumn = 5

location := sarif.NewLocation()
location.PhysicalLocation = sarif.PhysicalLocation{
    ArtifactLocation: artifactLocation,
    Region:           region,
}

result := sarif.NewResult()
result.RuleID = "no-unused-vars"
result.Level = "warning"
result.Message = sarif.Message{Text: "Variable 'x' is unused"}
result.Locations = []sarif.Location{location}

report := &sarif.Log{
    Version: "2.1.0",
    Runs: []sarif.Run{
        {
            Tool: sarif.Tool{
                Driver: sarif.ToolComponent{
                    Name:    "my-linter",
                    Version: "1.0.0",
                },
            },
            Results: []sarif.Result{result},
        },
    },
}

if err := sarif.Validate(report); err != nil {
    log.Fatal(err)
}

sarif.Dump(report, os.Stdout, true)
```

Use the generated `New<Type>` constructors for types that define schema defaults. They initialize sentinel values such as `-1`, preventing unset indexes and offsets from being serialized as meaningful zeroes. Constructors are listed in the generated API documentation for each applicable type.

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
