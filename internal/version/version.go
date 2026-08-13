package version

// Version is stamped into every evidence artifact and attestation, so an
// auditor can tell which build produced a verdict. Release builds override it
// via -ldflags; the constant here is the fallback for `go build` and `go test`.
var Version = "0.2.0"
