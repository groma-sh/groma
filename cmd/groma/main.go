package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/homedir"
	policyapi "sigs.k8s.io/network-policy-api/pkg/client/clientset/versioned"

	"github.com/groma-sh/groma/internal/analyzer"
	"github.com/groma-sh/groma/internal/attest"
	"github.com/groma-sh/groma/internal/evidence"
	"github.com/groma-sh/groma/internal/intent"
	"github.com/groma-sh/groma/internal/prober"
	"github.com/groma-sh/groma/internal/reconcile"
	reportpkg "github.com/groma-sh/groma/internal/report"
	"github.com/groma-sh/groma/internal/version"
)

const (
	modeActive = "active"
	modeStatic = "static"
	modeBoth   = "both"
)

func main() {
	var intentPath, outputPath, kubeconfig, probeImage, mode string
	var maxConcurrent, retries int
	var dryRun, showVersion bool
	var timeout time.Duration
	var emit emitOptions
	flag.StringVar(&intentPath, "intent", "", "path to a SegmentationIntent YAML file")
	flag.StringVar(&outputPath, "output", "", "path to write JSON evidence (default: stdout)")
	flag.StringVar(&mode, "mode", modeActive, "which signals to collect: active (runtime probing), static (policy analysis), or both (reconcile config vs runtime)")
	flag.IntVar(&maxConcurrent, "max-concurrent-probes", 8, "maximum probes to run in parallel")
	flag.StringVar(&probeImage, "probe-image", "busybox:1.36", "container image used for probe pods")
	flag.IntVar(&retries, "retries", 3, "connection attempts per probe before concluding blocked")
	flag.BoolVar(&dryRun, "dry-run", false, "resolve zones and print the probe plan without creating pods")
	flag.DurationVar(&timeout, "timeout", 0, "overall run timeout (0 = no cap)")
	flag.StringVar(&emit.statement, "statement", "", "path to write the unsigned in-toto statement JSON")
	flag.StringVar(&emit.attest, "attest", "", "path to write the signed in-toto attestation (DSSE envelope); requires --sign-key or --keyless")
	flag.StringVar(&emit.html, "html", "", "path to write the human-readable HTML report")
	flag.StringVar(&emit.signKey, "sign-key", "", "cosign key reference for --attest: a key file or a KMS/k8s URI (awskms://, gcpkms://, k8s://ns/secret)")
	flag.BoolVar(&emit.keyless, "keyless", false, "sign --attest keyless via Fulcio + Rekor over an ambient OIDC identity")
	flag.BoolVar(&emit.noRekor, "no-rekor", false, "with --keyless, skip uploading the signature to the Rekor transparency log")
	flag.StringVar(&emit.clusterID, "cluster-id", "", "cluster identifier recorded in the attestation")
	flag.StringVar(&emit.cni, "cni", "", "CNI name/version recorded in the attestation (informational)")
	defKubeconfig := ""
	if h := homedir.HomeDir(); h != "" {
		defKubeconfig = filepath.Join(h, ".kube", "config")
	}
	flag.StringVar(&kubeconfig, "kubeconfig", defKubeconfig, "path to kubeconfig")
	flag.BoolVar(&showVersion, "version", false, "print the Groma version and exit")
	flag.Parse()

	if showVersion {
		fmt.Println(version.Get())
		return
	}

	if intentPath == "" {
		fmt.Fprintln(os.Stderr, "error: --intent is required")
		os.Exit(2)
	}
	if mode != modeActive && mode != modeStatic && mode != modeBoth {
		fmt.Fprintf(os.Stderr, "error: --mode must be one of %s, %s, %s\n", modeActive, modeStatic, modeBoth)
		os.Exit(2)
	}

	si, err := intent.Load(intentPath)
	if err != nil {
		fatal(err)
	}

	cfg, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		fatal(err)
	}
	client, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		fatal(err)
	}

	ctx := context.Background()
	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}

	report := &evidence.Report{
		Intent:    si.Metadata.Name,
		Framework: si.Compliance.Framework,
		Controls:  si.Compliance.Controls,
		Mode:      modeLabel(mode),
		StartedAt: time.Now().UTC(),
	}
	pr := prober.New(client, prober.Options{
		MaxConcurrentProbes: maxConcurrent,
		Image:               probeImage,
		Retries:             retries,
		DryRun:              dryRun,
	})

	checks, zones, err := pr.Plan(ctx, si)
	if err != nil {
		fatal(err)
	}
	report.Zones = zones
	report.Probes, err = collect(ctx, mode, pr, client, cfg, checks)
	if err != nil {
		fatal(err)
	}
	reconcile.SetEnforcement(report)
	report.FinishedAt = time.Now().UTC()
	report.Summarize()
	report.RenderText(os.Stderr)

	out := os.Stdout
	if outputPath != "" {
		f, err := os.Create(outputPath)
		if err != nil {
			fatal(err)
		}
		defer f.Close()
		out = f
	}
	if err := report.Write(out); err != nil {
		fatal(err)
	}

	if err := emit.run(ctx, report, si); err != nil {
		fatal(err)
	}

	switch report.Result {
	case evidence.Pass, evidence.Skipped:
	default:
		os.Exit(1)
	}
}

func collect(ctx context.Context, mode string, pr *prober.Prober, client kubernetes.Interface, cfg *rest.Config, checks []prober.Check) ([]evidence.Probe, error) {
	if mode == modeActive {
		return pr.ProbeChecks(ctx, checks), nil
	}

	an, err := buildAnalyzer(ctx, client, cfg)
	if err != nil {
		return nil, err
	}
	static := an.Analyze(checks)

	if mode == modeStatic {
		return reconcile.StaticProbes(checks, static), nil
	}
	runtime := pr.ProbeChecks(ctx, checks)
	return reconcile.Reconcile(checks, runtime, static), nil
}

func buildAnalyzer(ctx context.Context, client kubernetes.Interface, cfg *rest.Config) (*analyzer.Analyzer, error) {
	policyClient, err := policyapi.NewForConfig(cfg)
	if err != nil {
		return nil, err
	}
	return analyzer.New(ctx, client, policyClient)
}

func modeLabel(mode string) string {
	if mode == modeBoth {
		return "active+static"
	}
	return mode
}

type emitOptions struct {
	statement string
	attest    string
	html      string
	signKey   string
	keyless   bool
	noRekor   bool
	clusterID string
	cni       string
}

func (o emitOptions) run(ctx context.Context, report *evidence.Report, si *intent.SegmentationIntent) error {
	if o.statement == "" && o.attest == "" && o.html == "" {
		return nil
	}
	stmt, err := attest.BuildStatement(report, si, attest.Meta{
		GromaVersion: version.Get(),
		ClusterID:    o.clusterID,
		CNI:          o.cni,
	})
	if err != nil {
		return err
	}
	stmtBytes, err := stmt.Marshal()
	if err != nil {
		return err
	}

	if o.statement != "" {
		if err := os.WriteFile(o.statement, stmtBytes, 0o644); err != nil {
			return err
		}
	}
	if o.html != "" {
		f, err := os.Create(o.html)
		if err != nil {
			return err
		}
		defer f.Close()
		if err := reportpkg.RenderHTML(f, stmt); err != nil {
			return err
		}
	}
	if o.attest != "" {
		signer, err := o.signer(ctx)
		if err != nil {
			return err
		}
		res, err := signer.Sign(ctx, stmtBytes)
		if err != nil {
			return err
		}
		if err := os.WriteFile(o.attest, res.Envelope, 0o644); err != nil {
			return err
		}
		if len(res.CertChainPEM) > 0 {
			if err := os.WriteFile(o.attest+".pem", res.CertChainPEM, 0o644); err != nil {
				return err
			}
		}
		if res.RekorLogIndex != 0 {
			fmt.Fprintf(os.Stderr, "  attestation recorded in Rekor at log index %d\n", res.RekorLogIndex)
		}
	}
	return nil
}

func (o emitOptions) signer(ctx context.Context) (attest.Signer, error) {
	switch {
	case o.signKey != "":
		return attest.NewKeySigner(ctx, o.signKey)
	case o.keyless:
		return attest.NewKeylessSigner(attest.KeylessOptions{UploadTLog: !o.noRekor}), nil
	default:
		return nil, fmt.Errorf("--attest requires --sign-key <keyRef> or --keyless")
	}
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "error:", err)
	os.Exit(1)
}
