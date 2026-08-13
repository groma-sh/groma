package main

import (
	"flag"
	"os"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
	policyapi "sigs.k8s.io/network-policy-api/pkg/client/clientset/versioned"

	groma "github.com/groma-sh/groma/api/v1alpha1"
	"github.com/groma-sh/groma/internal/controller"
)

func main() {
	var metricsAddr, probeAddr, evidenceNamespace, clusterID, cniAdapters string
	var leaderElect bool
	flag.StringVar(&metricsAddr, "metrics-bind-address", ":8080", "Prometheus metrics endpoint (0 disables it)")
	flag.StringVar(&probeAddr, "health-probe-bind-address", ":8081", "health probe endpoint")
	flag.StringVar(&evidenceNamespace, "evidence-namespace", "groma-system", "namespace evidence ConfigMaps are written to")
	flag.StringVar(&clusterID, "cluster-id", "", "cluster identifier recorded in evidence attestations")
	flag.StringVar(&cniAdapters, "cni-adapters", "auto", "CNI-native policy adapters to include in static analysis: auto, none, or a comma-separated list")
	flag.BoolVar(&leaderElect, "leader-elect", false, "enable leader election for HA (single replica by default in v0.2)")
	opts := zap.Options{Development: true}
	opts.BindFlags(flag.CommandLine)
	flag.Parse()

	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&opts)))
	setupLog := ctrl.Log.WithName("setup")

	scheme := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(scheme); err != nil {
		setupLog.Error(err, "unable to register client-go scheme")
		os.Exit(1)
	}
	if err := groma.AddToScheme(scheme); err != nil {
		setupLog.Error(err, "unable to register groma.dev/v1alpha1 scheme")
		os.Exit(1)
	}

	cfg := ctrl.GetConfigOrDie()

	mgr, err := ctrl.NewManager(cfg, ctrl.Options{
		Scheme:                 scheme,
		Metrics:                metricsserver.Options{BindAddress: metricsAddr},
		HealthProbeBindAddress: probeAddr,
		LeaderElection:         leaderElect,
		LeaderElectionID:       "groma-manager.groma.dev",
	})
	if err != nil {
		setupLog.Error(err, "unable to start manager")
		os.Exit(1)
	}

	clientset, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		setupLog.Error(err, "unable to build client-go clientset")
		os.Exit(1)
	}

	policyClient, err := policyapi.NewForConfig(cfg)
	if err != nil {
		setupLog.Error(err, "unable to build network-policy-api clientset")
		os.Exit(1)
	}

	dynamicClient, err := dynamic.NewForConfig(cfg)
	if err != nil {
		setupLog.Error(err, "unable to build dynamic client for CNI policy adapters")
		os.Exit(1)
	}

	if err := (&controller.ConformanceRunReconciler{
		Client:            mgr.GetClient(),
		APIReader:         mgr.GetAPIReader(),
		Scheme:            mgr.GetScheme(),
		Clientset:         clientset,
		PolicyClient:      policyClient,
		DynamicClient:     dynamicClient,
		CNIAdapters:       cniAdapters,
		EvidenceNamespace: evidenceNamespace,
		ClusterID:         clusterID,
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to set up ConformanceRun controller")
		os.Exit(1)
	}
	if err := (&controller.ConformanceScheduleReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to set up ConformanceSchedule controller")
		os.Exit(1)
	}

	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up health check")
		os.Exit(1)
	}
	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up ready check")
		os.Exit(1)
	}

	setupLog.Info("starting manager", "evidenceNamespace", evidenceNamespace, "cniAdapters", cniAdapters)
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		setupLog.Error(err, "problem running manager")
		os.Exit(1)
	}
}
