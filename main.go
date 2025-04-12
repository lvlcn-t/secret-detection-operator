package main

import (
	"flag"
	"os"

	"github.com/lvlcn-t/secret-detection-operator/apis/v1alpha1"
	"github.com/lvlcn-t/secret-detection-operator/controllers"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	"sigs.k8s.io/controller-runtime/pkg/metrics/server"
)

var scheme = runtime.NewScheme()

// version is set on build time.
// Use -ldflags "-X main.version=1.0.0" to set the version.
var version string

func init() { //nolint:gochecknoinits // Common pattern for controller-runtime
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(v1alpha1.AddToScheme(scheme))
}

func main() {
	var metricsAddr string
	var enableLeaderElection bool
	flag.StringVar(&metricsAddr, "metrics-bind-address", ":8080", "The address for the metrics endpoint")
	flag.BoolVar(&enableLeaderElection, "leader-elect", false, "Enable leader election")

	opts := zap.Options{}
	opts.BindFlags(flag.CommandLine)
	flag.Parse()

	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&opts)))
	setupLog := ctrl.Log.WithName("setup")

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme:                 scheme,
		Metrics:                server.Options{BindAddress: metricsAddr},
		LeaderElection:         enableLeaderElection,
		LeaderElectionID:       "secret-detection-operator",
		HealthProbeBindAddress: ":8081",
	})
	if err != nil {
		setupLog.Error(err, "Unable to start manager")
		os.Exit(1)
	}

	if err = (controllers.NewConfigMapReconciler(mgr.GetClient(), mgr.GetScheme())).
		SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "Unable to create controller", "controller", "ConfigMap")
		os.Exit(1)
	}

	setupLog.Info("Starting manager", "version", version)
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		setupLog.Error(err, "Problem running manager")
		os.Exit(1)
	}
}
