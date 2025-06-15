package main

import (
	"flag"
	"os"

	"github.com/lvlcn-t/secret-detection-operator/apis/v1alpha1"
	"github.com/lvlcn-t/secret-detection-operator/config"
	"github.com/lvlcn-t/secret-detection-operator/controllers"
	"go.uber.org/zap/zapcore"
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

const (
	metricsAddr    = ":9090"
	healthAddr     = ":8080"
	leaderElection = false
)

func main() {
	var configPath string
	flag.StringVar(&configPath, "config", "", "Path to the configuration file")

	opts := zap.Options{
		Level: zapcore.DebugLevel,
	}
	opts.BindFlags(flag.CommandLine)
	flag.Parse()

	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&opts)))
	setupLog := ctrl.Log.WithName("setup")

	cfg, err := config.Load(configPath)
	if err != nil {
		setupLog.Error(err, "Unable to load configuration")
		os.Exit(1)
	}
	setupLog.Info("Loaded configuration", "config", cfg)

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme:                 scheme,
		Metrics:                server.Options{BindAddress: metricsAddr},
		HealthProbeBindAddress: healthAddr,
		LeaderElection:         leaderElection,
		LeaderElectionID:       config.AppURL,
	})
	if err != nil {
		setupLog.Error(err, "Unable to start manager")
		os.Exit(1)
	}

	ctx := ctrl.SetupSignalHandler()
	if err = cfg.Validate(ctx, mgr.GetClient()); err != nil {
		setupLog.Error(err, "Invalid configuration")
		os.Exit(1)
	}
	setupLog.Info("Configuration is valid")

	controller := controllers.NewConfigMapReconciler(mgr.GetClient(), mgr.GetScheme(), cfg)
	if err = controller.SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "Unable to create controller", "controller", "ConfigMap")
		os.Exit(1)
	}

	setupLog.Info("Starting manager", "version", version)
	if err := mgr.Start(ctx); err != nil {
		setupLog.Error(err, "Problem running manager")
		os.Exit(1)
	}
}
