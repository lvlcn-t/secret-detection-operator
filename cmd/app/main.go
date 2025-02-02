package main

import (
	"context"
	"fmt"
	"os"

	"github.com/lvlcn-t/secret-detection-operator/scanners"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// ConfigMapReconciler scans [corev1.ConfigMap]s for secret values and migrates them
// to a corresponding [corev1.Secret]
type ConfigMapReconciler struct {
	client.Client
	scheme  *runtime.Scheme
	scanner scanners.Secret
}

// Reconcile implements the controller-runtime Reconciler interface.
func (r *ConfigMapReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := ctrl.LoggerFrom(ctx)

	// Get the ConfigMap.
	var cm corev1.ConfigMap
	if err := r.Get(ctx, req.NamespacedName, &cm); err != nil {
		// The ConfigMap may have been deleted.
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	// Collect any keys that have secret values.
	secretData := make(map[string][]byte)
	updated := false
	for key, value := range cm.Data {
		if r.scanner.IsSecret(value) {
			// We consider this value “secret”.
			secretData[key] = []byte(value)
			// Remove the key from the ConfigMap.
			delete(cm.Data, key)
			updated = true
			log.Info("Detected secret value in ConfigMap", "ConfigMap", req.NamespacedName, "key", key)
		}
	}

	// If any secret keys were found, update the ConfigMap and then ensure the
	// corresponding Secret contains these key/values.
	if updated {
		if err := r.Update(ctx, &cm); err != nil {
			log.Error(err, "failed to update ConfigMap after removing secret keys")
			return ctrl.Result{}, err
		}
		// Try to get a Secret with the same namespaced name.
		var sec corev1.Secret
		if err := r.Get(ctx, req.NamespacedName, &sec); err != nil {
			// Not found: create a new Secret.
			sec = corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      req.Name,
					Namespace: req.Namespace,
				},
				Data: secretData,
				// For our purposes we use Opaque.
				Type: corev1.SecretTypeOpaque,
			}
			if err := r.Create(ctx, &sec); err != nil {
				log.Error(err, "failed to create Secret")
				return ctrl.Result{}, err
			}
		} else {
			// Merge in the new secretData into the existing Secret.
			if sec.Data == nil {
				sec.Data = make(map[string][]byte)
			}
			for k, v := range secretData {
				sec.Data[k] = v
			}
			if err := r.Update(ctx, &sec); err != nil {
				log.Error(err, "failed to update Secret")
				return ctrl.Result{}, err
			}
		}
	}

	return ctrl.Result{}, nil
}

// SetupWithManager registers this reconciler with the manager.
func (r *ConfigMapReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&corev1.ConfigMap{}).
		Complete(r)
}

// SecretReconciler scans [corev1.Secret]s for non-secret values and migrates them to a
// corresponding [corev1.ConfigMap].
type SecretReconciler struct {
	client.Client
	scheme  *runtime.Scheme
	scanner scanners.Secret
}

// Reconcile implements the controller-runtime Reconciler interface.
func (r *SecretReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := ctrl.LoggerFrom(ctx)

	// Get the Secret.
	var sec corev1.Secret
	if err := r.Get(ctx, req.NamespacedName, &sec); err != nil {
		// The Secret may have been deleted.
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	nonSecretData := make(map[string]string)
	updated := false
	for key, value := range sec.Data {
		strVal := string(value)
		if !r.scanner.IsSecret(strVal) {
			// This value appears non-secret.
			nonSecretData[key] = strVal
			delete(sec.Data, key)
			updated = true
			log.Info("Detected non-secret value in Secret", "Secret", req.NamespacedName, "key", key)
		}
	}

	// If any keys were moved out, update the Secret and then ensure the
	// corresponding ConfigMap contains them.
	if updated {
		if err := r.Update(ctx, &sec); err != nil {
			log.Error(err, "failed to update Secret after removing non-secret keys")
			return ctrl.Result{}, err
		}

		// Try to get a ConfigMap with the same namespaced name.
		var cm corev1.ConfigMap
		if err := r.Get(ctx, req.NamespacedName, &cm); err != nil {
			// Not found: create a new ConfigMap.
			cm = corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      req.Name,
					Namespace: req.Namespace,
				},
				Data: nonSecretData,
			}
			if err := r.Create(ctx, &cm); err != nil {
				log.Error(err, "failed to create ConfigMap")
				return ctrl.Result{}, err
			}
		} else {
			// Merge in the new non-secret data.
			if cm.Data == nil {
				cm.Data = make(map[string]string)
			}
			for k, v := range nonSecretData {
				cm.Data[k] = v
			}
			if err := r.Update(ctx, &cm); err != nil {
				log.Error(err, "failed to update ConfigMap")
				return ctrl.Result{}, err
			}
		}
	}

	return ctrl.Result{}, nil
}

// SetupWithManager registers this reconciler with the manager.
func (r *SecretReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&corev1.Secret{}).
		Complete(r)
}

var scheme = runtime.NewScheme()

func init() {
	err := corev1.AddToScheme(scheme)
	if err != nil {
		panic(fmt.Errorf("unable to add corev1 scheme: %w", err))
	}
}

func main() {
	// Create a new manager to provide shared dependencies and start the controllers.
	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme: scheme,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "unable to start manager: %v\n", err)
		os.Exit(1)
	}

	scanner, err := scanners.Gitleaks()
	if err != nil {
		fmt.Fprintf(os.Stderr, "unable to create scanner: %v\n", err)
		os.Exit(1)
	}

	// Set up the ConfigMap controller.
	cmRec := &ConfigMapReconciler{
		Client:  mgr.GetClient(),
		scheme:  mgr.GetScheme(),
		scanner: scanner,
	}
	if err = cmRec.SetupWithManager(mgr); err != nil {
		fmt.Fprintf(os.Stderr, "unable to create ConfigMap controller: %v\n", err)
		os.Exit(1)
	}

	// Set up the Secret controller.
	secRec := &SecretReconciler{
		Client:  mgr.GetClient(),
		scheme:  mgr.GetScheme(),
		scanner: scanner,
	}
	if err = secRec.SetupWithManager(mgr); err != nil {
		fmt.Fprintf(os.Stderr, "unable to create Secret controller: %v\n", err)
		os.Exit(1)
	}

	// Start the manager.
	fmt.Println("starting manager")
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		fmt.Fprintf(os.Stderr, "problem running manager: %v\n", err)
		os.Exit(1)
	}
}
