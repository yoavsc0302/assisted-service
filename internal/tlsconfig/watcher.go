package tlsconfig

import (
	"context"
	"fmt"

	configclientset "github.com/openshift/client-go/config/clientset/versioned"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/rest"
)

// WatchForTLSProfileChanges watches the APIServer resource for TLS profile
// changes. When a change is detected, it calls the provided onChanged callback.
// Typical usage: pass a context.CancelFunc to trigger graceful shutdown, or a
// function that signals a channel. The process is expected to be restarted
// by its Deployment controller, at which point it will read the new TLS profile.
func WatchForTLSProfileChanges(ctx context.Context, restConfig *rest.Config, onChanged func()) error {
	configClient, err := configclientset.NewForConfig(restConfig)
	if err != nil {
		return fmt.Errorf("creating config client for TLS watcher: %w", err)
	}

	go watchAPIServer(ctx, configClient, onChanged)
	return nil
}

func watchAPIServer(ctx context.Context, configClient configclientset.Interface, onChanged func()) {
	w, err := configClient.ConfigV1().APIServers().Watch(ctx, metav1.ListOptions{
		FieldSelector: "metadata.name=cluster",
	})
	if err != nil {
		log.Error(err, "failed to watch APIServer, TLS profile changes will not be monitored")
		return
	}
	defer w.Stop()

	for event := range w.ResultChan() {
		if event.Type != watch.Modified {
			continue
		}
		log.Info("APIServer TLS configuration changed, shutting down to reload")
		onChanged()
		return
	}

	if ctx.Err() == nil {
		log.Error(nil, "watch on APIServer exited unexpectedly, TLS profile changes will not be monitored")
	}
}
