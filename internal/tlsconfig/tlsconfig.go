package tlsconfig

import (
	"context"
	"crypto/tls"
	"fmt"

	configv1 "github.com/openshift/api/config/v1"
	configclientset "github.com/openshift/client-go/config/clientset/versioned"
	libgocrypto "github.com/openshift/library-go/pkg/crypto"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"
	ctrl "sigs.k8s.io/controller-runtime"
)

var log = ctrl.Log.WithName("tlsconfig")

// FetchTLSConfig reads the TLS profile from the cluster's APIServer resource
// and returns a *tls.Config configured with the appropriate MinVersion and
// CipherSuites. If the APIServer resource is not available or has no TLS
// profile set, the default Intermediate profile is used.
func FetchTLSConfig(ctx context.Context, restConfig *rest.Config) (*tls.Config, error) {
	configClient, err := configclientset.NewForConfig(restConfig)
	if err != nil {
		return nil, fmt.Errorf("creating config client: %w", err)
	}

	apiserver, err := configClient.ConfigV1().APIServers().Get(ctx, "cluster", metav1.GetOptions{})
	if err != nil {
		log.Error(err, "unable to get APIServer config, using default Intermediate profile")
		return buildTLSConfigFromProfile(&configv1.TLSSecurityProfile{
			Type: configv1.TLSProfileIntermediateType,
		})
	}

	if !shouldHonorClusterTLSProfile(apiserver.Spec.TLSAdherence) {
		log.Info("TLS adherence does not require honoring cluster profile, using default Intermediate",
			"adherence", apiserver.Spec.TLSAdherence)
		return buildTLSConfigFromProfile(&configv1.TLSSecurityProfile{
			Type: configv1.TLSProfileIntermediateType,
		})
	}

	profile := apiserver.Spec.TLSSecurityProfile
	if profile == nil {
		profile = &configv1.TLSSecurityProfile{
			Type: configv1.TLSProfileIntermediateType,
		}
	}

	log.Info("resolved TLS profile from APIServer", "type", profile.Type)
	return buildTLSConfigFromProfile(profile)
}

func buildTLSConfigFromProfile(profile *configv1.TLSSecurityProfile) (*tls.Config, error) {
	profileSpec, err := getProfileSpec(profile)
	if err != nil {
		return nil, err
	}

	minVersion, err := libgocrypto.TLSVersion(string(profileSpec.MinTLSVersion))
	if err != nil {
		return nil, fmt.Errorf("invalid MinTLSVersion %q: %w", profileSpec.MinTLSVersion, err)
	}

	config := &tls.Config{
		MinVersion: minVersion,
	}

	// TLS 1.3 cipher suites are fixed by the Go runtime and cannot be configured.
	// Only set CipherSuites for TLS 1.2 and below.
	if minVersion < tls.VersionTLS13 {
		cipherSuites, err := parseCipherSuites(profileSpec.Ciphers)
		if err != nil {
			return nil, err
		}
		config.CipherSuites = cipherSuites
	}

	return config, nil
}

func getProfileSpec(profile *configv1.TLSSecurityProfile) (*configv1.TLSProfileSpec, error) {
	switch profile.Type {
	case configv1.TLSProfileOldType,
		configv1.TLSProfileIntermediateType,
		configv1.TLSProfileModernType:
		spec, ok := configv1.TLSProfiles[profile.Type]
		if !ok {
			return nil, fmt.Errorf("unknown built-in TLS profile type: %s", profile.Type)
		}
		return spec, nil
	case configv1.TLSProfileCustomType:
		if profile.Custom == nil {
			return nil, fmt.Errorf("custom TLS profile specified but Custom field is nil")
		}
		return &profile.Custom.TLSProfileSpec, nil
	default:
		return configv1.TLSProfiles[configv1.TLSProfileIntermediateType], nil
	}
}

// FetchTLSCLIArgs reads the TLS profile from the cluster's APIServer resource
// and returns the MinTLSVersion string and IANA cipher suite names suitable for
// passing as --tls-min-version and --tls-cipher-suites CLI flags.
func FetchTLSCLIArgs(ctx context.Context, restConfig *rest.Config) (minVersion string, cipherSuites []string, err error) {
	configClient, err := configclientset.NewForConfig(restConfig)
	if err != nil {
		return "", nil, fmt.Errorf("creating config client: %w", err)
	}

	apiserver, err := configClient.ConfigV1().APIServers().Get(ctx, "cluster", metav1.GetOptions{})
	if err != nil {
		log.Error(err, "unable to get APIServer config, using default Intermediate profile")
		spec := configv1.TLSProfiles[configv1.TLSProfileIntermediateType]
		return string(spec.MinTLSVersion), libgocrypto.OpenSSLToIANACipherSuites(spec.Ciphers), nil
	}

	if !shouldHonorClusterTLSProfile(apiserver.Spec.TLSAdherence) {
		log.Info("TLS adherence does not require honoring cluster profile, using default Intermediate",
			"adherence", apiserver.Spec.TLSAdherence)
		spec := configv1.TLSProfiles[configv1.TLSProfileIntermediateType]
		return string(spec.MinTLSVersion), libgocrypto.OpenSSLToIANACipherSuites(spec.Ciphers), nil
	}

	profile := apiserver.Spec.TLSSecurityProfile
	if profile == nil {
		profile = &configv1.TLSSecurityProfile{
			Type: configv1.TLSProfileIntermediateType,
		}
	}

	spec, err := getProfileSpec(profile)
	if err != nil {
		return "", nil, err
	}

	return string(spec.MinTLSVersion), libgocrypto.OpenSSLToIANACipherSuites(spec.Ciphers), nil
}

func parseCipherSuites(opensslNames []string) ([]uint16, error) {
	// OpenShift TLS profiles use OpenSSL-style cipher names (e.g., "ECDHE-RSA-AES128-GCM-SHA256")
	// but library-go's CipherSuite() expects IANA names (e.g., "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256").
	// Convert first using library-go's OpenSSLToIANACipherSuites().
	ianaNames := libgocrypto.OpenSSLToIANACipherSuites(opensslNames)

	var suites []uint16
	for _, name := range ianaNames {
		suite, err := libgocrypto.CipherSuite(name)
		if err != nil {
			log.Info("skipping unsupported cipher suite", "cipher", name)
			continue
		}
		suites = append(suites, suite)
	}
	if len(suites) == 0 && len(opensslNames) > 0 {
		return nil, fmt.Errorf("none of the specified cipher suites are supported: %v", opensslNames)
	}
	return suites, nil
}

// shouldHonorClusterTLSProfile returns true when the component must honor the
// cluster-wide TLS profile. Mirrors library-go's crypto.ShouldHonorClusterTLSProfile
// which cannot be imported due to library-go k8s version requirements.
// Unknown values return true for forward compatibility.
func shouldHonorClusterTLSProfile(adherence configv1.TLSAdherencePolicy) bool {
	switch adherence {
	case "", configv1.TLSAdherencePolicyLegacyAdheringComponentsOnly:
		return false
	default:
		return true
	}
}
