package tlsconfig

import (
	"crypto/tls"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	configv1 "github.com/openshift/api/config/v1"
)

var _ = Describe("buildTLSConfigFromProfile", func() {
	It("returns TLS 1.2 config for Intermediate profile", func() {
		profile := &configv1.TLSSecurityProfile{
			Type: configv1.TLSProfileIntermediateType,
		}
		config, err := buildTLSConfigFromProfile(profile)
		Expect(err).NotTo(HaveOccurred())
		Expect(config.MinVersion).To(Equal(uint16(tls.VersionTLS12)))
		Expect(config.CipherSuites).NotTo(BeEmpty())
	})

	It("returns TLS 1.3 config for Modern profile", func() {
		profile := &configv1.TLSSecurityProfile{
			Type: configv1.TLSProfileModernType,
		}
		config, err := buildTLSConfigFromProfile(profile)
		Expect(err).NotTo(HaveOccurred())
		Expect(config.MinVersion).To(Equal(uint16(tls.VersionTLS13)))
		Expect(config.CipherSuites).To(BeNil())
	})

	It("returns TLS 1.0 config for Old profile", func() {
		profile := &configv1.TLSSecurityProfile{
			Type: configv1.TLSProfileOldType,
		}
		config, err := buildTLSConfigFromProfile(profile)
		Expect(err).NotTo(HaveOccurred())
		Expect(config.MinVersion).To(Equal(uint16(tls.VersionTLS10)))
		Expect(config.CipherSuites).NotTo(BeEmpty())
	})

	It("returns config for Custom profile", func() {
		profile := &configv1.TLSSecurityProfile{
			Type: configv1.TLSProfileCustomType,
			Custom: &configv1.CustomTLSProfile{
				TLSProfileSpec: configv1.TLSProfileSpec{
					MinTLSVersion: "VersionTLS12",
					Ciphers:       []string{"ECDHE-RSA-AES128-GCM-SHA256", "ECDHE-RSA-AES256-GCM-SHA384"},
				},
			},
		}
		config, err := buildTLSConfigFromProfile(profile)
		Expect(err).NotTo(HaveOccurred())
		Expect(config.MinVersion).To(Equal(uint16(tls.VersionTLS12)))
		Expect(config.CipherSuites).To(HaveLen(2))
		Expect(config.CipherSuites).To(ContainElement(tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256))
		Expect(config.CipherSuites).To(ContainElement(tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384))
	})

	It("returns error for Custom profile with nil Custom field", func() {
		profile := &configv1.TLSSecurityProfile{
			Type:   configv1.TLSProfileCustomType,
			Custom: nil,
		}
		_, err := buildTLSConfigFromProfile(profile)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("Custom field is nil"))
	})

	It("falls back to Intermediate for unknown profile type", func() {
		profile := &configv1.TLSSecurityProfile{
			Type: configv1.TLSProfileType("Unknown"),
		}
		config, err := buildTLSConfigFromProfile(profile)
		Expect(err).NotTo(HaveOccurred())
		Expect(config.MinVersion).To(Equal(uint16(tls.VersionTLS12)))
	})

	It("skips unsupported cipher suites without error", func() {
		profile := &configv1.TLSSecurityProfile{
			Type: configv1.TLSProfileCustomType,
			Custom: &configv1.CustomTLSProfile{
				TLSProfileSpec: configv1.TLSProfileSpec{
					MinTLSVersion: "VersionTLS12",
					Ciphers:       []string{"ECDHE-RSA-AES128-GCM-SHA256", "FAKE-CIPHER-DOESNT-EXIST"},
				},
			},
		}
		config, err := buildTLSConfigFromProfile(profile)
		Expect(err).NotTo(HaveOccurred())
		Expect(config.CipherSuites).To(HaveLen(1))
		Expect(config.CipherSuites).To(ContainElement(tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256))
	})

	It("returns error when all cipher suites are unsupported", func() {
		profile := &configv1.TLSSecurityProfile{
			Type: configv1.TLSProfileCustomType,
			Custom: &configv1.CustomTLSProfile{
				TLSProfileSpec: configv1.TLSProfileSpec{
					MinTLSVersion: "VersionTLS12",
					Ciphers:       []string{"FAKE-CIPHER-1", "FAKE-CIPHER-2"},
				},
			},
		}
		_, err := buildTLSConfigFromProfile(profile)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("none of the specified cipher suites"))
	})

	It("does not set CipherSuites for TLS 1.3", func() {
		profile := &configv1.TLSSecurityProfile{
			Type: configv1.TLSProfileCustomType,
			Custom: &configv1.CustomTLSProfile{
				TLSProfileSpec: configv1.TLSProfileSpec{
					MinTLSVersion: "VersionTLS13",
					Ciphers:       []string{"ECDHE-RSA-AES128-GCM-SHA256"},
				},
			},
		}
		config, err := buildTLSConfigFromProfile(profile)
		Expect(err).NotTo(HaveOccurred())
		Expect(config.MinVersion).To(Equal(uint16(tls.VersionTLS13)))
		Expect(config.CipherSuites).To(BeNil())
	})
})
