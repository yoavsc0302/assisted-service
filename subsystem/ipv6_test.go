package subsystem

import (
	"context"
	"fmt"
	"time"

	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/openshift/assisted-service/client/installer"
	"github.com/openshift/assisted-service/internal/host/hostutil"
	"github.com/openshift/assisted-service/models"
	"github.com/openshift/assisted-service/subsystem/utils_test"
)

var _ = Describe("IPv6 installation", func() {
	var (
		ctx         = context.Background()
		cluster     *models.Cluster
		infraEnvID  *strfmt.UUID
		clusterCIDR = "2002:db8::/53"
		serviceCIDR = "2003:db8::/112"
		clusterID   strfmt.UUID
	)

	BeforeEach(func() {
		registerClusterReply, err := utils_test.TestContext.UserBMClient.Installer.V2RegisterCluster(ctx, &installer.V2RegisterClusterParams{
			NewClusterParams: &models.ClusterCreateParams{
				BaseDNSDomain:     "example.com",
				ClusterNetworks:   []*models.ClusterNetwork{{Cidr: models.Subnet(clusterCIDR), HostPrefix: 64}},
				ServiceNetworks:   []*models.ServiceNetwork{{Cidr: models.Subnet(serviceCIDR)}},
				Name:              swag.String("test-cluster"),
				OpenshiftVersion:  swag.String(openshiftVersion),
				PullSecret:        swag.String(pullSecret),
				SSHPublicKey:      utils_test.SshPublicKey,
				VipDhcpAllocation: swag.Bool(false),
				NetworkType:       swag.String(models.ClusterNetworkTypeOVNKubernetes),
			},
		})
		Expect(err).NotTo(HaveOccurred())
		cluster = registerClusterReply.GetPayload()
		clusterID = *cluster.ID
		log.Infof("Register cluster %s", cluster.ID.String())
		infraEnvID = registerInfraEnv(&clusterID, models.ImageTypeMinimalIso).ID
	})
	It("install_cluster IPv6 happy flow", func() {
		_ = registerHostsAndSetRolesV6(clusterID, *infraEnvID, 5)
		clusterReply, getErr := utils_test.TestContext.UserBMClient.Installer.V2GetCluster(ctx, &installer.V2GetClusterParams{
			ClusterID: clusterID,
		})
		Expect(getErr).ToNot(HaveOccurred())
		Expect(len(clusterReply.Payload.HostNetworks)).To(Equal(1))
		Expect(clusterReply.Payload.HostNetworks[0].Cidr).To(Equal("1001:db8::/120"))
		By("Installing cluster till finalize")
		c := installCluster(clusterID)
		Expect(swag.StringValue(c.Status)).Should(Equal("installing"))
		Expect(swag.StringValue(c.StatusInfo)).Should(Equal("Installation in progress"))
		Expect(len(c.Hosts)).Should(Equal(5))
		for _, host := range c.Hosts {
			Expect(swag.StringValue(host.Status)).Should(Equal("installing"))
		}

		for _, host := range c.Hosts {
			utils_test.TestContext.UpdateProgress(*host.ID, host.InfraEnvID, models.HostStageDone)
		}

		waitForClusterState(ctx, clusterID, models.ClusterStatusFinalizing, utils_test.DefaultWaitForClusterStateTimeout, utils_test.ClusterFinalizingStateInfo)
		By("Completing installation installation")
		completeInstallationAndVerify(ctx, utils_test.TestContext.AgentBMClient, clusterID, true)
	})
})

func registerHostsAndSetRolesV6(clusterID, infraEnvID strfmt.UUID, numHosts int) []*models.Host {
	ctx := context.Background()
	hosts := make([]*models.Host, 0)
	ips := hostutil.GenerateIPv6Addresses(numHosts, utils_test.DefaultCIDRv6)
	for i := 0; i < numHosts; i++ {
		hostname := fmt.Sprintf("h%d", i)
		host := &utils_test.TestContext.RegisterHost(infraEnvID).Host
		utils_test.ValidHwInfoV6.Interfaces[0].IPV6Addresses = []string{ips[i]}
		utils_test.ValidHwInfoV6.Interfaces[0].MacAddress = "e6:53:3d:a7:77:b4"
		utils_test.TestContext.GenerateEssentialHostStepsWithInventory(ctx, host, hostname, utils_test.ValidHwInfoV6)
		var role models.HostRole
		if i < 3 {
			role = models.HostRoleMaster
		} else {
			role = models.HostRoleWorker
		}
		_, err := utils_test.TestContext.UserBMClient.Installer.V2UpdateHost(ctx, &installer.V2UpdateHostParams{
			HostUpdateParams: &models.HostUpdateParams{
				HostRole: swag.String(string(role)),
			},
			HostID:     *host.ID,
			InfraEnvID: infraEnvID,
		})
		Expect(err).NotTo(HaveOccurred())
		hosts = append(hosts, host)
	}
	generateFullMeshConnectivity(ctx, ips[0], hosts...)
	apiVip := "1001:db8::64"
	ingressVip := "1001:db8::65"
	_, err := utils_test.TestContext.UserBMClient.Installer.V2UpdateCluster(ctx, &installer.V2UpdateClusterParams{
		ClusterUpdateParams: &models.V2ClusterUpdateParams{
			VipDhcpAllocation: swag.Bool(false),
			APIVips:           []*models.APIVip{{IP: models.IP(apiVip), ClusterID: clusterID}},
			IngressVips:       []*models.IngressVip{{IP: models.IP(ingressVip), ClusterID: clusterID}},
		},
		ClusterID: clusterID,
	})
	Expect(err).NotTo(HaveOccurred())
	if len(hosts) > 0 {
		utils_test.TestContext.GenerateVerifyVipsPostStepReply(ctx, hosts[0], []string{apiVip}, []string{ingressVip}, models.VipVerificationSucceeded)
	}
	waitForClusterState(ctx, clusterID, models.ClusterStatusReady, 60*time.Second, utils_test.ClusterReadyStateInfo)

	return hosts
}
