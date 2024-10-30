// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"
	"encoding/json"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/validate"
)

// HostValidationID host validation id
//
// swagger:model host-validation-id
type HostValidationID string

func NewHostValidationID(value HostValidationID) *HostValidationID {
	return &value
}

// Pointer returns a pointer to a freshly-allocated HostValidationID.
func (m HostValidationID) Pointer() *HostValidationID {
	return &m
}

const (

	// HostValidationIDConnected captures enum value "connected"
	HostValidationIDConnected HostValidationID = "connected"

	// HostValidationIDMediaConnected captures enum value "media-connected"
	HostValidationIDMediaConnected HostValidationID = "media-connected"

	// HostValidationIDHasInventory captures enum value "has-inventory"
	HostValidationIDHasInventory HostValidationID = "has-inventory"

	// HostValidationIDHasMinCPUCores captures enum value "has-min-cpu-cores"
	HostValidationIDHasMinCPUCores HostValidationID = "has-min-cpu-cores"

	// HostValidationIDHasMinValidDisks captures enum value "has-min-valid-disks"
	HostValidationIDHasMinValidDisks HostValidationID = "has-min-valid-disks"

	// HostValidationIDHasMinMemory captures enum value "has-min-memory"
	HostValidationIDHasMinMemory HostValidationID = "has-min-memory"

	// HostValidationIDMachineCidrDefined captures enum value "machine-cidr-defined"
	HostValidationIDMachineCidrDefined HostValidationID = "machine-cidr-defined"

	// HostValidationIDHasCPUCoresForRole captures enum value "has-cpu-cores-for-role"
	HostValidationIDHasCPUCoresForRole HostValidationID = "has-cpu-cores-for-role"

	// HostValidationIDHasMemoryForRole captures enum value "has-memory-for-role"
	HostValidationIDHasMemoryForRole HostValidationID = "has-memory-for-role"

	// HostValidationIDHostnameUnique captures enum value "hostname-unique"
	HostValidationIDHostnameUnique HostValidationID = "hostname-unique"

	// HostValidationIDHostnameValid captures enum value "hostname-valid"
	HostValidationIDHostnameValid HostValidationID = "hostname-valid"

	// HostValidationIDBelongsToMachineCidr captures enum value "belongs-to-machine-cidr"
	HostValidationIDBelongsToMachineCidr HostValidationID = "belongs-to-machine-cidr"

	// HostValidationIDIgnitionDownloadable captures enum value "ignition-downloadable"
	HostValidationIDIgnitionDownloadable HostValidationID = "ignition-downloadable"

	// HostValidationIDBelongsToMajorityGroup captures enum value "belongs-to-majority-group"
	HostValidationIDBelongsToMajorityGroup HostValidationID = "belongs-to-majority-group"

	// HostValidationIDValidPlatformNetworkSettings captures enum value "valid-platform-network-settings"
	HostValidationIDValidPlatformNetworkSettings HostValidationID = "valid-platform-network-settings"

	// HostValidationIDNtpSynced captures enum value "ntp-synced"
	HostValidationIDNtpSynced HostValidationID = "ntp-synced"

	// HostValidationIDTimeSyncedBetweenHostAndService captures enum value "time-synced-between-host-and-service"
	HostValidationIDTimeSyncedBetweenHostAndService HostValidationID = "time-synced-between-host-and-service"

	// HostValidationIDContainerImagesAvailable captures enum value "container-images-available"
	HostValidationIDContainerImagesAvailable HostValidationID = "container-images-available"

	// HostValidationIDLsoRequirementsSatisfied captures enum value "lso-requirements-satisfied"
	HostValidationIDLsoRequirementsSatisfied HostValidationID = "lso-requirements-satisfied"

	// HostValidationIDOcsRequirementsSatisfied captures enum value "ocs-requirements-satisfied"
	HostValidationIDOcsRequirementsSatisfied HostValidationID = "ocs-requirements-satisfied"

	// HostValidationIDOdfRequirementsSatisfied captures enum value "odf-requirements-satisfied"
	HostValidationIDOdfRequirementsSatisfied HostValidationID = "odf-requirements-satisfied"

	// HostValidationIDLvmRequirementsSatisfied captures enum value "lvm-requirements-satisfied"
	HostValidationIDLvmRequirementsSatisfied HostValidationID = "lvm-requirements-satisfied"

	// HostValidationIDMceRequirementsSatisfied captures enum value "mce-requirements-satisfied"
	HostValidationIDMceRequirementsSatisfied HostValidationID = "mce-requirements-satisfied"

	// HostValidationIDMtvRequirementsSatisfied captures enum value "mtv-requirements-satisfied"
	HostValidationIDMtvRequirementsSatisfied HostValidationID = "mtv-requirements-satisfied"

	// HostValidationIDSufficientInstallationDiskSpeed captures enum value "sufficient-installation-disk-speed"
	HostValidationIDSufficientInstallationDiskSpeed HostValidationID = "sufficient-installation-disk-speed"

	// HostValidationIDCnvRequirementsSatisfied captures enum value "cnv-requirements-satisfied"
	HostValidationIDCnvRequirementsSatisfied HostValidationID = "cnv-requirements-satisfied"

	// HostValidationIDSufficientNetworkLatencyRequirementForRole captures enum value "sufficient-network-latency-requirement-for-role"
	HostValidationIDSufficientNetworkLatencyRequirementForRole HostValidationID = "sufficient-network-latency-requirement-for-role"

	// HostValidationIDSufficientPacketLossRequirementForRole captures enum value "sufficient-packet-loss-requirement-for-role"
	HostValidationIDSufficientPacketLossRequirementForRole HostValidationID = "sufficient-packet-loss-requirement-for-role"

	// HostValidationIDHasDefaultRoute captures enum value "has-default-route"
	HostValidationIDHasDefaultRoute HostValidationID = "has-default-route"

	// HostValidationIDAPIDomainNameResolvedCorrectly captures enum value "api-domain-name-resolved-correctly"
	HostValidationIDAPIDomainNameResolvedCorrectly HostValidationID = "api-domain-name-resolved-correctly"

	// HostValidationIDAPIIntDomainNameResolvedCorrectly captures enum value "api-int-domain-name-resolved-correctly"
	HostValidationIDAPIIntDomainNameResolvedCorrectly HostValidationID = "api-int-domain-name-resolved-correctly"

	// HostValidationIDAppsDomainNameResolvedCorrectly captures enum value "apps-domain-name-resolved-correctly"
	HostValidationIDAppsDomainNameResolvedCorrectly HostValidationID = "apps-domain-name-resolved-correctly"

	// HostValidationIDReleaseDomainNameResolvedCorrectly captures enum value "release-domain-name-resolved-correctly"
	HostValidationIDReleaseDomainNameResolvedCorrectly HostValidationID = "release-domain-name-resolved-correctly"

	// HostValidationIDCompatibleWithClusterPlatform captures enum value "compatible-with-cluster-platform"
	HostValidationIDCompatibleWithClusterPlatform HostValidationID = "compatible-with-cluster-platform"

	// HostValidationIDDNSWildcardNotConfigured captures enum value "dns-wildcard-not-configured"
	HostValidationIDDNSWildcardNotConfigured HostValidationID = "dns-wildcard-not-configured"

	// HostValidationIDDiskEncryptionRequirementsSatisfied captures enum value "disk-encryption-requirements-satisfied"
	HostValidationIDDiskEncryptionRequirementsSatisfied HostValidationID = "disk-encryption-requirements-satisfied"

	// HostValidationIDNonOverlappingSubnets captures enum value "non-overlapping-subnets"
	HostValidationIDNonOverlappingSubnets HostValidationID = "non-overlapping-subnets"

	// HostValidationIDVsphereDiskUUIDEnabled captures enum value "vsphere-disk-uuid-enabled"
	HostValidationIDVsphereDiskUUIDEnabled HostValidationID = "vsphere-disk-uuid-enabled"

	// HostValidationIDCompatibleAgent captures enum value "compatible-agent"
	HostValidationIDCompatibleAgent HostValidationID = "compatible-agent"

	// HostValidationIDNoSkipInstallationDisk captures enum value "no-skip-installation-disk"
	HostValidationIDNoSkipInstallationDisk HostValidationID = "no-skip-installation-disk"

	// HostValidationIDNoSkipMissingDisk captures enum value "no-skip-missing-disk"
	HostValidationIDNoSkipMissingDisk HostValidationID = "no-skip-missing-disk"

	// HostValidationIDNoIPCollisionsInNetwork captures enum value "no-ip-collisions-in-network"
	HostValidationIDNoIPCollisionsInNetwork HostValidationID = "no-ip-collisions-in-network"
)

// for schema
var hostValidationIdEnum []interface{}

func init() {
	var res []HostValidationID
	if err := json.Unmarshal([]byte(`["connected","media-connected","has-inventory","has-min-cpu-cores","has-min-valid-disks","has-min-memory","machine-cidr-defined","has-cpu-cores-for-role","has-memory-for-role","hostname-unique","hostname-valid","belongs-to-machine-cidr","ignition-downloadable","belongs-to-majority-group","valid-platform-network-settings","ntp-synced","time-synced-between-host-and-service","container-images-available","lso-requirements-satisfied","ocs-requirements-satisfied","odf-requirements-satisfied","lvm-requirements-satisfied","mce-requirements-satisfied","mtv-requirements-satisfied","sufficient-installation-disk-speed","cnv-requirements-satisfied","sufficient-network-latency-requirement-for-role","sufficient-packet-loss-requirement-for-role","has-default-route","api-domain-name-resolved-correctly","api-int-domain-name-resolved-correctly","apps-domain-name-resolved-correctly","release-domain-name-resolved-correctly","compatible-with-cluster-platform","dns-wildcard-not-configured","disk-encryption-requirements-satisfied","non-overlapping-subnets","vsphere-disk-uuid-enabled","compatible-agent","no-skip-installation-disk","no-skip-missing-disk","no-ip-collisions-in-network"]`), &res); err != nil {
		panic(err)
	}
	for _, v := range res {
		hostValidationIdEnum = append(hostValidationIdEnum, v)
	}
}

func (m HostValidationID) validateHostValidationIDEnum(path, location string, value HostValidationID) error {
	if err := validate.EnumCase(path, location, value, hostValidationIdEnum, true); err != nil {
		return err
	}
	return nil
}

// Validate validates this host validation id
func (m HostValidationID) Validate(formats strfmt.Registry) error {
	var res []error

	// value enum
	if err := m.validateHostValidationIDEnum("", "body", m); err != nil {
		return err
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

// ContextValidate validates this host validation id based on context it is used
func (m HostValidationID) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}
