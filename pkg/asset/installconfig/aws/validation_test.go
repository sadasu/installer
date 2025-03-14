package aws

import (
	"context"
	"fmt"
	"os"
	"sort"
	"testing"

	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/aws/aws-sdk-go/service/route53"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/utils/ptr"

	"github.com/openshift/installer/pkg/asset/installconfig/aws/mock"
	"github.com/openshift/installer/pkg/ipnet"
	"github.com/openshift/installer/pkg/types"
	"github.com/openshift/installer/pkg/types/aws"
)

var (
	validCIDR             = "10.0.0.0/16"
	validRegion           = "us-east-1"
	validCallerRef        = "valid-caller-reference"
	validDSId             = "valid-delegation-set-id"
	validNameServers      = []string{"valid-name-server"}
	validHostedZoneName   = "valid-private-subnet-a"
	invalidHostedZoneName = "invalid-hosted-zone"
	validDomainName       = "valid-base-domain"
	invalidBaseDomain     = "invalid-base-domain"
	metaName              = "ClusterMetaName"

	publishInternal      = func(ic *types.InstallConfig) { ic.Publish = types.InternalPublishingStrategy }
	clearHostedZone      = func(ic *types.InstallConfig) { ic.AWS.HostedZone = "" }
	invalidateHostedZone = func(ic *types.InstallConfig) { ic.AWS.HostedZone = invalidHostedZoneName }
	invalidateBaseDomain = func(ic *types.InstallConfig) { ic.BaseDomain = invalidBaseDomain }
	clearBaseDomain      = func(ic *types.InstallConfig) { ic.BaseDomain = "" }
	invalidateRegion     = func(ic *types.InstallConfig) { ic.AWS.Region = "us-east4" }
)

type editFunctions []func(ic *types.InstallConfig)

func validInstallConfig() *types.InstallConfig {
	return &types.InstallConfig{
		Networking: &types.Networking{
			MachineNetwork: []types.MachineNetworkEntry{
				{CIDR: *ipnet.MustParseCIDR(validCIDR)},
			},
		},
		BaseDomain: validDomainName,
		Publish:    types.ExternalPublishingStrategy,
		Platform: types.Platform{
			AWS: &aws.Platform{
				Region: "us-east-1",
				VPC: aws.VPC{
					Subnets: []aws.Subnet{
						{ID: "valid-private-subnet-a"},
						{ID: "valid-private-subnet-b"},
						{ID: "valid-private-subnet-c"},
						{ID: "valid-public-subnet-a"},
						{ID: "valid-public-subnet-b"},
						{ID: "valid-public-subnet-c"},
					},
				},
				HostedZone: validHostedZoneName,
			},
		},
		ControlPlane: &types.MachinePool{
			Architecture: types.ArchitectureAMD64,
			Replicas:     ptr.To[int64](3),
			Platform: types.MachinePoolPlatform{
				AWS: &aws.MachinePool{
					Zones: []string{"a", "b", "c"},
				},
			},
		},
		Compute: []types.MachinePool{{
			Name:         types.MachinePoolComputeRoleName,
			Architecture: types.ArchitectureAMD64,
			Replicas:     ptr.To[int64](3),
			Platform: types.MachinePoolPlatform{
				AWS: &aws.MachinePool{
					Zones: []string{"a", "b", "c"},
				},
			},
		}},
		ObjectMeta: metav1.ObjectMeta{
			Name: metaName,
		},
	}
}

// validInstallConfigEdgeSubnets returns install-config for edge compute pool
// for existing VPC (subnets).
func validInstallConfigEdgeSubnets() *types.InstallConfig {
	ic := validInstallConfig()
	edgeSubnets := validEdgeSubnets()
	for subnet := range edgeSubnets {
		ic.Platform.AWS.VPC.Subnets = append(ic.Platform.AWS.VPC.Subnets, aws.Subnet{ID: aws.AWSSubnetID(subnet)})
	}
	ic.Compute = append(ic.Compute, types.MachinePool{
		Name: types.MachinePoolEdgeRoleName,
		Platform: types.MachinePoolPlatform{
			AWS: &aws.MachinePool{},
		},
	})
	return ic
}

func validAvailZones() []string {
	return []string{"a", "b", "c"}
}

func validAvailRegions() []string {
	return []string{"us-east-1", "us-central-1"}
}

func validAvailZonesWithEdge() []string {
	return []string{"a", "b", "c", "edge-a", "edge-b", "edge-c"}
}

func validAvailZonesOnlyEdge() []string {
	return []string{"edge-a", "edge-b", "edge-c"}
}

func validPrivateSubnets() Subnets {
	return Subnets{
		"valid-private-subnet-a": {
			Zone: &Zone{Name: "a"},
			CIDR: "10.0.1.0/24",
		},
		"valid-private-subnet-b": {
			Zone: &Zone{Name: "b"},
			CIDR: "10.0.2.0/24",
		},
		"valid-private-subnet-c": {
			Zone: &Zone{Name: "c"},
			CIDR: "10.0.3.0/24",
		},
	}
}

func validPublicSubnets() Subnets {
	return Subnets{
		"valid-public-subnet-a": {
			Zone: &Zone{Name: "a"},
			CIDR: "10.0.4.0/24",
		},
		"valid-public-subnet-b": {
			Zone: &Zone{Name: "b"},
			CIDR: "10.0.5.0/24",
		},
		"valid-public-subnet-c": {
			Zone: &Zone{Name: "c"},
			CIDR: "10.0.6.0/24",
		},
	}
}

func validEdgeSubnets() Subnets {
	return Subnets{
		"valid-public-subnet-edge-a": {
			Zone: &Zone{Name: "edge-a"},
			CIDR: "10.0.7.0/24",
		},
		"valid-public-subnet-edge-b": {
			Zone: &Zone{Name: "edge-b"},
			CIDR: "10.0.8.0/24",
		},
		"valid-public-subnet-edge-c": {
			Zone: &Zone{Name: "edge-c"},
			CIDR: "10.0.9.0/24",
		},
	}
}

func validServiceEndpoints() []aws.ServiceEndpoint {
	return []aws.ServiceEndpoint{{
		Name: "ec2",
		URL:  "e2e.local",
	}, {
		Name: "s3",
		URL:  "e2e.local",
	}, {
		Name: "iam",
		URL:  "e2e.local",
	}, {
		Name: "elasticloadbalancing",
		URL:  "e2e.local",
	}, {
		Name: "tagging",
		URL:  "e2e.local",
	}, {
		Name: "route53",
		URL:  "e2e.local",
	}, {
		Name: "sts",
		URL:  "e2e.local",
	}}
}

func invalidServiceEndpoint() []aws.ServiceEndpoint {
	return []aws.ServiceEndpoint{{
		Name: "testing",
		URL:  "testing",
	}, {
		Name: "test",
		URL:  "http://testing.non",
	}}
}

func validInstanceTypes() map[string]InstanceType {
	return map[string]InstanceType{
		"t2.small": {
			DefaultVCpus: 1,
			MemInMiB:     2048,
			Arches:       []string{ec2.ArchitectureTypeX8664},
		},
		"m5.large": {
			DefaultVCpus: 2,
			MemInMiB:     8192,
			Arches:       []string{ec2.ArchitectureTypeX8664},
		},
		"m5.xlarge": {
			DefaultVCpus: 4,
			MemInMiB:     16384,
			Arches:       []string{ec2.ArchitectureTypeX8664},
		},
		"m6g.xlarge": {
			DefaultVCpus: 4,
			MemInMiB:     16384,
			Arches:       []string{ec2.ArchitectureTypeArm64},
		},
	}
}

func createBaseDomainHostedZone() route53.HostedZone {
	return route53.HostedZone{
		CallerReference: &validCallerRef,
		Id:              &validDSId,
		Name:            &validDomainName,
	}
}

func createValidHostedZone() route53.GetHostedZoneOutput {
	ptrValidNameServers := []*string{}
	for i := range validNameServers {
		ptrValidNameServers = append(ptrValidNameServers, &validNameServers[i])
	}

	validDelegationSet := route53.DelegationSet{CallerReference: &validCallerRef, Id: &validDSId, NameServers: ptrValidNameServers}
	validHostedZone := route53.HostedZone{CallerReference: &validCallerRef, Id: &validDSId, Name: &validHostedZoneName}
	validVPCs := []*route53.VPC{{VPCId: &validHostedZoneName, VPCRegion: &validRegion}}

	return route53.GetHostedZoneOutput{
		DelegationSet: &validDelegationSet,
		HostedZone:    &validHostedZone,
		VPCs:          validVPCs,
	}
}

func TestValidate(t *testing.T) {
	tests := []struct {
		name           string
		installConfig  *types.InstallConfig
		availZones     []string
		availRegions   []string
		edgeZones      []string
		privateSubnets Subnets
		publicSubnets  Subnets
		edgeSubnets    Subnets
		instanceTypes  map[string]InstanceType
		proxy          string
		publicOnly     string
		expectErr      string
	}{{
		name: "valid no byo",
		installConfig: func() *types.InstallConfig {
			c := validInstallConfig()
			c.Platform.AWS = &aws.Platform{Region: "us-east-1"}
			return c
		}(),
		availZones:   validAvailZones(),
		availRegions: validAvailRegions(),
	}, {
		name: "valid no byo",
		installConfig: func() *types.InstallConfig {
			c := validInstallConfig()
			c.Platform.AWS.VPC.Subnets = nil
			return c
		}(),
		availZones:   validAvailZones(),
		availRegions: validAvailRegions(),
	}, {
		name: "valid no byo",
		installConfig: func() *types.InstallConfig {
			c := validInstallConfig()
			c.Platform.AWS.VPC.Subnets = []aws.Subnet{}
			return c
		}(),
		availZones:   validAvailZones(),
		availRegions: validAvailRegions(),
	}, {
		name:           "valid byo",
		installConfig:  validInstallConfig(),
		availZones:     validAvailZones(),
		privateSubnets: validPrivateSubnets(),
		publicSubnets:  validPublicSubnets(),
		availRegions:   validAvailRegions(),
	}, {
		name:           "valid byo",
		installConfig:  validInstallConfigEdgeSubnets(),
		availZones:     validAvailZones(),
		privateSubnets: validPrivateSubnets(),
		publicSubnets:  validPublicSubnets(),
		edgeSubnets:    validEdgeSubnets(),
		availRegions:   validAvailRegions(),
	}, {
		name: "valid byo",
		installConfig: func() *types.InstallConfig {
			c := validInstallConfig()
			c.Publish = types.InternalPublishingStrategy
			c.Platform.AWS.VPC.Subnets = []aws.Subnet{
				{ID: "valid-private-subnet-a"},
				{ID: "valid-private-subnet-b"},
				{ID: "valid-private-subnet-c"},
			}
			return c
		}(),
		availZones:     validAvailZones(),
		privateSubnets: validPrivateSubnets(),
		availRegions:   validAvailRegions(),
	}, {
		name: "valid instance types",
		installConfig: func() *types.InstallConfig {
			c := validInstallConfig()
			c.Platform.AWS = &aws.Platform{
				Region: "us-east-1",
				DefaultMachinePlatform: &aws.MachinePool{
					InstanceType: "m5.xlarge",
				},
			}
			c.ControlPlane.Platform.AWS.InstanceType = "m5.xlarge"
			c.Compute[0].Platform.AWS.InstanceType = "m5.large"
			return c
		}(),
		availZones:    validAvailZones(),
		instanceTypes: validInstanceTypes(),
		availRegions:  validAvailRegions(),
	}, {
		name: "invalid control plane instance type",
		installConfig: func() *types.InstallConfig {
			c := validInstallConfig()
			c.Platform.AWS = &aws.Platform{Region: "us-east-1"}
			c.ControlPlane.Platform.AWS.InstanceType = "t2.small"
			c.Compute[0].Platform.AWS.InstanceType = "m5.large"
			return c
		}(),
		availZones:    validAvailZones(),
		instanceTypes: validInstanceTypes(),
		availRegions:  validAvailRegions(),
		expectErr:     `^\Q[controlPlane.platform.aws.type: Invalid value: "t2.small": instance type does not meet minimum resource requirements of 4 vCPUs, controlPlane.platform.aws.type: Invalid value: "t2.small": instance type does not meet minimum resource requirements of 16384 MiB Memory]\E$`,
	}, {
		name: "invalid compute instance type",
		installConfig: func() *types.InstallConfig {
			c := validInstallConfig()
			c.Platform.AWS = &aws.Platform{Region: "us-east-1"}
			c.ControlPlane.Platform.AWS.InstanceType = "m5.xlarge"
			c.Compute[0].Platform.AWS.InstanceType = "t2.small"
			return c
		}(),
		availZones:    validAvailZones(),
		instanceTypes: validInstanceTypes(),
		availRegions:  validAvailRegions(),
		expectErr:     `^\Q[compute[0].platform.aws.type: Invalid value: "t2.small": instance type does not meet minimum resource requirements of 2 vCPUs, compute[0].platform.aws.type: Invalid value: "t2.small": instance type does not meet minimum resource requirements of 8192 MiB Memory]\E$`,
	}, {
		name: "undefined compute instance type",
		installConfig: func() *types.InstallConfig {
			c := validInstallConfig()
			c.Platform.AWS = &aws.Platform{Region: "us-east-1"}
			c.Compute[0].Platform.AWS.InstanceType = "m5.dummy"
			return c
		}(),
		availZones:    validAvailZones(),
		instanceTypes: validInstanceTypes(),
		availRegions:  validAvailRegions(),
		expectErr:     `^\Qcompute[0].platform.aws.type: Invalid value: "m5.dummy": instance type m5.dummy not found\E$`,
	}, {
		name: "mismatched instance architecture",
		installConfig: func() *types.InstallConfig {
			c := validInstallConfig()
			c.Platform.AWS = &aws.Platform{
				Region:                 "us-east-1",
				DefaultMachinePlatform: &aws.MachinePool{InstanceType: "m5.xlarge"},
			}
			c.ControlPlane.Architecture = types.ArchitectureARM64
			c.Compute[0].Platform.AWS.InstanceType = "m6g.xlarge"
			c.Compute[0].Architecture = types.ArchitectureAMD64
			return c
		}(),
		availZones:    validAvailZones(),
		instanceTypes: validInstanceTypes(),
		availRegions:  validAvailRegions(),
		expectErr:     `^\[controlPlane.platform.aws.type: Invalid value: "m5.xlarge": instance type supported architectures \[amd64\] do not match specified architecture arm64, compute\[0\].platform.aws.type: Invalid value: "m6g.xlarge": instance type supported architectures \[arm64\] do not match specified architecture amd64\]$`,
	}, {
		name: "mismatched compute pools architectures",
		installConfig: func() *types.InstallConfig {
			c := validInstallConfigEdgeSubnets()
			c.Compute[0].Architecture = types.ArchitectureAMD64
			c.Compute[1].Architecture = types.ArchitectureARM64
			return c
		}(),
		availZones:     validAvailZones(),
		privateSubnets: validPrivateSubnets(),
		publicSubnets:  validPublicSubnets(),
		edgeSubnets:    validEdgeSubnets(),
		availRegions:   validAvailRegions(),
		expectErr:      `^compute\[1\].architecture: Invalid value: "arm64": all compute machine pools must be of the same architecture$`,
	}, {
		name: "valid compute pools architectures",
		installConfig: func() *types.InstallConfig {
			c := validInstallConfigEdgeSubnets()
			c.Compute[0].Architecture = types.ArchitectureAMD64
			return c
		}(),
		availZones:     validAvailZones(),
		privateSubnets: validPrivateSubnets(),
		publicSubnets:  validPublicSubnets(),
		edgeSubnets:    validEdgeSubnets(),
		availRegions:   validAvailRegions(),
	}, {
		name: "mismatched compute pools architectures 2",
		installConfig: func() *types.InstallConfig {
			c := validInstallConfigEdgeSubnets()
			c.Compute[1].Architecture = types.ArchitectureARM64
			return c
		}(),
		availZones:     validAvailZones(),
		privateSubnets: validPrivateSubnets(),
		publicSubnets:  validPublicSubnets(),
		edgeSubnets:    validEdgeSubnets(),
		availRegions:   validAvailRegions(),
		expectErr:      `^compute\[1\].architecture: Invalid value: "arm64": all compute machine pools must be of the same architecture$`,
	}, {
		name: "invalid no private subnets",
		installConfig: func() *types.InstallConfig {
			c := validInstallConfig()
			c.Platform.AWS.VPC.Subnets = []aws.Subnet{
				{ID: "valid-public-subnet-a"},
				{ID: "valid-public-subnet-b"},
				{ID: "valid-public-subnet-c"},
			}
			return c
		}(),
		availZones:    validAvailZones(),
		publicSubnets: validPublicSubnets(),
		expectErr:     `^\[platform\.aws\.vpc\.subnets: Invalid value: \[\]aws\.Subnet\{aws\.Subnet\{ID:\"valid-public-subnet-a\", Roles:\[\]aws\.SubnetRole\(nil\)\}, aws\.Subnet\{ID:\"valid-public-subnet-b\", Roles:\[\]aws\.SubnetRole\(nil\)\}, aws\.Subnet\{ID:\"valid-public-subnet-c\", Roles:\[\]aws\.SubnetRole\(nil\)\}\}: No private subnets found, controlPlane\.platform\.aws\.zones: Invalid value: \[\]string\{\"a\", \"b\", \"c\"\}: No subnets provided for zones \[a b c\], compute\[0\]\.platform\.aws\.zones: Invalid value: \[\]string\{\"a\", \"b\", \"c\"\}: No subnets provided for zones \[a b c\]\]$`,
		availRegions:  validAvailRegions(),
	}, {
		name: "invalid no public subnets",
		installConfig: func() *types.InstallConfig {
			c := validInstallConfig()
			c.Platform.AWS.VPC.Subnets = []aws.Subnet{
				{ID: "valid-private-subnet-a"},
				{ID: "valid-private-subnet-b"},
				{ID: "valid-private-subnet-c"},
			}
			return c
		}(),
		availZones:     validAvailZones(),
		privateSubnets: validPrivateSubnets(),
		expectErr:      `^platform\.aws\.vpc\.subnets: Invalid value: \[\]aws\.Subnet\{aws\.Subnet\{ID:\"valid-private-subnet-a\", Roles:\[\]aws\.SubnetRole\(nil\)\}, aws\.Subnet\{ID:\"valid-private-subnet-b\", Roles:\[\]aws\.SubnetRole\(nil\)\}, aws\.Subnet\{ID:\"valid-private-subnet-c\", Roles:\[\]aws\.SubnetRole\(nil\)\}\}: No public subnet provided for zones \[a b c\]$`,
		availRegions:   validAvailRegions(),
	}, {
		name: "invalid cidr does not belong to machine CIDR",
		installConfig: func() *types.InstallConfig {
			c := validInstallConfig()
			c.Platform.AWS.VPC.Subnets = append(c.Platform.AWS.VPC.Subnets, aws.Subnet{ID: "invalid-cidr-subnet"})
			return c
		}(),
		availZones: func() []string {
			zones := validAvailZones()
			return append(zones, "zone-for-invalid-cidr-subnet")
		}(),
		privateSubnets: validPrivateSubnets(),
		availRegions:   validAvailRegions(),
		publicSubnets: func() Subnets {
			s := validPublicSubnets()
			s["invalid-cidr-subnet"] = Subnet{
				Zone: &Zone{Name: "zone-for-invalid-cidr-subnet"},
				CIDR: "192.168.126.0/24",
			}
			return s
		}(),
		expectErr: `^platform\.aws\.vpc\.subnets\[6\]: Invalid value: \"invalid-cidr-subnet\": subnet's CIDR range start 192\.168\.126\.0 is outside of the specified machine networks$`,
	}, {
		name: "invalid cidr does not belong to machine CIDR",
		installConfig: func() *types.InstallConfig {
			c := validInstallConfig()
			c.Platform.AWS.VPC.Subnets = append(c.Platform.AWS.VPC.Subnets, aws.Subnet{ID: "invalid-private-cidr-subnet"}, aws.Subnet{ID: "invalid-public-cidr-subnet"})
			return c
		}(),
		availZones: func() []string {
			zones := validAvailZones()
			return append(zones, "zone-for-invalid-cidr-subnet")
		}(),
		privateSubnets: func() Subnets {
			s := validPrivateSubnets()
			s["invalid-private-cidr-subnet"] = Subnet{
				Zone: &Zone{Name: "zone-for-invalid-cidr-subnet"},
				CIDR: "192.168.126.0/24",
			}
			return s
		}(),
		publicSubnets: func() Subnets {
			s := validPublicSubnets()
			s["invalid-public-cidr-subnet"] = Subnet{
				Zone: &Zone{Name: "zone-for-invalid-cidr-subnet"},
				CIDR: "192.168.127.0/24",
			}
			return s
		}(),
		expectErr:    `^\[platform\.aws\.vpc\.subnets\[6\]: Invalid value: \"invalid-private-cidr-subnet\": subnet's CIDR range start 192\.168\.126\.0 is outside of the specified machine networks, platform\.aws\.vpc\.subnets\[7\]: Invalid value: \"invalid-public-cidr-subnet\": subnet's CIDR range start 192\.168\.127\.0 is outside of the specified machine networks\]$`,
		availRegions: validAvailRegions(),
	}, {
		name: "invalid missing public subnet in a zone",
		installConfig: func() *types.InstallConfig {
			c := validInstallConfig()
			c.Platform.AWS.VPC.Subnets = append(c.Platform.AWS.VPC.Subnets, aws.Subnet{ID: "no-matching-public-private-zone"})
			return c
		}(),
		availZones:   validAvailZones(),
		availRegions: validAvailRegions(),
		privateSubnets: func() Subnets {
			s := validPrivateSubnets()
			s["no-matching-public-private-zone"] = Subnet{
				Zone: &Zone{Name: "f"},
				CIDR: "10.0.7.0/24",
			}
			return s
		}(),
		publicSubnets: validPublicSubnets(),
		expectErr:     `^platform\.aws\.vpc\.subnets: Invalid value: \[\]aws\.Subnet\{aws\.Subnet\{ID:\"valid-private-subnet-a\", Roles:\[\]aws\.SubnetRole\(nil\)\}, aws\.Subnet\{ID:\"valid-private-subnet-b\", Roles:\[\]aws\.SubnetRole\(nil\)\}, aws\.Subnet\{ID:\"valid-private-subnet-c\", Roles:\[\]aws\.SubnetRole\(nil\)\}, aws\.Subnet\{ID:\"valid-public-subnet-a\", Roles:\[\]aws\.SubnetRole\(nil\)\}, aws\.Subnet\{ID:\"valid-public-subnet-b\", Roles:\[\]aws\.SubnetRole\(nil\)\}, aws\.Subnet\{ID:\"valid-public-subnet-c\", Roles:\[\]aws\.SubnetRole\(nil\)\}, aws\.Subnet\{ID:\"no-matching-public-private-zone\", Roles:\[\]aws\.SubnetRole\(nil\)\}\}: No public subnet provided for zones \[f\]$`,
	}, {
		name: "invalid multiple private in same zone",
		installConfig: func() *types.InstallConfig {
			c := validInstallConfig()
			c.Platform.AWS.VPC.Subnets = append(c.Platform.AWS.VPC.Subnets, aws.Subnet{ID: "valid-private-zone-c-2"})
			return c
		}(),
		availZones:   validAvailZones(),
		availRegions: validAvailRegions(),
		privateSubnets: func() Subnets {
			s := validPrivateSubnets()
			s["valid-private-zone-c-2"] = Subnet{
				Zone: &Zone{Name: "c"},
				CIDR: "10.0.7.0/24",
			}
			return s
		}(),
		publicSubnets: validPublicSubnets(),
		expectErr:     `^platform\.aws\.vpc\.subnets\[6\]: Invalid value: \"valid-private-zone-c-2\": private subnet valid-private-subnet-c is also in zone c$`,
	}, {
		name: "invalid multiple public in same zone",
		installConfig: func() *types.InstallConfig {
			c := validInstallConfig()
			c.Platform.AWS.VPC.Subnets = append(c.Platform.AWS.VPC.Subnets, aws.Subnet{ID: "valid-public-zone-c-2"})
			return c
		}(),
		availZones:     validAvailZones(),
		availRegions:   validAvailRegions(),
		privateSubnets: validPrivateSubnets(),
		publicSubnets: func() Subnets {
			s := validPublicSubnets()
			s["valid-public-zone-c-2"] = Subnet{
				Zone: &Zone{Name: "c"},
				CIDR: "10.0.7.0/24",
			}
			return s
		}(),
		expectErr: `^platform\.aws\.vpc\.subnets\[6\]: Invalid value: \"valid-public-zone-c-2\": public subnet valid-public-subnet-c is also in zone c$`,
	}, {
		name: "invalid multiple public edge in same zone",
		installConfig: func() *types.InstallConfig {
			c := validInstallConfigEdgeSubnets()
			c.Platform.AWS.VPC.Subnets = append(c.Platform.AWS.VPC.Subnets, aws.Subnet{ID: "valid-public-zone-edge-c-2"})
			return c
		}(),
		availZones:     validAvailZonesWithEdge(),
		privateSubnets: validPrivateSubnets(),
		publicSubnets:  validPublicSubnets(),
		availRegions:   validAvailRegions(),
		edgeSubnets: func() Subnets {
			s := validEdgeSubnets()
			s["valid-public-zone-edge-c-2"] = Subnet{
				Zone: &Zone{Name: "edge-c", Type: aws.LocalZoneType},
				CIDR: "10.0.9.0/24",
			}
			return s
		}(),
		expectErr: `^platform\.aws\.vpc\.subnets\[9\]: Invalid value: \"valid-public-zone-edge-c-2\": edge subnet valid-public-subnet-edge-c is also in zone edge-c$`,
	}, {
		name:           "invalid edge pool missing valid subnets",
		installConfig:  validInstallConfigEdgeSubnets(),
		availZones:     validAvailZonesWithEdge(),
		privateSubnets: validPrivateSubnets(),
		publicSubnets:  validPublicSubnets(),
		availRegions:   validAvailRegions(),
		edgeSubnets:    Subnets{},
		expectErr:      `^compute\[1\]\.platform\.aws: Required value: the provided subnets must include valid subnets for the specified edge zones$`,
	}, {
		name: "invalid edge pool missing zones",
		installConfig: func() *types.InstallConfig {
			ic := validInstallConfig()
			ic.Platform.AWS.VPC.Subnets = []aws.Subnet{}
			ic.ControlPlane = &types.MachinePool{}
			edgePool := types.MachinePool{
				Name: types.MachinePoolEdgeRoleName,
				Platform: types.MachinePoolPlatform{
					AWS: &aws.MachinePool{},
				},
			}
			ic.Compute = []types.MachinePool{edgePool}
			return ic
		}(),
		availRegions: validAvailRegions(),
		expectErr:    `^compute\[0\]\.platform\.aws: Required value: zone is required when using edge machine pools$`,
	}, {
		name: "invalid edge pool empty zones",
		installConfig: func() *types.InstallConfig {
			ic := validInstallConfig()
			ic.Platform.AWS.VPC.Subnets = []aws.Subnet{}
			ic.ControlPlane = &types.MachinePool{}
			edgePool := types.MachinePool{
				Name: types.MachinePoolEdgeRoleName,
				Platform: types.MachinePoolPlatform{
					AWS: &aws.MachinePool{
						Zones: []string{},
					},
				},
			}
			ic.Compute = []types.MachinePool{edgePool}
			return ic
		}(),
		availRegions: validAvailRegions(),
		expectErr:    `^compute\[0\]\.platform\.aws: Required value: zone is required when using edge machine pools$`,
	}, {
		name: "invalid edge pool missing platform definition",
		installConfig: func() *types.InstallConfig {
			ic := validInstallConfig()
			ic.Platform.AWS.VPC.Subnets = []aws.Subnet{}
			ic.ControlPlane = &types.MachinePool{}
			edgePool := types.MachinePool{
				Name:     types.MachinePoolEdgeRoleName,
				Platform: types.MachinePoolPlatform{},
			}
			ic.Compute = []types.MachinePool{edgePool}
			return ic
		}(),
		availRegions: validAvailRegions(),
		expectErr:    `^\[compute\[0\]\.platform\.aws: Required value: edge compute pools are only supported on the AWS platform, compute\[0\].platform.aws: Required value: zone is required when using edge machine pools\]$`,
	}, {
		name: "invalid edge pool missing subnets on availability zones",
		installConfig: func() *types.InstallConfig {
			c := validInstallConfigEdgeSubnets()
			c.Platform.AWS.VPC.Subnets = []aws.Subnet{}
			edgeSubnets := validEdgeSubnets()
			for subnet := range edgeSubnets {
				c.Platform.AWS.VPC.Subnets = append(c.Platform.AWS.VPC.Subnets, aws.Subnet{ID: aws.AWSSubnetID(subnet)})
			}
			sort.Slice(c.Platform.AWS.VPC.Subnets, func(i, j int) bool {
				subnets := c.Platform.AWS.VPC.Subnets
				return subnets[i].ID < subnets[j].ID
			})
			return c
		}(),
		availZones:     validAvailZonesOnlyEdge(),
		privateSubnets: Subnets{},
		publicSubnets:  Subnets{},
		edgeSubnets:    validEdgeSubnets(),
		expectErr:      `^\[platform\.aws\.vpc\.subnets: Invalid value: \[\]aws\.Subnet\{aws\.Subnet\{ID:\"valid-public-subnet-edge-a\", Roles:\[\]aws\.SubnetRole\(nil\)\}, aws\.Subnet\{ID:\"valid-public-subnet-edge-b\", Roles:\[\]aws\.SubnetRole\(nil\)\}, aws\.Subnet\{ID:\"valid-public-subnet-edge-c\", Roles:\[\]aws\.SubnetRole\(nil\)\}\}: No private subnets found, controlPlane\.platform\.aws\.zones: Invalid value: \[\]string\{\"a\", \"b\", \"c\"\}: No subnets provided for zones \[a b c\], compute\[0\]\.platform\.aws\.zones: Invalid value: \[\]string\{\"a\", \"b\", \"c\"\}: No subnets provided for zones \[a b c\]\]$`,
		availRegions:   validAvailRegions(),
	}, {
		name: "invalid no subnet for control plane zones",
		installConfig: func() *types.InstallConfig {
			c := validInstallConfig()
			c.ControlPlane.Platform.AWS.Zones = append(c.ControlPlane.Platform.AWS.Zones, "d")
			return c
		}(),
		availZones:     validAvailZones(),
		privateSubnets: validPrivateSubnets(),
		publicSubnets:  validPublicSubnets(),
		availRegions:   validAvailRegions(),
		expectErr:      `^controlPlane\.platform\.aws\.zones: Invalid value: \[\]string{\"a\", \"b\", \"c\", \"d\"}: No subnets provided for zones \[d\]$`,
	}, {
		name: "invalid no subnet for control plane zones",
		installConfig: func() *types.InstallConfig {
			c := validInstallConfig()
			c.ControlPlane.Platform.AWS.Zones = append(c.ControlPlane.Platform.AWS.Zones, "d", "e")
			return c
		}(),
		availZones:     validAvailZones(),
		privateSubnets: validPrivateSubnets(),
		publicSubnets:  validPublicSubnets(),
		availRegions:   validAvailRegions(),
		expectErr:      `^controlPlane\.platform\.aws\.zones: Invalid value: \[\]string{\"a\", \"b\", \"c\", \"d\", \"e\"}: No subnets provided for zones \[d e\]$`,
	}, {
		name: "invalid no subnet for compute[0] zones",
		installConfig: func() *types.InstallConfig {
			c := validInstallConfig()
			c.Compute[0].Platform.AWS.Zones = append(c.ControlPlane.Platform.AWS.Zones, "d")
			return c
		}(),
		availZones:     validAvailZones(),
		privateSubnets: validPrivateSubnets(),
		publicSubnets:  validPublicSubnets(),
		availRegions:   validAvailRegions(),
		expectErr:      `^compute\[0\]\.platform\.aws\.zones: Invalid value: \[\]string{\"a\", \"b\", \"c\", \"d\"}: No subnets provided for zones \[d\]$`,
	}, {
		name: "invalid no subnet for compute zone",
		installConfig: func() *types.InstallConfig {
			c := validInstallConfig()
			c.Compute[0].Platform.AWS.Zones = append(c.ControlPlane.Platform.AWS.Zones, "d")
			c.Compute = append(c.Compute, types.MachinePool{
				Architecture: types.ArchitectureAMD64,
				Platform: types.MachinePoolPlatform{
					AWS: &aws.MachinePool{
						Zones: []string{"a", "b", "e"},
					},
				},
			})
			return c
		}(),
		availZones:     validAvailZones(),
		privateSubnets: validPrivateSubnets(),
		publicSubnets:  validPublicSubnets(),
		availRegions:   validAvailRegions(),
		expectErr:      `^\[compute\[0\]\.platform\.aws\.zones: Invalid value: \[\]string{\"a\", \"b\", \"c\", \"d\"}: No subnets provided for zones \[d\], compute\[1\]\.platform\.aws\.zones: Invalid value: \[\]string{\"a\", \"b\", \"e\"}: No subnets provided for zones \[e\]\]$`,
	}, {
		name: "custom region invalid service endpoints none provided",
		installConfig: func() *types.InstallConfig {
			c := validInstallConfig()
			c.Platform.AWS.Region = "test-region"
			c.Platform.AWS.AMIID = "dummy-id"
			return c
		}(),
		availZones:     validAvailZones(),
		privateSubnets: validPrivateSubnets(),
		publicSubnets:  validPublicSubnets(),
		availRegions:   validAvailRegions(),
	}, {
		name: "custom region invalid service endpoints some provided",
		installConfig: func() *types.InstallConfig {
			c := validInstallConfig()
			c.Platform.AWS.Region = "test-region"
			c.Platform.AWS.AMIID = "dummy-id"
			c.Platform.AWS.ServiceEndpoints = validServiceEndpoints()[:3]
			return c
		}(),
		availZones:     validAvailZones(),
		privateSubnets: validPrivateSubnets(),
		publicSubnets:  validPublicSubnets(),
		availRegions:   validAvailRegions(),
	}, {
		name: "custom region valid service endpoints",
		installConfig: func() *types.InstallConfig {
			c := validInstallConfig()
			c.Platform.AWS.Region = "test-region"
			c.Platform.AWS.AMIID = "dummy-id"
			c.Platform.AWS.ServiceEndpoints = validServiceEndpoints()
			return c
		}(),
		availZones:     validAvailZones(),
		privateSubnets: validPrivateSubnets(),
		publicSubnets:  validPublicSubnets(),
		availRegions:   validAvailRegions(),
	}, {
		name: "AMI omitted for new region in standard partition",
		installConfig: func() *types.InstallConfig {
			c := validInstallConfig()
			c.Platform.AWS.Region = "us-newregion-1"
			c.Platform.AWS.ServiceEndpoints = validServiceEndpoints()
			return c
		}(),
		availZones:     validAvailZones(),
		privateSubnets: validPrivateSubnets(),
		publicSubnets:  validPublicSubnets(),
		availRegions:   validAvailRegions(),
		expectErr:      "platform.aws.amiID: Required value: AMI must be provided",
	}, {
		name: "accept platform-level AMI",
		installConfig: func() *types.InstallConfig {
			c := validInstallConfig()
			c.Platform.AWS.Region = "us-gov-east-1"
			c.Platform.AWS.AMIID = "custom-ami"
			return c
		}(),
		availZones:     validAvailZones(),
		privateSubnets: validPrivateSubnets(),
		publicSubnets:  validPublicSubnets(),
		availRegions:   validAvailRegions(),
	}, {
		name: "accept AMI from default machine platform",
		installConfig: func() *types.InstallConfig {
			c := validInstallConfig()
			c.Platform.AWS.Region = "us-gov-east-1"
			c.Platform.AWS.DefaultMachinePlatform = &aws.MachinePool{AMIID: "custom-ami"}
			return c
		}(),
		availZones:     validAvailZones(),
		privateSubnets: validPrivateSubnets(),
		publicSubnets:  validPublicSubnets(),
		availRegions:   validAvailRegions(),
	}, {
		name: "accept AMIs specified for each machine pool",
		installConfig: func() *types.InstallConfig {
			c := validInstallConfig()
			c.Platform.AWS.Region = "us-gov-east-1"
			c.ControlPlane.Platform.AWS.AMIID = "custom-ami"
			c.Compute[0].Platform.AWS.AMIID = "custom-ami"
			return c
		}(),
		availZones:     validAvailZones(),
		privateSubnets: validPrivateSubnets(),
		publicSubnets:  validPublicSubnets(),
		availRegions:   validAvailRegions(),
	}, {
		name: "AMI omitted for compute with no replicas",
		installConfig: func() *types.InstallConfig {
			c := validInstallConfig()
			c.Platform.AWS.Region = "us-gov-east-1"
			c.ControlPlane.Platform.AWS.AMIID = "custom-ami"
			c.Compute[0].Replicas = ptr.To[int64](0)
			return c
		}(),
		availZones:     validAvailZones(),
		privateSubnets: validPrivateSubnets(),
		publicSubnets:  validPublicSubnets(),
		availRegions:   validAvailRegions(),
	}, {
		name: "AMI not provided for unknown region",
		installConfig: func() *types.InstallConfig {
			c := validInstallConfig()
			c.Platform.AWS.Region = "test-region"
			c.Platform.AWS.ServiceEndpoints = validServiceEndpoints()
			return c
		}(),
		availZones:     validAvailZones(),
		privateSubnets: validPrivateSubnets(),
		publicSubnets:  validPublicSubnets(),
		availRegions:   validAvailRegions(),
		expectErr:      `^platform\.aws\.amiID: Required value: AMI must be provided$`,
	}, {
		name: "invalid endpoint URL",
		installConfig: func() *types.InstallConfig {
			c := validInstallConfig()
			c.Platform.AWS.Region = "us-east-1"
			c.Platform.AWS.ServiceEndpoints = invalidServiceEndpoint()
			c.Platform.AWS.AMIID = "custom-ami"
			return c
		}(),
		availZones:     validAvailZones(),
		privateSubnets: validPrivateSubnets(),
		publicSubnets:  validPublicSubnets(),
		availRegions:   validAvailRegions(),
		expectErr:      `^\Q[platform.aws.serviceEndpoints[0].url: Invalid value: "testing": Head "testing": unsupported protocol scheme "", platform.aws.serviceEndpoints[1].url: Invalid value: "http://testing.non": Head "http://testing.non": dial tcp: lookup testing.non\E.*: no such host\]$`,
	}, {
		name: "invalid proxy URL but valid URL",
		installConfig: func() *types.InstallConfig {
			c := validInstallConfig()
			c.Platform.AWS.Region = "us-east-1"
			c.Platform.AWS.AMIID = "custom-ami"
			c.Platform.AWS.ServiceEndpoints = []aws.ServiceEndpoint{{Name: "test", URL: "http://testing.com"}}
			return c
		}(),
		availZones:     validAvailZones(),
		privateSubnets: validPrivateSubnets(),
		publicSubnets:  validPublicSubnets(),
		availRegions:   validAvailRegions(),
		proxy:          "proxy",
	}, {
		name: "invalid proxy URL and invalid URL",
		installConfig: func() *types.InstallConfig {
			c := validInstallConfig()
			c.Platform.AWS.Region = "us-east-1"
			c.Platform.AWS.AMIID = "custom-ami"
			c.Platform.AWS.ServiceEndpoints = []aws.ServiceEndpoint{{Name: "test", URL: "http://test"}}
			return c
		}(),
		availZones:     validAvailZones(),
		privateSubnets: validPrivateSubnets(),
		publicSubnets:  validPublicSubnets(),
		availRegions:   validAvailRegions(),
		proxy:          "http://proxy.com",
		expectErr:      `^\Qplatform.aws.serviceEndpoints[0].url: Invalid value: "http://test": Head "http://test": dial tcp: lookup test\E.*: no such host$`,
	}, {
		name: "invalid public ipv4 pool private installation",
		installConfig: func() *types.InstallConfig {
			c := validInstallConfig()
			c.Publish = types.InternalPublishingStrategy
			c.Platform.AWS.PublicIpv4Pool = "ipv4pool-ec2-123"
			c.Platform.AWS.VPC.Subnets = []aws.Subnet{}
			return c
		}(),
		availZones:   validAvailZones(),
		availRegions: validAvailRegions(),
		expectErr:    `^platform.aws.publicIpv4PoolId: Invalid value: "ipv4pool-ec2-123": publish strategy Internal can't be used with custom Public IPv4 Pools$`,
	}, {
		name: "invalid publish method for public-only subnets install",
		installConfig: func() *types.InstallConfig {
			c := validInstallConfig()
			c.Publish = types.InternalPublishingStrategy
			return c
		}(),
		privateSubnets: validPrivateSubnets(),
		publicSubnets:  validPublicSubnets(),
		availRegions:   validAvailRegions(),
		publicOnly:     "true",
		expectErr:      `^publish: Invalid value: \"Internal\": cluster cannot be private with public subnets$`,
	}, {
		name: "no subnets specified for public-only subnets cluster",
		installConfig: func() *types.InstallConfig {
			c := validInstallConfig()
			c.Platform.AWS.VPC.Subnets = []aws.Subnet{}
			return c
		}(),
		privateSubnets: validPrivateSubnets(),
		availZones:     validAvailZones(),
		availRegions:   validAvailRegions(),
		publicOnly:     "true",
		expectErr:      `^platform\.aws\.subnets: Required value: subnets must be specified for public-only subnets clusters$`,
	}, {
		name:           "no public subnets specified for public-only subnets cluster",
		installConfig:  validInstallConfig(),
		privateSubnets: validPrivateSubnets(),
		availZones:     validAvailZones(),
		availRegions:   validAvailRegions(),
		publicOnly:     "true",
		expectErr:      `^\[platform\.aws\.vpc\.subnets: Required value: public subnets are required for a public-only subnets cluster, platform\.aws\.vpc\.subnets: Invalid value: \[\]aws\.Subnet\{aws\.Subnet\{ID:\"valid-private-subnet-a\", Roles:\[\]aws\.SubnetRole\(nil\)\}, aws\.Subnet\{ID:\"valid-private-subnet-b\", Roles:\[\]aws\.SubnetRole\(nil\)\}, aws\.Subnet\{ID:\"valid-private-subnet-c\", Roles:\[\]aws\.SubnetRole\(nil\)\}, aws\.Subnet\{ID:\"valid-public-subnet-a\", Roles:\[\]aws\.SubnetRole\(nil\)\}, aws\.Subnet\{ID:\"valid-public-subnet-b\", Roles:\[\]aws\.SubnetRole\(nil\)\}, aws\.Subnet\{ID:\"valid-public-subnet-c\", Roles:\[\]aws\.SubnetRole\(nil\)\}\}: No public subnet provided for zones \[a b c\]\]$`,
	}, {
		name:           "valid public-only subnets install config",
		installConfig:  validInstallConfig(),
		privateSubnets: validPrivateSubnets(),
		publicSubnets:  validPublicSubnets(),
		availZones:     validAvailZones(),
		availRegions:   validAvailRegions(),
		publicOnly:     "true",
	}}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			meta := &Metadata{
				availabilityZones: test.availZones,
				availableRegions:  test.availRegions,
				privateSubnets:    test.privateSubnets,
				publicSubnets:     test.publicSubnets,
				edgeSubnets:       test.edgeSubnets,
				instanceTypes:     test.instanceTypes,
				Subnets:           test.installConfig.Platform.AWS.VPC.Subnets,
			}
			if test.proxy != "" {
				os.Setenv("HTTP_PROXY", test.proxy)
			} else {
				os.Unsetenv("HTTP_PROXY")
			}
			if test.publicOnly != "" {
				os.Setenv("OPENSHIFT_INSTALL_AWS_PUBLIC_ONLY", test.publicOnly)
			} else {
				os.Unsetenv("OPENSHIFT_INSTALL_AWS_PUBLIC_ONLY")
			}
			err := Validate(context.TODO(), meta, test.installConfig)
			if test.expectErr == "" {
				assert.NoError(t, err)
			} else {
				if assert.Error(t, err) {
					assert.Regexp(t, test.expectErr, err.Error())
				}
			}
		})
	}
}

func TestIsHostedZoneDomainParentOfClusterDomain(t *testing.T) {
	cases := []struct {
		name             string
		hostedZoneDomain string
		clusterDomain    string
		expected         bool
	}{{
		name:             "same",
		hostedZoneDomain: "c.b.a.",
		clusterDomain:    "c.b.a.",
		expected:         true,
	}, {
		name:             "strict parent",
		hostedZoneDomain: "b.a.",
		clusterDomain:    "c.b.a.",
		expected:         true,
	}, {
		name:             "grandparent",
		hostedZoneDomain: "a.",
		clusterDomain:    "c.b.a.",
		expected:         true,
	}, {
		name:             "not parent",
		hostedZoneDomain: "f.e.d.",
		clusterDomain:    "c.b.a.",
		expected:         false,
	}, {
		name:             "child",
		hostedZoneDomain: "d.c.b.a.",
		clusterDomain:    "c.b.a.",
		expected:         false,
	}, {
		name:             "suffix but not parent",
		hostedZoneDomain: "b.a.",
		clusterDomain:    "cb.a.",
		expected:         false,
	}}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			zone := &route53.HostedZone{Name: &tc.hostedZoneDomain}
			actual := isHostedZoneDomainParentOfClusterDomain(zone, tc.clusterDomain)
			assert.Equal(t, tc.expected, actual)
		})
	}
}

func TestValidateForProvisioning(t *testing.T) {
	cases := []struct {
		name        string
		edits       editFunctions
		expectedErr string
	}{{
		// This really should test for nil, as nothing happened, but no errors were provided
		name:  "internal publish strategy no hosted zone",
		edits: editFunctions{publishInternal, clearHostedZone},
	}, {
		name:        "external publish strategy no hosted zone invalid (empty) base domain",
		edits:       editFunctions{clearHostedZone, clearBaseDomain},
		expectedErr: "baseDomain: Invalid value: \"\": cannot find base domain",
	}, {
		name:        "external publish strategy no hosted zone invalid base domain",
		edits:       editFunctions{clearHostedZone, invalidateBaseDomain},
		expectedErr: "baseDomain: Invalid value: \"invalid-base-domain\": cannot find base domain",
	}, {
		name:  "external publish strategy no hosted zone valid base domain",
		edits: editFunctions{clearHostedZone},
	}, {
		name:  "internal publish strategy valid hosted zone",
		edits: editFunctions{publishInternal},
	}, {
		name:        "internal publish strategy invalid hosted zone",
		edits:       editFunctions{publishInternal, invalidateHostedZone},
		expectedErr: "aws.hostedZone: Invalid value: \"invalid-hosted-zone\": unable to retrieve hosted zone",
	}, {
		name: "external publish strategy valid hosted zone",
	}, {
		name:        "external publish strategy invalid hosted zone",
		edits:       editFunctions{invalidateHostedZone},
		expectedErr: "aws.hostedZone: Invalid value: \"invalid-hosted-zone\": unable to retrieve hosted zone",
	}}

	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	route53Client := mock.NewMockAPI(mockCtrl)

	validHostedZoneOutput := createValidHostedZone()
	validDomainOutput := createBaseDomainHostedZone()

	route53Client.EXPECT().GetBaseDomain(validDomainName).Return(&validDomainOutput, nil).AnyTimes()
	route53Client.EXPECT().GetBaseDomain("").Return(nil, fmt.Errorf("invalid value: \"\": cannot find base domain")).AnyTimes()
	route53Client.EXPECT().GetBaseDomain(invalidBaseDomain).Return(nil, fmt.Errorf("invalid value: \"%s\": cannot find base domain", invalidBaseDomain)).AnyTimes()

	route53Client.EXPECT().ValidateZoneRecords(&validDomainOutput, gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(field.ErrorList{}).AnyTimes()
	route53Client.EXPECT().ValidateZoneRecords(gomock.Any(), validHostedZoneName, gomock.Any(), gomock.Any(), gomock.Any()).Return(field.ErrorList{}).AnyTimes()

	// An invalid hosted zone should provide an error
	route53Client.EXPECT().GetHostedZone(validHostedZoneName, gomock.Any()).Return(&validHostedZoneOutput, nil).AnyTimes()
	route53Client.EXPECT().GetHostedZone(gomock.Not(validHostedZoneName), gomock.Any()).Return(nil, fmt.Errorf("invalid value: \"invalid-hosted-zone\": cannot find hosted zone")).AnyTimes()

	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			editedInstallConfig := validInstallConfig()
			for _, edit := range test.edits {
				edit(editedInstallConfig)
			}

			meta := &Metadata{
				availabilityZones: validAvailZones(),
				privateSubnets:    validPrivateSubnets(),
				publicSubnets:     validPublicSubnets(),
				instanceTypes:     validInstanceTypes(),
				Region:            editedInstallConfig.AWS.Region,
				vpc:               "valid-private-subnet-a",
				Subnets:           editedInstallConfig.Platform.AWS.VPC.Subnets,
			}

			err := ValidateForProvisioning(route53Client, editedInstallConfig, meta)
			if test.expectedErr == "" {
				assert.NoError(t, err)
			} else {
				if assert.Error(t, err) {
					assert.Regexp(t, test.expectedErr, err.Error())
				}
			}
		})
	}
}

func TestGetSubDomainDNSRecords(t *testing.T) {
	cases := []struct {
		name               string
		baseDomain         string
		problematicRecords []string
		expectedErr        string
	}{{
		name:        "empty cluster domain",
		expectedErr: fmt.Sprintf("hosted zone domain %s is not a parent of the cluster domain %s", validDomainName, ""),
	}, {
		name:        "period cluster domain",
		baseDomain:  ".",
		expectedErr: fmt.Sprintf("hosted zone domain %s is not a parent of the cluster domain %s", validDomainName, "."),
	}, {
		name:       "valid dns record no problems",
		baseDomain: validDomainName + ".",
	}, {
		name:               "valid dns record with problems",
		baseDomain:         validDomainName,
		problematicRecords: []string{"test1.ClusterMetaName.valid-base-domain."},
	}, {
		name:               "valid dns record with skipped problems",
		baseDomain:         validDomainName,
		problematicRecords: []string{"test1.ClusterMetaName.valid-base-domain.", "ClusterMetaName.xxxxx-xxxx-xxxxxx."},
	},
	}

	validDomainOutput := createBaseDomainHostedZone()

	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()
	route53Client := mock.NewMockAPI(mockCtrl)

	for _, test := range cases {

		t.Run(test.name, func(t *testing.T) {

			ic := validInstallConfig()
			ic.BaseDomain = test.baseDomain

			if test.expectedErr != "" {
				if test.problematicRecords == nil {
					route53Client.EXPECT().GetSubDomainDNSRecords(&validDomainOutput, ic, gomock.Any()).Return(nil, fmt.Errorf("%s", test.expectedErr)).AnyTimes()
				} else {
					// mimic the results of what should happen in the internal function passed to
					// ListResourceRecordSetsPages by GetSubDomainDNSRecords. Skip certain problematicRecords
					returnedProblems := make([]string, 0, len(test.problematicRecords))
					expectedName := ic.ClusterDomain() + "."
					for _, pr := range test.problematicRecords {
						if len(pr) != len(expectedName) {
							returnedProblems = append(returnedProblems, pr)
						}
					}
					route53Client.EXPECT().GetSubDomainDNSRecords(&validDomainOutput, ic, gomock.Any()).Return(returnedProblems, fmt.Errorf("%s", test.expectedErr)).AnyTimes()
				}
			} else {
				route53Client.EXPECT().GetSubDomainDNSRecords(&validDomainOutput, ic, gomock.Any()).Return(nil, nil).AnyTimes()
			}

			_, err := route53Client.GetSubDomainDNSRecords(&validDomainOutput, ic, nil)
			if test.expectedErr == "" {
				assert.NoError(t, err)
			} else {
				if assert.Error(t, err) {
					assert.Regexp(t, test.expectedErr, err.Error())
				}
			}
		})
	}
}

func TestSkipRecords(t *testing.T) {
	cases := []struct {
		name           string
		recordName     string
		expectedResult bool
	}{{
		name:           "record not part of cluster",
		recordName:     fmt.Sprintf("%s.test.domain.", metaName),
		expectedResult: true,
	}, {
		name:           "record and cluster domain are same",
		recordName:     fmt.Sprintf("%s.%s.", metaName, validDomainName),
		expectedResult: true,
	}, {
		name: "record not part of cluster bad suffix",
		// The parent below does not have a dot following it on purpose - do not Remove
		recordName:     fmt.Sprintf("parent%s.%s.", metaName, validDomainName),
		expectedResult: true,
	}, {
		name: "record part of cluster bad suffix",
		// The parent below does not have a dot following it on purpose - do not Remove
		recordName:     fmt.Sprintf("parent.%s.%s.", metaName, validDomainName),
		expectedResult: false,
	},
	}

	// create the dottedClusterDomain in the same manner that it will be used in GetSubDomainDNSRecords
	ic := validInstallConfig()
	ic.BaseDomain = validDomainName
	dottedClusterDomain := ic.ClusterDomain() + "."

	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.expectedResult, skipRecord(test.recordName, dottedClusterDomain))
		})
	}
}
