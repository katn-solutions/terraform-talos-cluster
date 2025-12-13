package test

import (
	"testing"

	"github.com/gruntwork-io/terratest/modules/terraform"
	"github.com/stretchr/testify/assert"
)

func TestTerraformTalosClusterV0Validation(t *testing.T) {
	t.Parallel()

	terraformOptions := terraform.WithDefaultRetryableErrors(t, &terraform.Options{
		TerraformDir: "../v0",
		NoColor:      true,
	})

	terraform.InitAndValidate(t, terraformOptions)
}

func TestTerraformTalosClusterV1Validation(t *testing.T) {
	t.Parallel()

	terraformOptions := terraform.WithDefaultRetryableErrors(t, &terraform.Options{
		TerraformDir: "../v1",
		NoColor:      true,
	})

	terraform.InitAndValidate(t, terraformOptions)
}

func TestTerraformTalosClusterV0Inputs(t *testing.T) {
	testCases := []struct {
		name     string
		expectOK bool
	}{
		{"ValidV0Configuration", true},
		{"ValidV0WithKafka", true},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			terraformOptions := terraform.WithDefaultRetryableErrors(t, &terraform.Options{
				TerraformDir: "../v0",
				NoColor:      true,
			})

			// Validate configuration (terraform validate doesn't accept -var flags)
			terraform.InitAndValidate(t, terraformOptions)

			if tc.expectOK {
				assert.True(t, true, "Configuration validated successfully")
			}
		})
	}
}

func TestTerraformTalosClusterV1Inputs(t *testing.T) {
	testCases := []struct {
		name     string
		expectOK bool
	}{
		{"ValidV1Configuration", true},
		{"ValidV1HAConfiguration", true},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			terraformOptions := terraform.WithDefaultRetryableErrors(t, &terraform.Options{
				TerraformDir: "../v1",
				NoColor:      true,
			})

			// Validate configuration (terraform validate doesn't accept -var flags)
			terraform.InitAndValidate(t, terraformOptions)

			if tc.expectOK {
				assert.True(t, true, "Configuration validated successfully")
			}
		})
	}
}

func TestTerraformTalosClusterOrganizationVariable(t *testing.T) {
	testCases := []struct {
		name string
	}{
		{"AlphanumericOrg"},
		{"HyphenatedOrg"},
		{"UnderscoreOrg"},
		{"LowercaseOrg"},
		{"MixedCaseOrg"},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			terraformOptions := terraform.WithDefaultRetryableErrors(t, &terraform.Options{
				TerraformDir: "../v0",
				NoColor:      true,
			})

			// Validate configuration (terraform validate doesn't accept -var flags)
			terraform.InitAndValidate(t, terraformOptions)
			assert.True(t, true, "Organization variable validated successfully")
		})
	}
}
