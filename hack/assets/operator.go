package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"strings"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	configclient "sigs.k8s.io/cluster-api/cmd/clusterctl/client/config"
	"sigs.k8s.io/cluster-api/cmd/clusterctl/client/repository"
	"sigs.k8s.io/cluster-api/cmd/clusterctl/client/yamlprocessor"
	"sigs.k8s.io/yaml"
)

var (
	operatorUrlFmt = "https://github.com/openshift/cluster-api-operator//config/default?ref=%s"
)

func importCAPIOperator() error {
	fmt.Println("Processing Cluster API Operator")

	// Load CAPI Operator manifests from file
	objs, err := readCAPIOperatorManifests()
	if err != nil {
		return fmt.Errorf("failed to read CAPI Operator manifests: %v", err)
	}

	// Perform all manifest transformations
	resourceMap := processObjects(objs, true)

	// Write RBAC components to manifests, they will be managed by CVO
	rbacFileName := fmt.Sprintf("%s%s_03_rbac-roles.%s.yaml", manifestPrefix, "capi-operator", "upstream")
	err = writeComponentsToManifests(rbacFileName, resourceMap[rbacKey])
	if err != nil {
		return err
	}

	// Write CRD components to manifests, they will be managed by CVO
	crdFileName := fmt.Sprintf("%s%s_02_crd.%s.yaml", manifestPrefix, "capi-operator", "upstream")
	err = writeComponentsToManifests(crdFileName, resourceMap[crdKey])
	if err != nil {
		return err
	}

	// Write all other components(deployments, services, secret, etc)
	return writeAllOtherOperatorComponents(resourceMap[otherKey])
}

func readCAPIOperatorManifests() ([]unstructured.Unstructured, error) {
	// Create new clusterctl config client
	configClient, err := configclient.New("")
	if err != nil {
		return nil, err
	}

	// Create new clusterctl provider client
	// The arguments to Get() do nothing in this case, but they are required for setting up a yaml processor
	providerConfig, err := configClient.Providers().Get("cluster-api", "CoreProvider")
	if err != nil {
		return nil, err
	}

	// Read operator config yaml
	operatorConfig, err := ioutil.ReadFile(operatorConfigPath)
	if err != nil {
		return nil, err
	}

	operatorConfigMap := map[string]string{}

	// Parse operator config yaml
	err = yaml.Unmarshal(operatorConfig, &operatorConfigMap)
	if err != nil {
		return nil, err
	}

	operatorUrl := fmt.Sprintf(operatorUrlFmt, operatorConfigMap["branch"])

	rawComponents, err := fetchAndCompileComponents(operatorUrl)
	if err != nil {
		return nil, err
	}

	// Set options for yaml processor
	options := repository.ComponentsOptions{
		TargetNamespace:     targetNamespace,
		SkipTemplateProcess: false,
	}

	// Process operator manifests
	components, err := repository.NewComponents(repository.ComponentsInput{
		Provider:     providerConfig,
		ConfigClient: configClient,
		Processor:    yamlprocessor.NewSimpleProcessor(),
		RawYaml:      rawComponents,
		Options:      options,
	})
	if err != nil {
		return nil, err
	}

	return components.Objs(), nil
}

func writeAllOtherOperatorComponents(objs []unstructured.Unstructured) error {
	for _, obj := range objs {
		content, err := yaml.Marshal(obj.UnstructuredContent())
		if err != nil {
			return fmt.Errorf("failed to marshal object: %w", err)
		}

		fileName := fmt.Sprintf("%s.yaml", strings.ToLower(obj.GroupVersionKind().Kind))
		err = os.WriteFile(path.Join(operatorAssetsPath, fileName), ensureNewLine(content), 0600)
		if err != nil {
			return fmt.Errorf("failed to write %s: %w", operatorAssetsPath, err)
		}
	}

	return nil
}
