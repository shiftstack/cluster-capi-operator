package assets

import (
	"embed"
	"fmt"
	"path"
	"strings"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type assetKey string

const (
	OperatorDeploymentKey assetKey = "operator-deployment"
	OperatorServiceKey    assetKey = "operator-service"

	CoreProviderKey          assetKey = "core-provider"
	CoreProviderConfigMapKey assetKey = "core-provider-configmap"

	InfrastructureProviderKey          assetKey = "infrastructure-provider"
	InfrastructureProviderConfigMapKey assetKey = "infrastructure-provider-configmap"
)

//go:embed capi-operator/*.yaml core-capi/*.yaml infrastructure-providers/*.yaml
var fs embed.FS

func ReadOperatorAssets(scheme *runtime.Scheme) (map[assetKey]client.Object, error) {
	dir := "capi-operator"
	assetNames, err := fs.ReadDir(dir)
	if err != nil {
		return nil, err
	}

	objs := map[assetKey]client.Object{}
	for _, assetName := range assetNames {
		obj, err := readObject(dir, assetName.Name(), scheme)
		if err != nil {
			return nil, err
		}

		switch obj.GetObjectKind().GroupVersionKind().Kind {
		case "Deployment":
			objs[OperatorDeploymentKey] = obj.(client.Object)
		case "Service":
			objs[OperatorServiceKey] = obj.(client.Object)
		default:
			return nil, fmt.Errorf("unsupported asset for operator: %s", obj.GetObjectKind().GroupVersionKind().Kind)
		}
	}

	return objs, nil
}

func ReadCoreProviderAssets(scheme *runtime.Scheme) (map[assetKey]client.Object, error) {
	dir := "core-capi"
	assetNames, err := fs.ReadDir(dir)
	if err != nil {
		return nil, err
	}

	objs := map[assetKey]client.Object{}
	for _, assetName := range assetNames {
		obj, err := readObject(dir, assetName.Name(), scheme)
		if err != nil {
			return nil, err
		}
		switch obj.GetObjectKind().GroupVersionKind().Kind {
		case "ConfigMap":
			objs[CoreProviderConfigMapKey] = obj.(client.Object)
		case "CoreProvider":
			objs[CoreProviderKey] = obj.(client.Object)
		default:
			return nil, fmt.Errorf("unsupported asset for core provider: %s", obj.GetObjectKind().GroupVersionKind().Kind)
		}
	}

	if len(objs) != 2 {
		return nil, fmt.Errorf("expected exactly 2 assets for core provider, got %d", len(assetNames))
	}

	return objs, nil
}

func ReadInfrastructureProviderAssets(scheme *runtime.Scheme, platformType string) (map[assetKey]client.Object, error) {
	dir := "infrastructure-providers"
	assetNames, err := fs.ReadDir(dir)
	if err != nil {
		return nil, err
	}

	objs := map[assetKey]client.Object{}
	for _, assetName := range assetNames {
		prefix := fmt.Sprintf("infrastructure-%s", platformType)
		if !strings.HasPrefix(assetName.Name(), prefix) {
			continue
		}
		obj, err := readObject(dir, assetName.Name(), scheme)
		if err != nil {
			return nil, err
		}
		switch obj.GetObjectKind().GroupVersionKind().Kind {
		case "ConfigMap":
			objs[InfrastructureProviderConfigMapKey] = obj.(client.Object)
		case "InfrastructureProvider":
			objs[InfrastructureProviderKey] = obj.(client.Object)
		default:
			return nil, fmt.Errorf("unsupported asset for infrastructure provider: %s", obj.GetObjectKind().GroupVersionKind().Kind)
		}
	}

	if len(objs) != 2 {
		return nil, fmt.Errorf("expected exactly 2 assets for infrastructure provider, got %d", len(objs))
	}

	return objs, nil
}

func readObject(dir, name string, scheme *runtime.Scheme) (runtime.Object, error) {
	b, err := fs.ReadFile(path.Join(dir, name))
	if err != nil {
		return nil, err
	}
	codecs := serializer.NewCodecFactory(scheme)
	obj, _, err := codecs.UniversalDeserializer().Decode(b, nil, nil)
	if err != nil {
		return nil, err
	}
	return obj, nil
}
