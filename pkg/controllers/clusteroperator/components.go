package clusteroperator

import (
	"context"
	"fmt"
	"strings"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	operatorv1 "sigs.k8s.io/cluster-api-operator/api/v1alpha1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
)

func (r *ClusterOperatorReconciler) reconcileOperatorDeployment(ctx context.Context, deployment *appsv1.Deployment) error {
	log := ctrl.LoggerFrom(ctx)

	deploymentCopy := deployment.DeepCopy()
	if _, err := controllerutil.CreateOrUpdate(ctx, r.Client, deployment, func() error {
		deployment.Spec = deploymentCopy.Spec

		containerToImageRef := map[string]string{
			"manager":         "cluster-kube-cluster-api-operator",
			"kube-rbac-proxy": "kube-rbac-proxy",
		}
		for i, cont := range deployment.Spec.Template.Spec.Containers {
			if imageRef, ok := containerToImageRef[cont.Name]; ok {
				if cont.Image == r.Images[imageRef] {
					log.V(5).Info("container doesn't require mutation", "containerName", cont.Name, "containerName",
						cont.Image)
					continue
				}
				log.Info("container changing image", cont.Name, r.Images[imageRef])
				deployment.Spec.Template.Spec.Containers[i].Image = r.Images[imageRef]
			} else {
				log.Info("container %s no image replacement found", "containerName", cont.Name, "containerName",
					cont.Image)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("unable to create or update upstream CAPI operator Deployment: %v", err)
	}

	return nil
}

func (r *ClusterOperatorReconciler) reconcileOperatorService(ctx context.Context, service *corev1.Service) error {
	serviceCopy := service.DeepCopy()
	if _, err := controllerutil.CreateOrUpdate(ctx, r.Client, service, func() error {
		service.Spec = serviceCopy.Spec
		return nil
	}); err != nil {
		return fmt.Errorf("unable to create or update upstream CAPI operator Service: %v", err)
	}

	return nil
}

func (r *ClusterOperatorReconciler) reconcileCoreProvider(ctx context.Context, coreProvider *operatorv1.CoreProvider) error {
	coreProviderCopy := coreProvider.DeepCopy()
	if _, err := controllerutil.CreateOrUpdate(ctx, r.Client, coreProvider, func() error {
		coreProvider.TypeMeta = coreProviderCopy.TypeMeta
		coreProvider.Spec = coreProviderCopy.Spec
		containers := coreProvider.Spec.Deployment.Containers
		coreProvider.Spec.ProviderSpec.Deployment = &operatorv1.DeploymentSpec{
			Containers: r.containerCustomizationFromProvider(coreProvider.Kind, coreProvider.Name, containers),
		}
		return nil
	}); err != nil {
		return fmt.Errorf("unable to create or update CoreProvider: %v", err)
	}

	return nil
}

func (r *ClusterOperatorReconciler) reconcileInfrastructureProvider(ctx context.Context, infraProvider *operatorv1.InfrastructureProvider) error {
	infraProviderCopy := infraProvider.DeepCopy()
	if _, err := controllerutil.CreateOrUpdate(ctx, r.Client, infraProvider, func() error {
		infraProvider.TypeMeta = infraProviderCopy.TypeMeta
		infraProvider.Spec = infraProviderCopy.Spec
		containers := infraProviderCopy.Spec.Deployment.Containers
		infraProvider.Spec.ProviderSpec.Deployment = &operatorv1.DeploymentSpec{
			Containers: r.containerCustomizationFromProvider(infraProvider.Kind, infraProvider.Name, containers),
		}
		return nil
	}); err != nil {
		return fmt.Errorf("unable to create or update InfrastructureProvider: %v", err)
	}
	return nil
}

func (r *ClusterOperatorReconciler) reconcileConfigMap(ctx context.Context, configMap *corev1.ConfigMap) error {
	cmCopy := configMap.DeepCopy()
	if _, err := controllerutil.CreateOrUpdate(ctx, r.Client, configMap, func() error {
		configMap.Labels = cmCopy.Labels
		configMap.Data = cmCopy.Data
		return nil
	}); err != nil {
		return fmt.Errorf("unable to create or update core Cluster API Configmap: %v", err)
	}
	return nil
}

// containerCustomizationFromProvider returns a list of containers customized for the given provider
func (r *ClusterOperatorReconciler) containerCustomizationFromProvider(kind, name string, containers []operatorv1.ContainerSpec) []operatorv1.ContainerSpec {
	for i := range containers {
		switch containers[i].Name {
		// We expect provider to always have a manager container
		case "manager":
			// TODO: we should return error when image was not found
			image := getProviderImage(kind, name, r.Images)
			containers[i].Image = newImageMeta(image)
		case "kube-rbac-proxy":
			image := r.Images["kube-rbac-proxy"]
			containers[i].Image = newImageMeta(image)
		}
	}
	return containers
}

func getProviderImage(kind, name string, images map[string]string) string {
	expectedImage := ""
	switch kind {
	case "CoreProvider":
		// core provider image will always have this name
		expectedImage = "cluster-capi-controllers"
	case "InfrastructureProvider":
		// infrastructure provider image name will be in this form - $providername-cluster-api-controllers
		expectedImage = fmt.Sprintf("%s-cluster-api-controllers", name)
	}
	return images[expectedImage]
}

func newImageMeta(imageURL string) *operatorv1.ImageMeta {
	im := &operatorv1.ImageMeta{}

	urlSplit := strings.Split(imageURL, ":")
	if len(urlSplit) == 2 {
		im.Tag = urlSplit[1]
	}
	urlSplit = strings.Split(urlSplit[0], "/")
	im.Name = urlSplit[len(urlSplit)-1]
	im.Repository = strings.Join(urlSplit[0:len(urlSplit)-1], "/")
	return im
}
