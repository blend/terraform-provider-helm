// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package helm

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/pkg/errors"
	"helm.sh/helm/v3/pkg/action"
	"helm.sh/helm/v3/pkg/chart"
	"helm.sh/helm/v3/pkg/kube"
	"helm.sh/helm/v3/pkg/release"
	corev1 "k8s.io/api/core/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	runtimeschema "k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/managedfields"
	"k8s.io/cli-runtime/pkg/genericiooptions"
	"k8s.io/cli-runtime/pkg/resource"
	"k8s.io/client-go/discovery"
	"k8s.io/kube-openapi/pkg/util/proto"
	"k8s.io/kubectl/pkg/cmd/diff"
	"k8s.io/kubectl/pkg/scheme"
	"sigs.k8s.io/structured-merge-diff/v4/fieldpath"
	"sigs.k8s.io/structured-merge-diff/v4/value"
	"sigs.k8s.io/yaml"
)

func getKubeClient(actionConfig *action.Configuration) (*kube.Client, error) {
	kc, ok := actionConfig.KubeClient.(*kube.Client)
	if !ok {
		return nil, errors.Errorf("client is not a *kube.Client")
	}
	return kc, nil
}

type filteredModels struct {
	models proto.Models
}

var versionSuffix = regexp.MustCompile(`_v\d+$`)

func (f *filteredModels) ListModels() []string {
	var models []string
	for _, model := range f.models.ListModels() {
		if versionSuffix.MatchString(model) {
			continue
		}
		models = append(models, model)
	}
	return models
}

func (f *filteredModels) LookupModel(name string) proto.Schema {
	return f.models.LookupModel(name)
}

// regenerateGVKParser builds the parser from the raw OpenAPI schema.
func regenerateGVKParser(dc discovery.DiscoveryInterface) (*managedfields.GvkParser, error) {
	doc, err := dc.OpenAPISchema()
	if err != nil {
		return nil, err
	}

	models, err := proto.NewOpenAPIData(doc)
	if err != nil {
		return nil, err
	}

	return managedfields.NewGVKParser(&filteredModels{models}, false)
}

type resourceIgnore struct {
	keyRegex   *regexp.Regexp
	fieldsJSON string
}

// removeUnmanagedFields removes fields updated by `kube-controller-manager` or
// through subresource apis from a kubernetes object
func removeUnmanagedFields(parser *managedfields.GvkParser, obj runtime.Object, gvk runtimeschema.GroupVersionKind, ignoreFieldsJSONs []string) error {
	parseableType := parser.Type(gvk)
	if parseableType == nil {
		return errors.Errorf("no parseable type found for %s", gvk.String())
	}
	typedObj, err := parseableType.FromStructured(obj)
	if err != nil {
		return err
	}
	accessor, err := apimeta.Accessor(obj)
	if err != nil {
		return err
	}
	objManagedFields := accessor.GetManagedFields()
	fieldSet := &fieldpath.Set{}
	for _, mf := range objManagedFields {
		if mf.Manager == "kube-controller-manager" || mf.Subresource != "" {
			fs := &fieldpath.Set{}
			if err := fs.FromJSON(bytes.NewReader(mf.FieldsV1.Raw)); err != nil {
				return err
			}
			fieldSet = fieldSet.Union(fs)
		}
	}
	fieldSet.Insert(fieldpath.MakePathOrDie("metadata", "generation"))
	for _, fieldsJSON := range ignoreFieldsJSONs {
		fieldsValue, err := value.FromJSON([]byte(fieldsJSON))
		if err != nil {
			return err
		}
		fieldSet = fieldSet.Union(fieldpath.SetFromValue(fieldsValue))
	}
	u := typedObj.RemoveItems(fieldSet).AsValue().Unstructured()
	m, ok := u.(map[string]interface{})
	if !ok {
		return errors.Errorf("unexpected type %T", u)
	}
	return runtime.DefaultUnstructuredConverter.FromUnstructured(m, obj)
}

// mapRuntimeObjects maps a list of kubernetes objects by key to their JSON
// representation, with unmanaged fields removed and sensitive values redacted
func mapRuntimeObjects(kc *kube.Client, objects []runtime.Object, d resourceGetter) (map[string]string, error) {
	clientSet, err := kc.Factory.KubernetesClientSet()
	if err != nil {
		return nil, err
	}
	parser, err := regenerateGVKParser(clientSet.Discovery())
	if err != nil {
		return nil, err
	}

	var resourceIgnores []resourceIgnore
	for _, ignoreElem := range d.Get("ignore_resource_fields").([]interface{}) {
		ignore := ignoreElem.(map[string]interface{})
		resourceIgnores = append(resourceIgnores, resourceIgnore{
			keyRegex:   regexp.MustCompile(ignore["key_regex"].(string)),
			fieldsJSON: ignore["fields_json"].(string),
		})
	}

	mappedObjects := make(map[string]string)
	for _, obj := range objects {
		gvk := obj.GetObjectKind().GroupVersionKind()
		if gvk.Kind == "Secret" {
			secret := &corev1.Secret{}
			err := scheme.Scheme.Convert(obj, secret, nil)
			if err != nil {
				return nil, err
			}
			redactSecretData(secret)
			obj = secret
		}
		accessor, err := apimeta.Accessor(obj)
		if err != nil {
			return nil, err
		}
		key := fmt.Sprintf("%s/%s/%s/%s",
			strings.ToLower(gvk.GroupKind().String()),
			gvk.Version,
			accessor.GetNamespace(),
			accessor.GetName(),
		)
		var ignoreFieldsJSONs []string
		for _, ignore := range resourceIgnores {
			if ignore.keyRegex.MatchString(key) {
				ignoreFieldsJSONs = append(ignoreFieldsJSONs, ignore.fieldsJSON)
			}
		}
		if err := removeUnmanagedFields(parser, obj, gvk, ignoreFieldsJSONs); err != nil {
			return nil, err
		}
		accessor.SetUID(types.UID(""))
		accessor.SetCreationTimestamp(metav1.Time{})
		accessor.SetResourceVersion("")
		accessor.SetManagedFields(nil)
		objJSON, err := json.Marshal(obj)
		if err != nil {
			return nil, err
		}
		mappedObjects[key] = redactSensitiveValues(string(objJSON), d)
	}
	return mappedObjects, nil
}

func mapResources(actionConfig *action.Configuration, r *release.Release, d resourceGetter, f func(*resource.Info) (runtime.Object, error)) (map[string]string, error) {
	resources, err := actionConfig.KubeClient.Build(bytes.NewBufferString(r.Manifest), false)
	if err != nil {
		return nil, err
	}
	var objects []runtime.Object
	err = resources.Visit(func(i *resource.Info, err error) error {
		if err != nil {
			return err
		}
		obj, err := f(i)
		if apierrors.IsNotFound(err) {
			return nil
		}
		if err != nil {
			return err
		}
		objects = append(objects, obj)
		return nil
	})
	if err != nil {
		return nil, err
	}
	kc, err := getKubeClient(actionConfig)
	if err != nil {
		return nil, err
	}
	return mapRuntimeObjects(kc, objects, d)
}

// getLiveResources gets the live kubernetes resources of a release
func getLiveResources(r *release.Release, m *Meta, d resourceGetter) (map[string]string, error) {
	actionConfig, err := m.GetHelmConfiguration(r.Namespace)
	if err != nil {
		return nil, err
	}
	kc, err := getKubeClient(actionConfig)
	if err != nil {
		return nil, err
	}
	return mapResources(actionConfig, r, d, func(i *resource.Info) (runtime.Object, error) {
		gvk := i.Object.GetObjectKind().GroupVersionKind()
		return kc.Factory.NewBuilder().
			Unstructured().
			NamespaceParam(i.Namespace).DefaultNamespace().
			ResourceNames(gvk.GroupKind().String(), i.Name).
			Flatten().
			Do().
			Object()
	})
}

// getDryRunResources gets the kubernetes resources as they would look like if
// the helm manifest is applied to the cluster. this is useful for detecting the
// differences between the live cluster state and the desired state.
func getDryRunResources(r *release.Release, m *Meta, d resourceGetter) (map[string]string, error) {
	actionConfig, err := m.GetHelmConfiguration(r.Namespace)
	if err != nil {
		return nil, err
	}
	ioStreams := genericiooptions.IOStreams{
		In:     os.Stdin,
		Out:    os.Stdout,
		ErrOut: os.Stderr,
	}
	fieldManager := "terraform-provider-helm"
	if os.Args[0] != "" {
		fieldManager = filepath.Base(os.Args[0])
	}
	return mapResources(actionConfig, r, d, func(i *resource.Info) (runtime.Object, error) {
		info := &diff.InfoObject{
			LocalObj:        i.Object,
			Info:            i,
			Encoder:         scheme.DefaultJSONEncoder(),
			Force:           false,
			ServerSideApply: true,
			FieldManager:    fieldManager,
			ForceConflicts:  true,
			IOStreams:       ioStreams,
		}
		return info.Merged()
	})
}

func getChartCRDs(c *chart.Chart) ([]apiextensionsv1.CustomResourceDefinition, error) {
	var crds []apiextensionsv1.CustomResourceDefinition
	for _, crdObject := range c.CRDObjects() {
		var crd apiextensionsv1.CustomResourceDefinition
		if err := yaml.Unmarshal(crdObject.File.Data, &crd); err != nil {
			return nil, err
		}
		crds = append(crds, crd)
	}
	return crds, nil
}

func shouldForceUpdateCustomResources(actionConfig *action.Configuration, r *release.Release, m *Meta, d *schema.ResourceData) (bool, error) {
	if !m.ExperimentEnabled("manifest") ||
		!d.Get("force_update_custom_resources").(bool) ||
		!d.HasChange("resources") {
		return false, nil
	}

	// force update if any custom resource has changed
	oldResources, newResources := d.GetChange("resources")
	oldResourcesMap := oldResources.(map[string]interface{})
	newResourcesMap := newResources.(map[string]interface{})
	crds, err := getChartCRDs(r.Chart)
	if err != nil {
		return false, err
	}
	forceGroupKinds := make(map[string]struct{})
	for _, crd := range crds {
		forceGroupKinds[fmt.Sprintf("%s.%s", crd.Spec.Names.Singular, crd.Spec.Group)] = struct{}{}
	}
	resources, err := actionConfig.KubeClient.Build(bytes.NewBufferString(r.Manifest), false)
	if err != nil {
		return false, err
	}
	err = resources.Visit(func(i *resource.Info, err error) error {
		versioned := kube.AsVersioned(i)
		switch obj := versioned.(type) {
		case *apiextensionsv1.CustomResourceDefinition:
			forceGroupKinds[fmt.Sprintf("%s.%s", obj.Spec.Names.Singular, obj.Spec.Group)] = struct{}{}
		// also force update resource kinds not recognized by helm as native k8s schemes
		// https://github.com/helm/helm/blob/v3.15.3/pkg/kube/converter.go#L54-L69
		case runtime.Unstructured:
			forceGroupKinds[strings.ToLower(obj.GetObjectKind().GroupVersionKind().GroupKind().String())] = struct{}{}
		}
		return nil
	})
	if err != nil {
		return false, err
	}
	if len(forceGroupKinds) == 0 {
		return false, nil
	}
	for key, newResource := range newResourcesMap {
		groupKind := strings.SplitN(key, "/", 2)[0]
		if _, ok := forceGroupKinds[groupKind]; ok {
			if oldResource, ok := oldResourcesMap[key]; ok && oldResource == newResource {
				continue
			}
			return true, nil
		}
	}
	return false, nil
}
