//go:build !ignore_autogenerated
// +build !ignore_autogenerated

// Code generated by controller-gen. DO NOT EDIT.

package v1alpha1

import (
	"k8s.io/apimachinery/pkg/runtime"
)

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ConfigMapReference) DeepCopyInto(out *ConfigMapReference) {
	*out = *in
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ConfigMapReference.
func (in *ConfigMapReference) DeepCopy() *ConfigMapReference {
	if in == nil {
		return nil
	}
	out := new(ConfigMapReference)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ExposedSecret) DeepCopyInto(out *ExposedSecret) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	out.Spec = in.Spec
	in.Status.DeepCopyInto(&out.Status)
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ExposedSecret.
func (in *ExposedSecret) DeepCopy() *ExposedSecret {
	if in == nil {
		return nil
	}
	out := new(ExposedSecret)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *ExposedSecret) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ExposedSecretBuilder) DeepCopyInto(out *ExposedSecretBuilder) {
	*out = *in
	if in.ExposedSecret != nil {
		in, out := &in.ExposedSecret, &out.ExposedSecret
		*out = new(ExposedSecret)
		(*in).DeepCopyInto(*out)
	}
	if in.policy != nil {
		in, out := &in.policy, &out.policy
		*out = new(ScanPolicy)
		(*in).DeepCopyInto(*out)
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ExposedSecretBuilder.
func (in *ExposedSecretBuilder) DeepCopy() *ExposedSecretBuilder {
	if in == nil {
		return nil
	}
	out := new(ExposedSecretBuilder)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ExposedSecretList) DeepCopyInto(out *ExposedSecretList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		in, out := &in.Items, &out.Items
		*out = make([]ExposedSecret, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ExposedSecretList.
func (in *ExposedSecretList) DeepCopy() *ExposedSecretList {
	if in == nil {
		return nil
	}
	out := new(ExposedSecretList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *ExposedSecretList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ExposedSecretSpec) DeepCopyInto(out *ExposedSecretSpec) {
	*out = *in
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ExposedSecretSpec.
func (in *ExposedSecretSpec) DeepCopy() *ExposedSecretSpec {
	if in == nil {
		return nil
	}
	out := new(ExposedSecretSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ExposedSecretStatus) DeepCopyInto(out *ExposedSecretStatus) {
	*out = *in
	out.ConfigMapReference = in.ConfigMapReference
	if in.CreatedSecretRef != nil {
		in, out := &in.CreatedSecretRef, &out.CreatedSecretRef
		*out = new(SecretReference)
		**out = **in
	}
	in.LastUpdateTime.DeepCopyInto(&out.LastUpdateTime)
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ExposedSecretStatus.
func (in *ExposedSecretStatus) DeepCopy() *ExposedSecretStatus {
	if in == nil {
		return nil
	}
	out := new(ExposedSecretStatus)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ScanPolicy) DeepCopyInto(out *ScanPolicy) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	in.Status.DeepCopyInto(&out.Status)
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ScanPolicy.
func (in *ScanPolicy) DeepCopy() *ScanPolicy {
	if in == nil {
		return nil
	}
	out := new(ScanPolicy)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *ScanPolicy) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ScanPolicyList) DeepCopyInto(out *ScanPolicyList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		in, out := &in.Items, &out.Items
		*out = make([]ScanPolicy, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ScanPolicyList.
func (in *ScanPolicyList) DeepCopy() *ScanPolicyList {
	if in == nil {
		return nil
	}
	out := new(ScanPolicyList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *ScanPolicyList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ScanPolicySpec) DeepCopyInto(out *ScanPolicySpec) {
	*out = *in
	if in.ExcludedKeys != nil {
		in, out := &in.ExcludedKeys, &out.ExcludedKeys
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ScanPolicySpec.
func (in *ScanPolicySpec) DeepCopy() *ScanPolicySpec {
	if in == nil {
		return nil
	}
	out := new(ScanPolicySpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ScanPolicyStatus) DeepCopyInto(out *ScanPolicyStatus) {
	*out = *in
	in.LastProcessedTime.DeepCopyInto(&out.LastProcessedTime)
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ScanPolicyStatus.
func (in *ScanPolicyStatus) DeepCopy() *ScanPolicyStatus {
	if in == nil {
		return nil
	}
	out := new(ScanPolicyStatus)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *SecretReference) DeepCopyInto(out *SecretReference) {
	*out = *in
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new SecretReference.
func (in *SecretReference) DeepCopy() *SecretReference {
	if in == nil {
		return nil
	}
	out := new(SecretReference)
	in.DeepCopyInto(out)
	return out
}
