package test

import (
	"fmt"
	"reflect"

	"github.com/stretchr/testify/require"
)

// AssertMatchesNonZeroFields compares two values and checks if they match.
// It ignores zero values in the "want" value.
func AssertMatchesNonZeroFields(t require.TestingT, want, got any) {
	if t, ok := t.(interface{ Helper() }); ok {
		t.Helper()
	}
	compareValue(t, reflect.ValueOf(want), reflect.ValueOf(got), reflect.TypeOf(want).Name())
}

// compareValue will descend into structs, slices, maps and pointers.
// Whenever a field in want is its zero‑value, it’s skipped.
func compareValue(t require.TestingT, want, got reflect.Value, path string) {
	// if want is not even present, nothing to compare
	if !want.IsValid() {
		return
	}

	// handle pointer
	if want.Kind() == reflect.Pointer {
		if want.IsNil() {
			return
		}
		require.False(t, got.IsNil(), "pointer at %s: got nil, want non-nil", path)
		compareValue(t, want.Elem(), got.Elem(), path)
		return
	}

	switch want.Kind() {
	case reflect.Struct:
		for i := range want.NumField() {
			field := want.Type().Field(i)
			wantField := want.Field(i)
			// skip zero‑value in want
			if reflect.DeepEqual(wantField.Interface(), reflect.Zero(wantField.Type()).Interface()) {
				continue
			}
			gotField := got.FieldByName(field.Name)
			compareValue(t, wantField, gotField, join(path, field.Name))
		}

	case reflect.Slice, reflect.Array:
		if want.Len() == 0 {
			return
		}
		require.Equal(t, want.Len(), got.Len(), "length mismatch at %s", path)
		for i := range want.Len() {
			compareValue(t, want.Index(i), got.Index(i), fmt.Sprintf("%s[%d]", path, i))
		}

	case reflect.Map:
		if want.Len() == 0 {
			return
		}
		for _, key := range want.MapKeys() {
			wantVal := want.MapIndex(key)
			var gotVal reflect.Value
			require.NotPanics(t, func() {
				gotVal = got.MapIndex(key)
			}, "error accessing map key %v at %s", key, path)
			require.True(t, gotVal.IsValid(), "missing map key %v at %s", key, path)
			compareValue(t, wantVal, gotVal, fmt.Sprintf("%s[%v]", path, key))
		}

	default:
		// basic kinds: int, string, bool, etc.
		require.Equal(t, want.Interface(), got.Interface(), "value mismatch at %s", path)
	}
}

func join(prefix, field string) string {
	if prefix == "" {
		return field
	}
	return prefix + "." + field
}
