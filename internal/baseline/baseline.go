// Package baseline provides a mechanism for applying baseline overrides to Go structs
package baseline

import "reflect"

// Apply applies a baseline to the destination struct.
// It sets any fields in the destination struct that are not set to their zero value.
// Only directly exported fields are considered.
func Apply[T any](dst, src *T) {
	var (
		dstVal = reflect.ValueOf(dst).Elem()
		srcVal = reflect.ValueOf(src).Elem()
	)

	for i := range dstVal.NumField() {
		var (
			dstField = dstVal.Field(i)
			srcField = srcVal.Field(i)
		)

		if !dstField.CanSet() || !dstField.IsZero() {
			continue
		}

		dstField.Set(srcField)
	}
}
