package baseline

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

type TestStruct struct {
	//nolint:unused
	unexportedField string

	Field1         string
	Field2, Field3 int
	Field4         bool
	Field5         []string
	Field6         map[string]string
	Field7         any
	Field8         *TestStruct
}

func TestApply(t *testing.T) {
	t.Parallel()

	baseline := &TestStruct{
		Field1: "foo",
		Field2: 1,
		Field3: 2,
		Field4: true,
		Field5: []string{"a", "b", "c"},
		Field6: map[string]string{"a": "b", "c": "d"},
		Field7: "bar",
	}

	target := &TestStruct{
		Field1: "bar",
		Field3: 3,
	}

	Apply(target, baseline)

	assert.Equal(t, "bar", target.Field1)
	assert.Equal(t, 1, target.Field2)
	assert.Equal(t, 3, target.Field3)

	target.Field6["a"] = "z"

	assert.Equal(t, "b", baseline.Field6["a"])
}
