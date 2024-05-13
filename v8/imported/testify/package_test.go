package testify

import (
	"testing"

	"github.com/jfjallid/gokrb5/v8/imported/testify/assert"
)

func TestImports(t *testing.T) {
	if assert.Equal(t, 1, 1) != true {
		t.Error("Something is wrong.")
	}
}
