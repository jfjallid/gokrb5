package goidentity

import (
	"github.com/jfjallid/gokrb5/v8/imported/testify/assert"
	"testing"
)

func TestUserImplementsInterface(t *testing.T) {
	u := new(User)
	assert.Implements(t, (*Identity)(nil), u, "User type does not implement the Identity interface")
}
