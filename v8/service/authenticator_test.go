package service

import (
	"testing"

	"github.com/jfjallid/gokrb5/v8/imported/goidentity/v6"
	"github.com/jfjallid/gokrb5/v8/imported/testify/assert"
)

func TestImplementsInterface(t *testing.T) {
	t.Parallel()
	//s := new(SPNEGOAuthenticator)
	var s KRB5BasicAuthenticator
	a := new(goidentity.Authenticator)
	assert.Implements(t, a, s, "SPNEGOAuthenticator type does not implement the goidentity.Authenticator interface")
}
