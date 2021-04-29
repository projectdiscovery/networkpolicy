package networkpolicy

import (
	"log"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestValidateAddress(t *testing.T) {
	var npOptions Options
	npOptions.DenyList = append(npOptions.DenyList, "127.0.0.0/8")
	np, err := New(npOptions)
	if err != nil {
		log.Fatal(err)
	}
	ok := np.ValidateAddress("127.0.0.1")
	require.Equal(t, false, ok, "Unexpected positive result")
	ok = np.ValidateAddress("192.168.1.1")
	require.Equal(t, true, ok, "Unexpected negative result")
}
