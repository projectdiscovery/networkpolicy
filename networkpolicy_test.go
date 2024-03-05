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

func TestMultipleCases(t *testing.T) {
	var testCases = []struct {
		address       string
		expectedValid bool
	}{
		{"projectdiscovery.io", false},
		{"projectdiscovery.io:80", false},
		{"http://scanme.sh", false},
		{"scanme.sh:8080", true},
	}

	var npOptions Options
	npOptions.DenyList = append(npOptions.DenyList,
		"projectdiscovery.io",
		"projectdiscovery.io:80",
		"http://scanm.\\.sh",
		"honey\\.scanme\\.sh",
	)

	np, err := New(npOptions)
	if err != nil {
		log.Fatal(err)
	}

	for _, tc := range testCases {
		ok := np.Validate(tc.address)
		require.Equal(t, tc.expectedValid, ok, "Unexpected result for address: "+tc.address)
	}
}
