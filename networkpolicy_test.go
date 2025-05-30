package networkpolicy

import (
	"log"
	"net"
	"net/netip"
	"regexp"
	"testing"

	"github.com/gaissmai/bart"
	"github.com/stretchr/testify/require"
	"github.com/yl2chen/cidranger"
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

func Test_ValidateV6Address(t *testing.T) {
	np, err := New(DefaultOptions)
	if err != nil {
		log.Fatal(err)
	}

	ok := np.ValidateAddress("::1")
	require.Equal(t, false, ok, "IPv6 localhost should be denied")

	ok = np.ValidateAddress("2404:6800:4002:81c::200e")
	require.Equal(t, true, ok, "Non-localhost IPv6 should be allowed")

	t.Run("validate", func(t *testing.T) {
		ok := np.Validate("::1")
		require.Equal(t, false, ok, "IPv6 localhost should be denied")
	})
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

func Benchmark_Networkpolicy_CIDRRanger(b *testing.B) {
	for i := 0; i < b.N; i++ {
		ranger := cidranger.NewPCTrieRanger()
		for _, r := range DefaultIPv4DenylistRanges {
			_, cidr, _ := net.ParseCIDR(r)
			_ = ranger.Insert(cidranger.NewBasicRangerEntry(*cidr))
		}
		contains, err := ranger.Contains(net.ParseIP("127.0.0.1"))
		if err != nil || !contains {
			b.Fatalf("unexpected error: %v %v", err, contains)
		}
	}
}

func Benchmark_Networkpolicy_BartAlgorithm(b *testing.B) {
	for i := 0; i < b.N; i++ {
		rtbl := new(bart.Table[net.IP])
		for _, r := range DefaultIPv4DenylistRanges {
			parsed, _ := netip.ParsePrefix(r)
			rtbl.Insert(parsed, nil)
		}

		_, contains := rtbl.Lookup(netip.MustParseAddr("127.0.0.1"))
		if !contains {
			b.Fatalf("expected to contain")
		}
	}
}

func TestDefaultOptionsContent(t *testing.T) {
	for _, scheme := range DefaultOptions.AllowSchemeList {
		require.True(t, schemePattern.MatchString(scheme), "Scheme %s doesn't match expected pattern protocol://", scheme)
	}

	// Test deny list entries are either valid IPs, CIDRs, or compilable regexes
	for _, entry := range DefaultOptions.DenyList {
		// Try parsing as IP
		if ip := net.ParseIP(entry); ip != nil {
			continue
		}

		// Try parsing as CIDR
		if _, _, err := net.ParseCIDR(entry); err == nil {
			continue
		}

		// Try compiling as regex
		if _, err := regexp.Compile(entry); err != nil {
			t.Errorf("Entry in DenyList is neither a valid IP, CIDR, nor a valid regex: %s", entry)
		}
	}
}
