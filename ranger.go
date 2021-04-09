package ranger

import (
	"net"
	"net/url"
	"regexp"

	"github.com/projectdiscovery/chaos-middleware/iputil"
	"github.com/yl2chen/cidranger"
)

func init() {
	DefaultOptions.DenyList = append(DefaultOptions.DenyList, DefaultIPv4DenylistRanges...)
	DefaultOptions.DenyList = append(DefaultOptions.DenyList, DefaultIPv6Denylist...)
	DefaultOptions.DenyList = append(DefaultOptions.DenyList, DefaultIPv4DenylistRanges...)
	DefaultOptions.DenyList = append(DefaultOptions.DenyList, DefaultIPv6Denylist...)
	DefaultOptions.AllowSchemeList = append(DefaultOptions.DenyList, DefaultSchemeWhitelist...)
}

type Options struct {
	DenyList        []string
	AllowList       []string
	AllowSchemeList []string
	DenySchemeList  []string
}

// DefaultOptions is the base configuration for the validator
var DefaultOptions Options

type Ranger struct {
	DenyRanger      cidranger.Ranger
	AllowRanger     cidranger.Ranger
	AllowRules      map[string]*regexp.Regexp
	DenyRules       map[string]*regexp.Regexp
	AllowSchemeList map[string]struct{}
	DenySchemeList  map[string]struct{}
}

// New creates a new URL validator using the validator options
func New(options Options) (*Ranger, error) {
	allowSchemeList := make(map[string]struct{})
	for _, scheme := range options.AllowSchemeList {
		allowSchemeList[scheme] = struct{}{}
	}

	denySchemeList := make(map[string]struct{})
	for _, scheme := range options.DenySchemeList {
		denySchemeList[scheme] = struct{}{}
	}

	allowRules := make(map[string]*regexp.Regexp)
	denyRules := make(map[string]*regexp.Regexp)

	allowRanger := cidranger.NewPCTrieRanger()
	for _, r := range options.AllowList {
		// check if it's a regex
		if rgx, err := regexp.Compile(r); err == nil {
			allowRules[r] = rgx
			continue
		}

		// handle it as a cidr
		cidr, err := asCidr(r)
		if err != nil {
			return nil, err
		}

		if err := allowRanger.Insert(cidranger.NewBasicRangerEntry(*cidr)); err != nil {
			return nil, err
		}
	}

	denyRanger := cidranger.NewPCTrieRanger()
	for _, r := range options.DenyList {
		// check if it's a regex
		if rgx, err := regexp.Compile(r); err == nil {
			denyRules[r] = rgx
			continue
		}

		cidr, err := asCidr(r)
		if err != nil {
			return nil, err
		}

		if err := denyRanger.Insert(cidranger.NewBasicRangerEntry(*cidr)); err != nil {
			return nil, err
		}
	}

	return &Ranger{DenyRanger: denyRanger, AllowRanger: allowRanger, AllowSchemeList: allowSchemeList, DenySchemeList: denySchemeList, AllowRules: allowRules, DenyRules: denyRules}, nil
}

func (r Ranger) Validate(host string) bool {
	// check if it's an ip
	IP := net.ParseIP(host)
	if IP != nil {
		if r.DenyRanger != nil && rangerContains(r.DenyRanger, IP) {
			return false
		}

		if r.AllowRanger != nil {
			return rangerContains(r.AllowRanger, IP)
		}
	}

	// check if it's a valid URL
	URL, err := url.Parse(host)
	if err != nil {
		return false
	}

	var isSchemeInDenyList, isSchemeInAllowedList bool
	if r.DenySchemeList != nil {
		_, isSchemeInDenyList = r.DenySchemeList[URL.Scheme]
	}

	if r.AllowSchemeList != nil {
		_, isSchemeInAllowedList = r.AllowSchemeList[URL.Scheme]
	} else {
		isSchemeInAllowedList = true
	}

	// regex
	var isInDenyList, isInAllowedList bool
	for _, r := range r.DenyRules {
		if r.MatchString(host) {
			isInDenyList = true
			break
		}
	}
	if r.AllowRules != nil {
		for _, r := range r.AllowRules {
			if r.MatchString(host) {
				isInAllowedList = true
				break
			}
		}
	} else {
		isInAllowedList = true
	}

	return !isSchemeInDenyList && !isInDenyList && isInAllowedList && isSchemeInAllowedList
}

func (r Ranger) ValidateURLWithIP(host string, ip string) bool {
	return r.Validate(host) && r.ValidateAddress(ip)
}

func (r Ranger) ValidateAddress(IP string) bool {
	IPDest := net.ParseIP(IP)
	if IPDest == nil {
		return false
	}
	if r.DenyRanger != nil && rangerContains(r.DenyRanger, IPDest) {
		return false
	}

	if r.AllowRanger != nil {
		return rangerContains(r.AllowRanger, IPDest)
	}

	return true
}

func asCidr(s string) (*net.IPNet, error) {
	if iputil.IsIP(s) {
		s += "/32"
	}
	_, cidr, err := net.ParseCIDR(s)
	if err != nil {
		return nil, err
	}

	return cidr, nil
}

func rangerContains(ranger cidranger.Ranger, IP net.IP) bool {
	ok, err := ranger.Contains(IP)
	return ok && err == nil
}
