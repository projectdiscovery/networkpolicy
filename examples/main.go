package main

import (
	"crypto/tls"
	"errors"
	"log"
	"net/http"
	"net/http/httputil"

	"github.com/projectdiscovery/networkpolicy"
)

func main() {
	var npOptions networkpolicy.Options
	// deny connections to localhost
	npOptions.DenyList = append(npOptions.DenyList, "127.0.0.0/8")

	np, err := networkpolicy.New(npOptions)
	if err != nil {
		log.Fatal(err)
	}

	customRedirectHandler := func(req *http.Request, via []*http.Request) error {
		// if at least one address is valid we follow the redirect
		if _, ok := np.ValidateHost(req.Host); ok {
			return nil
		}
		return errors.New("redirected to a forbidden target")
	}

	client := &http.Client{
		CheckRedirect: customRedirectHandler,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}
	req, err := http.NewRequest(http.MethodGet, "https://scanme.sh", nil)
	if err != nil {
		log.Fatal(err)
	}
	resp, err := client.Do(req)
	if err != nil {
		log.Fatal(err)
	}

	bin, err := httputil.DumpResponse(resp, true)

	if err != nil {
		log.Fatal(err)
	}

	log.Println(string(bin))
}
