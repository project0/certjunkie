package api

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/project0/certjunkie/certstore"
)

// Client talks with the API
type Client struct {
	Address string
}

// Get retrieves the cert, private key and ca bundle
func (c *Client) Get(domain string, san []string, onlyCN bool, valid int) (cert *certstore.CertificateResource, err error) {

	var (
		resp *http.Response
		u    *url.URL
	)
	client := http.DefaultClient

	u, err = url.Parse(c.Address + "/cert/" + domain)
	if err != nil {
		return
	}

	// Add queries
	q := u.Query()
	if onlyCN {
		q.Set("onlycn", "1")
	}
	if valid != 0 {
		q.Set("valid", strconv.Itoa(valid))
	}
	if len(san) > 0 {
		q.Set("san", strings.Join(san, ","))
	}
	u.RawQuery = q.Encode()

	resp, err = client.Get(u.String())
	if err != nil {
		return
	}

	if resp.StatusCode != http.StatusOK {
		respBody, _ := ioutil.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to retrieve cert: %s", string(respBody))
	}

	cert = &certstore.CertificateResource{}
	err = json.NewDecoder(resp.Body).Decode(cert)
	return
}

// WriteCert writes the cert to file
func (c *Client) WriteCert(cert *certstore.CertificateResource, filepath string) (err error) {
	return c.writeFile(cert.GetNoBundleCertificate(), filepath)
}

// WriteBundle writes the cert + ca to file
func (c *Client) WriteBundle(cert *certstore.CertificateResource, filepath string) (err error) {
	return c.writeFile(append(cert.GetNoBundleCertificate(), cert.IssuerCertificate...), filepath)
}

// WriteKey writes the private key to file
func (c *Client) WriteKey(cert *certstore.CertificateResource, filepath string) (err error) {
	return c.writeFile(cert.PrivateKey, filepath)
}

// WriteCA writes the ca chain to file
func (c *Client) WriteCA(cert *certstore.CertificateResource, filepath string) (err error) {
	return c.writeFile(cert.IssuerCertificate, filepath)
}

func (c *Client) writeFile(data []byte, filepath string) error {
	return ioutil.WriteFile(filepath, data, 0644)
}
