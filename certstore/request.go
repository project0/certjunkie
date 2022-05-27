package certstore

import (
	"strings"
	"time"

	"github.com/rs/zerolog/log"
)

// CertRequest contains information about the requested cert
type CertRequest struct {
	Domain     string   `json:"domain"`
	DomainIsCn bool     `json:"onlycn"`
	ValidDays  int      `json:"valid"`
	San        []string `json:"san"`
}

func (r *CertRequest) pathCert() string {
	return "certs/" + strings.ToLower(r.Domain) + ".json"
}

func (r *CertRequest) domains() []string {
	// First element in the list will get the common name
	return removeDuplicates(append([]string{r.Domain}, r.San...))
}

func (r *CertRequest) matchCertificate(cert *CertificateResource) (bool, error) {
	// First element in the list will get the common name

	certInfo, err := cert.parseCert()
	if err != nil {
		return false, err
	}

	matches := 0
	for _, host := range r.domains() {
		if certInfo.VerifyHostname(host) == nil {
			matches += 1
		}
	}

	if len(r.domains()) == matches {
		// seems to be the perfect cert
		validEndDay := time.Now().Add(time.Hour * time.Duration(24*r.ValidDays))
		if certInfo.NotAfter.After(validEndDay) {
			return true, nil
		}
		// cert is expired
		log.Printf("certificate is valid until %s but needs to be valid for %d days", certInfo.NotAfter, r.ValidDays)
		return false, nil
	}

	return false, nil
}

func removeDuplicates(elements []string) []string {
	// Use map to record duplicates as we find them.
	encountered := map[string]bool{}
	result := []string{}

	for v := range elements {
		if encountered[elements[v]] {
			// Do not add duplicate.
		} else {
			// Record this element as an encountered element.
			encountered[elements[v]] = true
			// Append to result slice.
			result = append(result, elements[v])
		}
	}
	// Return the new slice.
	return result
}
