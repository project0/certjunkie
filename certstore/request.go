package certstore

import "strings"

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

func removeDuplicates(elements []string) []string {
	// Use map to record duplicates as we find them.
	encountered := map[string]bool{}
	result := []string{}

	for v := range elements {
		if encountered[elements[v]] == true {
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
