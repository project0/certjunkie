package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/gorilla/mux"

	"github.com/project0/certjunkie/certstore"
)

type apiCert struct {
	store *certstore.CertStore
}

// certRequest obtains a cert from the certstore
func (a *apiCert) certRequest(w http.ResponseWriter, r *http.Request) *certstore.CertificateResource {
	var err error
	vars := mux.Vars(r)
	if vars["domain"] == "" {
		http.Error(w, fmt.Sprintf("Domain name %q is not valid", vars["domain"]), http.StatusBadRequest)
		return nil
	}
	query := r.URL.Query()
	cr := certstore.CertRequest{
		Domain:    vars["domain"],
		ValidDays: 30,
	}

	if query.Get("onlycn") != "" {
		cr.DomainIsCn = true
	}

	if query.Get("valid") != "" {
		cr.ValidDays, err = strconv.Atoi(query.Get("valid"))
		if err != nil {
			http.Error(w, fmt.Sprintf("Invalid value for parameter valid: %v", err), http.StatusBadRequest)
			return nil
		}
	}

	if query.Get("san") != "" {
		cr.San = strings.Split(query.Get("san"), ",")
	}

	cert, err := a.store.GetCertificate(&cr)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return nil
	}

	return cert
}

func (a *apiCert) getJson(w http.ResponseWriter, r *http.Request) {
	cert := a.certRequest(w, r)
	if cert == nil {
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(cert)
}

func (a *apiCert) getCert(w http.ResponseWriter, r *http.Request) {
	cert := a.certRequest(w, r)
	if cert == nil {
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Write(cert.GetNoBundleCertificate())
}

func (a *apiCert) getCA(w http.ResponseWriter, r *http.Request) {
	cert := a.certRequest(w, r)
	if cert == nil {
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Write(cert.IssuerCertificate)
}

func (a *apiCert) getKey(w http.ResponseWriter, r *http.Request) {
	cert := a.certRequest(w, r)
	if cert == nil {
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Write(cert.PrivateKey)
}

func (a *apiCert) getBundle(w http.ResponseWriter, r *http.Request) {
	cert := a.certRequest(w, r)
	if cert == nil {
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Write(append(cert.GetNoBundleCertificate(), cert.IssuerCertificate...))
}
