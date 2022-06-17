package api

import (
	"net/http"

	"github.com/rs/zerolog/log"

	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"

	"github.com/project0/certjunkie/certstore"
)

func NewApiServer(listen string, store *certstore.CertStore) {

	apiCert := apiCert{
		store: store,
	}

	r := mux.NewRouter()
	r.HandleFunc("/cert/{domain}", apiCert.getJson).Methods(http.MethodGet)
	r.HandleFunc("/cert/{domain}/cert", apiCert.getCert).Methods(http.MethodGet)
	r.HandleFunc("/cert/{domain}/ca", apiCert.getCA).Methods(http.MethodGet)
	r.HandleFunc("/cert/{domain}/key", apiCert.getKey).Methods(http.MethodGet)
	r.HandleFunc("/cert/{domain}/bundle", apiCert.getBundle).Methods(http.MethodGet)

	log.Info().Msgf("Start listening http server on %s", listen)
	go func() {
		err := http.ListenAndServe(listen, handlers.LoggingHandler(log.With().Str("component", "api_requests").Logger(), r))
		if err != nil {
			log.Fatal().Err(err).Msg("Failed to setup the http server")
		}
	}()
}
