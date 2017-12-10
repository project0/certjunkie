package main

import (
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/docker/libkv"
	"github.com/docker/libkv/store"
	"github.com/spf13/pflag"
	"github.com/xenolf/lego/acme"
	"github.com/xenolf/lego/providers/dns"

	"github.com/project0/certjunkie/api"
	"github.com/project0/certjunkie/certstore"
	"github.com/project0/certjunkie/certstore/libkv/local"
	"github.com/project0/certjunkie/provider"
)

const ACME_STAGING = "https://acme-staging.api.letsencrypt.org/directory"
const ACME = "https://acme-v01.api.letsencrypt.org/directory"

var certStore *certstore.CertStore

func main() {
	AcmeServer := pflag.String("server", ACME, "ACME Directory Resource URI")
	Email := pflag.String("email", "", "Registration email for the ACME server")
	ApiListen := pflag.String("listen", ":80", "Bind on this port to run the API server on")
	ChallengeProvider := pflag.String("provider", "dnscname", "DNS challenge provider name")
	DnsListen := pflag.String("dns.listen", ":53", "Bind on this port to run the DNS server on (tcp and udp)")
	DnsDomain := pflag.String("dns.domain", "ns.local", "The NS domain name of this server")
	DnsZone := pflag.String("dns.zone", "acme.local", "The zone we are using to provide the txt records for challenge")
	StorageDriver := pflag.String("storage", "local", "Storage driver to use, currently only local is supported")
	StorageLocalPath := pflag.String("storage.local", os.Getenv("HOME")+"/.certjunkie", "Path to store the certs and account data for local storage driver")
	pflag.Parse()

	if *Email == "" {
		log.Fatal("Email is not set")
	}
	if *DnsDomain == "" {
		log.Fatal("DNS Domain is not set")
	}
	if *DnsZone == "" {
		log.Fatal("Dns Zone is not set")
	}
	if *DnsZone == "" {
		log.Fatal("Dns Zone is not set")
	}

	local.Register()
	storage, err := libkv.NewStore(store.Backend(*StorageDriver), []string{}, &store.Config{
		Bucket: *StorageLocalPath,
	})
	if err != nil {
		log.Fatal(err)
	}

	var dnsprovider acme.ChallengeProvider
	if *ChallengeProvider == "dnscname" {
		// use built in dns server for cname redirect
		dnsprovider = provider.NewDNSCnameChallengeProvider(*DnsZone, *DnsDomain, *DnsListen)
	} else {
		// one of the shipped lego providers
		dnsprovider, err = dns.NewDNSChallengeProviderByName(*ChallengeProvider)
		if err != nil {
			log.Fatal(err)
		}
	}

	certStore, err = certstore.NewCertStore(*AcmeServer, *Email, &dnsprovider, storage)
	if err != nil {
		log.Fatal(err)
	}

	api.NewApiServer(*ApiListen, certStore)
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	<-sigs
	storage.Close()
}
