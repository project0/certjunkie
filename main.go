package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/docker/libkv"
	"github.com/docker/libkv/store"
	"github.com/project0/certjunkie/api"
	"github.com/project0/certjunkie/certstore"
	"github.com/project0/certjunkie/certstore/libkv/local"
	"github.com/project0/certjunkie/provider"
	"github.com/urfave/cli"
	"github.com/xenolf/lego/acme"
	"github.com/xenolf/lego/providers/dns"
)

const ACME_STAGING = "https://acme-staging-v02.api.letsencrypt.org/directory"
const ACME = "https://acme-v02.api.letsencrypt.org/directory"

const envPrefix = "CJ"

var certStore *certstore.CertStore

func flagSetHelperEnvKey(name string) string {
	envKey := strings.ToUpper(name)
	envKey = strings.Replace(envKey, "-", "_", -1)
	return envPrefix + "_" + envKey
}

func main() {

	app := cli.NewApp()
	app.HideVersion = true

	app.Commands = []cli.Command{
		{
			Name:        "server",
			Description: "run DNS and API server",
			Flags: []cli.Flag{
				cli.StringFlag{
					Name:   "server",
					Value:  ACME,
					Usage:  "ACME Directory Resource URI",
					EnvVar: flagSetHelperEnvKey("SERVER"),
				},
				cli.StringFlag{
					Name:   "email",
					Usage:  "Registration email for the ACME server",
					EnvVar: flagSetHelperEnvKey("EMAIL"),
				},
				cli.StringFlag{
					Name:   "listen",
					Value:  ":80",
					Usage:  "Bind listener address for http (api) server",
					EnvVar: flagSetHelperEnvKey("LISTEN"),
				},
				cli.StringFlag{
					Name:   "provider",
					Value:  provider.Name,
					Usage:  "DNS challenge provider name",
					EnvVar: flagSetHelperEnvKey("PROVIDER"),
				},
				cli.StringFlag{
					Name:   "dns.listen",
					Value:  ":53",
					Usage:  "Bind on this port to run the DNS server on (tcp and udp)",
					EnvVar: flagSetHelperEnvKey("DNS_LISTEN"),
				},
				cli.StringFlag{
					Name:   "dns.domain",
					Value:  "ns.local",
					Usage:  "The NS domain name of this server",
					EnvVar: flagSetHelperEnvKey("DNS_DOMAIN"),
				},
				cli.StringFlag{
					Name:   "dns.zone",
					Value:  "acme.local",
					Usage:  "The zone we are using to provide the txt records for challenge",
					EnvVar: flagSetHelperEnvKey("DNS_ZONE"),
				},
				cli.StringFlag{
					Name:   "storage",
					Value:  "local",
					Usage:  "Storage driver to use, currently only local is supported",
					EnvVar: flagSetHelperEnvKey("STORAGE"),
				},
				cli.StringFlag{
					Name:   "storage.path",
					Value:  os.Getenv("HOME") + "/.certjunkie",
					Usage:  "Path to store the certs and account data for local storage driver",
					EnvVar: flagSetHelperEnvKey("STORAGE_PATH"),
				},
			},
			Action: func(c *cli.Context) error {
				email := c.String("email")
				challengeProvider := c.String("provider")
				if email == "" {
					return fmt.Errorf("Email is not set")
				}

				local.Register()
				storage, err := libkv.NewStore(store.Backend(c.String("storage")), []string{}, &store.Config{
					Bucket: c.String("storage.path"),
				})
				if err != nil {
					log.Fatal(err)
				}

				var dnsprovider acme.ChallengeProvider
				if challengeProvider == provider.Name {
					// use built in dns server for cname redirect

					dnsprovider = provider.NewDNSCnameChallengeProvider(c.String("dns.zone"), c.String("dns.domain"), c.String("dns.listen"))
				} else {
					// one of the shipped lego providers
					dnsprovider, err = dns.NewDNSChallengeProviderByName(challengeProvider)
					if err != nil {
						log.Fatal(err)
					}
				}

				certStore, err = certstore.NewCertStore(c.String("server"), email, &dnsprovider, storage)
				if err != nil {
					log.Fatal(err)
				}

				api.NewApiServer(c.String("listen"), certStore)
				sigs := make(chan os.Signal, 1)
				signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
				<-sigs
				storage.Close()

				return nil
			},
		},
		{
			Name:        "client",
			Description: "client to retrieve cert bundle from an certjunkie api",
			Flags: []cli.Flag{
				cli.StringFlag{
					Name:   "address",
					Value:  "http://localhost:80",
					Usage:  "CertJunkie api address",
					EnvVar: flagSetHelperEnvKey("CLIENT_ADDRESS"),
				},
				cli.StringFlag{
					Name:   "domain",
					Usage:  "Domain (common name) to obtain cert for, wildcard is allowed to use here",
					EnvVar: flagSetHelperEnvKey("CLIENT_DOMAIN"),
				},
				cli.BoolFlag{
					Name:   "onlycn",
					Usage:  "Retrieve only certs where the common name is matching the domain",
					EnvVar: flagSetHelperEnvKey("CLIENT_ONLYCN"),
				},
				cli.StringSliceFlag{
					Name:   "san",
					Usage:  "Additonal subject alternative names (domains) the cert must have",
					EnvVar: flagSetHelperEnvKey("CLIENT_SAN"),
				},
				cli.IntFlag{
					Name:   "valid",
					Usage:  " How long needs the cert to be valid in days before requesting a new on",
					EnvVar: flagSetHelperEnvKey("CLIENT_VALID"),
				},
				cli.StringFlag{
					Name:   "file.cert",
					Usage:  "Write certificate to file",
					EnvVar: flagSetHelperEnvKey("CLIENT_FILE_CERT"),
				},
				cli.StringFlag{
					Name:   "file.ca",
					Usage:  "Write ca issuer to file",
					EnvVar: flagSetHelperEnvKey("CLIENT_FILE_CA"),
				},
				cli.StringFlag{
					Name:   "file.key",
					Usage:  "Write private key to file",
					EnvVar: flagSetHelperEnvKey("CLIENT_FILE_KEY"),
				},
				cli.StringFlag{
					Name:   "file.bundle",
					Usage:  "Write bundle (cert+ca) to file",
					EnvVar: flagSetHelperEnvKey("CLIENT_FILE_BUNDLE"),
				},
			},
			Action: func(c *cli.Context) error {
				domain := c.String("domain")
				if domain == "" {
					return fmt.Errorf("Domain is not set")
				}

				client := &api.Client{
					Address: c.String("address"),
				}

				cert, err := client.Get(domain, c.StringSlice("san"), c.Bool("onlycn"), c.Int("valid"))
				if err != nil {
					return err
				}

				// write result to files
				fileCert := c.String("file.cert")
				fileCA := c.String("file.ca")
				fileKey := c.String("file.key")
				fileBundle := c.String("file.bundle")
				if fileCert != "" {
					err := client.WriteCert(cert, fileCert)
					if err != nil {
						return err
					}
				}
				if fileCA != "" {
					err := client.WriteCA(cert, fileCA)
					if err != nil {
						return err
					}
				}
				if fileKey != "" {
					err := client.WriteKey(cert, fileKey)
					if err != nil {
						return err
					}
				}
				if fileBundle != "" {
					err := client.WriteBundle(cert, fileBundle)
					if err != nil {
						return err
					}
				}

				return nil
			},
		},
	}

	app.RunAndExitOnError()

}
