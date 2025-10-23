package main

import (
	"errors"
	"fmt"
	stdlog "log"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/docker/libkv"
	"github.com/docker/libkv/store"
	"github.com/go-acme/lego/v4/challenge"
	legolog "github.com/go-acme/lego/v4/log"
	"github.com/go-acme/lego/v4/providers/dns"
	"github.com/project0/certjunkie/api"
	"github.com/project0/certjunkie/certstore"
	"github.com/project0/certjunkie/certstore/libkv/local"
	"github.com/project0/certjunkie/provider"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/urfave/cli/v2"
)

var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

const (
	ACME_STAGING = "https://acme-staging-v02.api.letsencrypt.org/directory"
	ACME         = "https://acme-v02.api.letsencrypt.org/directory"
	envPrefix    = "CJ"
)

var certStore *certstore.CertStore

func flagSetHelperEnvKey(name string) []string {
	envKey := strings.ToUpper(name)
	envKey = strings.ReplaceAll(envKey, "-", "_")
	return []string{envPrefix + "_" + envKey}
}

func main() {

	app := cli.NewApp()
	app.Version = fmt.Sprintf("%s %s %s", version, commit, date)
	app.Usage = "issue certificate with ACME as a REST"

	app.Flags = []cli.Flag{
		&cli.BoolFlag{
			Name:     "log.debug",
			Category: "log",
			Usage:    "Enable debug logs",
			EnvVars:  flagSetHelperEnvKey("LOG_DEBUG"),
		},
		&cli.StringFlag{
			Name:     "log.format",
			Category: "log",
			Usage:    "Log format (console,json)",
			Value:    "console",
			EnvVars:  flagSetHelperEnvKey("LOG_FORMAT"),
		},
	}
	app.Before = func(ctx *cli.Context) error {
		// Default level for this example is info, unless debug flag is present
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
		if ctx.Bool("log.debug") {
			zerolog.SetGlobalLevel(zerolog.DebugLevel)
		}

		// output format
		if ctx.String("log.format") == "console" {
			log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stdout})
		}

		// overwrite lego logger
		legolog.Logger = stdlog.New(
			log.With().Str("component", "lego").Logger(),
			"",
			0,
		)

		return nil
	}

	app.Commands = []*cli.Command{
		{
			Name:  "server",
			Usage: "run DNS and API server",

			Flags: []cli.Flag{
				&cli.StringFlag{
					Name:    "server",
					Value:   ACME,
					Usage:   "ACME Directory Resource URI",
					EnvVars: flagSetHelperEnvKey("SERVER"),
				},
				&cli.StringFlag{
					Name:    "email",
					Usage:   "Registration email for the ACME server",
					EnvVars: flagSetHelperEnvKey("EMAIL"),
				},
				&cli.StringFlag{
					Name:    "listen",
					Value:   ":80",
					Usage:   "Bind listener address for http (api) server",
					EnvVars: flagSetHelperEnvKey("LISTEN"),
				},
				&cli.StringFlag{
					Name:    "provider",
					Value:   provider.Name,
					Usage:   "DNS challenge provider name",
					EnvVars: flagSetHelperEnvKey("PROVIDER"),
				},
				&cli.StringFlag{
					Name:    "preferred-chain",
					Value:   "",
					Usage:   "If the CA offers multiple certificate chains, prefer the chain with an issuer matching this Subject Common Name. If no match, the default offered chain will be used.",
					EnvVars: flagSetHelperEnvKey("PREFERRED_CHAIN"),
				},
				&cli.StringFlag{
					Name:    "dns.listen",
					Value:   ":53",
					Usage:   "Bind on this port to run the DNS server on (tcp and udp)",
					EnvVars: flagSetHelperEnvKey("DNS_LISTEN"),
				},
				&cli.StringFlag{
					Name:    "dns.domain",
					Value:   "ns.local",
					Usage:   "The NS domain name of this server",
					EnvVars: flagSetHelperEnvKey("DNS_DOMAIN"),
				},
				&cli.StringFlag{
					Name:    "dns.zone",
					Value:   "acme.local",
					Usage:   "The zone we are using to provide the txt records for challenge",
					EnvVars: flagSetHelperEnvKey("DNS_ZONE"),
				},
				&cli.StringFlag{
					Name:    "storage",
					Value:   "local",
					Usage:   "Storage driver to use, currently only local is supported",
					EnvVars: flagSetHelperEnvKey("STORAGE"),
				},
				&cli.StringFlag{
					Name:    "storage.path",
					Value:   os.Getenv("HOME") + "/.certjunkie",
					Usage:   "Path to store the certs and account data for local storage driver",
					EnvVars: flagSetHelperEnvKey("STORAGE_PATH"),
				},
			},
			Action: func(c *cli.Context) error {
				email := c.String("email")
				challengeProvider := c.String("provider")
				if email == "" {
					log.Error().Str("email", email).Msg("you need to provide a valid email address")
					return errors.New("cannot initialize server")
				}

				local.Register()
				storage, err := libkv.NewStore(store.Backend(c.String("storage")), []string{}, &store.Config{
					Bucket: c.String("storage.path"),
				})
				if err != nil {
					log.Err(err).Msg("failed to initialize storage")
					return errors.New("cannot initialize server")
				}

				var dnsprovider challenge.Provider
				if challengeProvider == provider.Name {
					// use built in dns server for cname redirect
					dnsprovider = provider.NewDNSCnameChallengeProvider(c.String("dns.zone"), c.String("dns.domain"), c.String("dns.listen"))
				} else {
					// one of the shipped lego providers
					dnsprovider, err = dns.NewDNSChallengeProviderByName(challengeProvider)
					if err != nil {
						log.Err(err).Msg("failed to initialize DNS challenge provider")
						return errors.New("cannot initialize server")

					}
				}
				log.Debug().
					Str("provider", challengeProvider).
					Msg("initialize certificate store")

				certStore, err = certstore.NewCertStore(c.String("server"), email, dnsprovider, storage, c.String("preferred-chain"))
				if err != nil {
					log.Err(err).Msg("failed to initialize certificate storage")
					return errors.New("cannot initialize server")
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
				&cli.StringFlag{
					Name:    "address",
					Value:   "http://localhost:80",
					Usage:   "CertJunkie api address",
					EnvVars: flagSetHelperEnvKey("CLIENT_ADDRESS"),
				},
				&cli.StringFlag{
					Name:    "domain",
					Usage:   "Domain (common name) to obtain cert for, wildcard is allowed to use here",
					EnvVars: flagSetHelperEnvKey("CLIENT_DOMAIN"),
				},
				&cli.BoolFlag{
					Name:    "onlycn",
					Usage:   "Retrieve only certs where the common name is matching the domain",
					EnvVars: flagSetHelperEnvKey("CLIENT_ONLYCN"),
				},
				&cli.StringSliceFlag{
					Name:    "san",
					Usage:   "Additonal subject alternative names (domains) the cert must have",
					EnvVars: flagSetHelperEnvKey("CLIENT_SAN"),
				},
				&cli.IntFlag{
					Name:    "valid",
					Usage:   " How long needs the cert to be valid in days before requesting a new on",
					EnvVars: flagSetHelperEnvKey("CLIENT_VALID"),
				},
				&cli.StringFlag{
					Name:    "file.cert",
					Usage:   "Write certificate to file",
					EnvVars: flagSetHelperEnvKey("CLIENT_FILE_CERT"),
				},
				&cli.StringFlag{
					Name:    "file.ca",
					Usage:   "Write ca issuer to file",
					EnvVars: flagSetHelperEnvKey("CLIENT_FILE_CA"),
				},
				&cli.StringFlag{
					Name:    "file.key",
					Usage:   "Write private key to file",
					EnvVars: flagSetHelperEnvKey("CLIENT_FILE_KEY"),
				},
				&cli.StringFlag{
					Name:    "file.bundle",
					Usage:   "Write bundle (cert+ca) to file",
					EnvVars: flagSetHelperEnvKey("CLIENT_FILE_BUNDLE"),
				},
			},
			Action: func(c *cli.Context) error {
				domain := c.String("domain")
				if domain == "" {
					return errors.New("domain is not set")
				}

				client := &api.Client{
					Address: c.String("address"),
				}

				log.Info().
					Str("domain", domain).
					Strs("san", c.StringSlice("san")).
					Bool("onlycn", c.Bool("onlycn")).
					Int("valid", c.Int("valid")).
					Msg("request certificate")
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

	if err := app.Run(os.Args); err != nil {
		log.Fatal().Err(err).Msg("execution failed")
	}
}
