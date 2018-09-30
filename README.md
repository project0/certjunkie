# CertJunkie

This project is inspired by [acme-dns](https://github.com/joohoi/acme-dns). While acme-dns is awesome to use with other acme clients, it lacks of capabilities of shared certs and anonymous usage.

I want to have a simple http server to create, challenge and receive my (lets encrypt) certs from an central point.
As it is intended to be used within an private and closed context, optional authentication and secured connection is currently not focused (fee free to create PR).

## Usage

```
server
--dns.domain string      The NS domain name of this server (default "ns.local")
--dns.listen string      Bind on this port to run the DNS server on (tcp and udp) (default ":53")
--dns.zone string        The zone we are using to provide the txt records for challenge (default "acme.local")
--email string           Registration email for the ACME server
--listen string          Bind on this port to run the API server on (default ":80")
--provider string        DNS challenge provider name (default "dnscname")
--server string          ACME Directory Resource URI (default "https://acme-v01.api.letsencrypt.org/directory")
--storage string         Storage driver to use, currently only local is supported (default "local")
--storage.local string   Path to store the certs and account data for local storage driver (default "$HOME/.certjunkie")

```

For combatible dns provdider look at https://github.com/xenolf/lego/tree/master/providers/dns

### Docker

[Image DockerHub](https://hub.docker.com/r/project0de/certjunkie)

```bash
docker run -ti -p 80:80 -p 53:53 -p 53:53/udp \
-v $(pwd)/certjunkie:/storage project0de/certjunkie \
server --storage.local /storage --email your@domain.com --dns.zone certjunkie.domain.com --dns.domain thisserver.domain.com
```

### Client

certjunkie has a built in client to write certificate easy to file.

```bash
certjunkie client --address "http://localhost:8080" --domain "my.domain.de" \
--file.cert my.domain.de.crt \
--file.key my.domain.de.key \
--file.ca my.domain.de.ca \
--file.bundle my.domain.de.bundle
```

### Client example with curl

```bash
curl http://localhost:8080/cert/my.domain.de/cert -Fo my.domain.de.crt && \
curl http://localhost:8080/cert/my.domain.de/key -Fo my.domain.de.key && \
curl http://localhost:8080/cert/my.domain.de/ca -Fo my.domain.de.ca
```

## `dnscname` DNS redirect with CNAME

This is actually `$challengeDomain.$dnsDomain.`.
Ensure the NS record is set to this server

### Example

Asume starting with `certjunkie server --dns.domain certjunkiens.example.com --dns.zone certjunkie.example.com --email your@registration.mail`

1. Delegate a subdomain to the server running certbot on your remote hosted DNS `example.com`:
```
certjunkiens A 1.1.1.1 300 # this should be A/AAAA record
certunkie NS certjunkiens.example.com # delegate zone to our built in nameserver
```

2. Setup certjunkie to start with his new authorative domain `certjunkie.example.com`

3. Forward the acme txt record for domains you would like to automate challenge:
```
_acme-challenge.yourdomain.com                CNAME yourdomain.com.certjunkie.example.com
_acme-challenge.www.yourdomain.com            CNAME www.yourdomain.com.certjunkie.example.com
_acme-challenge.service.cloud.yourdomain.com  CNAME service.cloud.yourdomain.com.certjunkie.example.com
```

## API

* `domain`: Get an cert which matches this domain.

### GET /cert/{domain}

Get JSON of an cert with CA and key
If the cert does not exist (or is not valid anymore) it will request a new one (sync).

#### Optional query parameters

* `san`: Comma separated list of subject alternative names the cert must have.
* `onlycn`: Get only a cert which matches the CommonName
* `valid`: How long needs the cert to be valid in days before requesting a new one. Defaults to 30

### GET /cert/{domain}/cert

Retrieve only the certificate pem encoded.

### GET /cert/{domain}/ca

Retrieve only the Issuer Certificate (CA) pem encoded.

### GET /cert/{domain}/bundle

Retrieve bundled cert with ca pem encoded.

### GET /cert/{domain}/key

Retrieve the private key pem encoded.
