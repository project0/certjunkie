package certstore

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"log"
	"sync"

	"github.com/docker/libkv/store"
	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/registration"
)

type User struct {
	Email        string                 `json:"email"`
	Registration *registration.Resource `json:"registration"`
	Key          []byte                 `json:"key"`
}

func (u User) GetEmail() string {
	return u.Email
}

func (u User) GetRegistration() *registration.Resource {
	return u.Registration
}

func (u User) GetPrivateKey() crypto.PrivateKey {
	key, err := x509.ParsePKCS1PrivateKey(u.Key)
	if err != nil {
		log.Fatal("Could not decode stored user private key")
	}
	return key
}

type CertStore struct {
	user           *User
	email          string
	preferredChain string
	client         *lego.Client
	sync           *sync.Mutex
	storage        store.Store
}

func NewCertStore(acmeDirectory string, email string, challengeProvider challenge.Provider, storage store.Store, preferredChain string) (*CertStore, error) {
	var err error
	cs := &CertStore{
		sync:           &sync.Mutex{},
		email:          email,
		storage:        storage,
		preferredChain: preferredChain,
	}

	// ensure we have a user
	cs.user, err = cs.GetUser()
	if err != nil {
		return nil, err
	}
	// ensure we can write stuff to the storage
	err = cs.SaveUser(cs.user)
	if err != nil {
		return nil, err
	}

	config := lego.NewConfig(cs.user)
	config.CADirURL = acmeDirectory
	config.Certificate.KeyType = certcrypto.RSA4096

	cs.client, err = lego.NewClient(config)
	if err != nil {
		return nil, err
	}
	// we support only dns challenges
	// set our own dns provider
	cs.client.Challenge.SetDNS01Provider(challengeProvider)

	return cs, nil
}

func (c *CertStore) GetUser() (*User, error) {

	fileUser, err := c.storage.Get("user.json")
	if err != nil {
		//seems not to exist, create new
		const rsaKeySize = 4096
		privateKey, err := rsa.GenerateKey(rand.Reader, rsaKeySize)
		if err != nil {
			return nil, err
		}

		return &User{
			Email: c.email,
			Key:   x509.MarshalPKCS1PrivateKey(privateKey),
		}, nil
	}

	user := &User{}
	json.Unmarshal(fileUser.Value, user)
	return user, err
}

func (c *CertStore) SaveUser(user registration.User) error {
	jsonContent, err := json.Marshal(user)
	if err != nil {
		return err
	}
	return c.storage.Put("user.json", jsonContent, nil)
}

// GetCertificate retrieves an certificate from acme or storage
func (c *CertStore) GetCertificate(request *CertRequest) (*CertificateResource, error) {
	// Block this request until we got a cert.
	// This may not perfect but prevents simple concurrent requests to acme servers.
	// Note: If we want to have concurrency lock between different processes/instances this need to be done by storage level.
	c.sync.Lock()
	defer c.sync.Unlock()

	var (
		err  error
		cert *CertificateResource
	)

	// check if cert exists in storage and return
	if request.DomainIsCn {
		cert, err = c.getStoredCertByCN(request)
	} else {
		cert, err = c.findStoredCert(request)
	}

	if err != nil && err != store.ErrKeyNotFound {
		// unhandled errors from the storage
		return nil, err
	}
	if cert != nil {
		// validation is already checked
		return cert, nil
	}

	// continue with creating a new one

	// check user first....
	if c.user.Registration == nil {
		log.Println("New Registration of user", c.client)
		reg, err := c.client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
		if err != nil {
			log.Println(err)
			return nil, err
		}
		// save this
		c.user.Registration = reg
		if err := c.SaveUser(c.user); err != nil {
			log.Printf("could not save user registration %v", err)
			return nil, err
		}
	}

	req := certificate.ObtainRequest{
		Domains:        request.domains(),
		Bundle:         false,
		PrivateKey:     nil,
		MustStaple:     false,
		PreferredChain: c.preferredChain,
	}
	acmeCerts, err := c.client.Certificate.Obtain(req)
	if err != nil {
		return nil, err
	}

	// create our own cert resource
	cert = &CertificateResource{
		Domain:            acmeCerts.Domain,
		PrivateKey:        acmeCerts.PrivateKey,
		Certificate:       acmeCerts.Certificate,
		IssuerCertificate: acmeCerts.IssuerCertificate,
	}

	// save
	val, _ := json.Marshal(cert)
	err = c.storage.Put(request.pathCert(), val, nil)
	if err != nil {
		log.Printf("could not save cert for %s to storage %v", request.Domain, err)
	}

	return cert, nil
}

func (c *CertStore) getStoredCertByCN(r *CertRequest) (*CertificateResource, error) {
	pair, err := c.storage.Get(r.pathCert())
	if err != nil {
		return nil, err
	}

	cert := new(CertificateResource)
	if err := json.Unmarshal(pair.Value, cert); err != nil {
		return nil, err
	}
	ok, err := r.matchCertificate(cert)
	if !ok || err != nil {
		return nil, err
	}
	return cert, nil
}

func (c *CertStore) findStoredCert(r *CertRequest) (*CertificateResource, error) {
	list, err := c.storage.List("certs/")
	if err != nil {
		return nil, err
	}

	for _, pair := range list {
		cert := new(CertificateResource)
		if err := json.Unmarshal(pair.Value, cert); err != nil {
			log.Printf("Could not decode json from %s", pair.Key)
			continue
		}

		ok, err := r.matchCertificate(cert)
		if err != nil {
			log.Print(err)
			continue
		}
		if ok {
			return cert, nil
		}

	}
	return nil, nil
}
