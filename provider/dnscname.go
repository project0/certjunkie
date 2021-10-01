package provider

import (
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.com/miekg/dns"
)

const Name = "dnscname"

var ChallengeLocker = make(map[string]*sync.Mutex)
var ChallengeRecord = make(map[string]*dns.TXT)

// DnsCnameProviderAcme is an acme.ChallengeProvider with built in dns server
// to answer acme challenges which has been redirect with an cname
type DnsCnameProviderAcme struct {
	Zone     string
	Nsdomain string
}

// NewDNSCnameChallengeProvider creates an dns server and returns an challenge provider for the acme library
func NewDNSCnameChallengeProvider(zone string, nsdomain string, listen string) challenge.Provider {
	provider := &DnsCnameProviderAcme{
		Zone:     zone,
		Nsdomain: nsdomain,
	}
	// start the internal dns server
	dns.HandleFunc(zone+".", provider.handleDnsRequests)
	log.Printf("Start listening DNS server on %s", listen)
	go serveDns("tcp", listen)
	go serveDns("udp", listen)
	return provider
}

// Present implements the interface for acme.ChallengeProvider
func (d *DnsCnameProviderAcme) Present(domain, token, keyAuth string) error {
	getChallengeLock(domain).Lock()
	// ignore domain, we have a cname on it
	_, value := dns01.GetRecord(domain, keyAuth)

	cd := d.getChallengeDomainName(domain)
	rr := new(dns.TXT)
	rr.Hdr = dns.RR_Header{Name: cd, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: uint32(1)}
	rr.Txt = []string{value}

	ChallengeRecord[cd] = rr
	return nil
}

// CleanUp implements the interface for acme.ChallengeProvider
func (d *DnsCnameProviderAcme) CleanUp(domain, token, keyAuth string) error {
	cd := d.getChallengeDomainName(domain)

	delete(ChallengeRecord, cd)
	getChallengeLock(domain).Unlock()
	return nil
}

func (d *DnsCnameProviderAcme) getChallengeDomainName(domain string) string {
	return fmt.Sprintf("%s.%s.", domain, d.Zone)
}

func getChallengeLock(domain string) *sync.Mutex {
	if s, ok := ChallengeLocker[domain]; ok {
		return s
	}
	s := &sync.Mutex{}
	ChallengeLocker[domain] = s
	return s
}

func (d *DnsCnameProviderAcme) handleDnsRequests(w dns.ResponseWriter, r *dns.Msg) {
	// BIND does not support answering multiple questions so we won't
	if len(r.Question) != 1 {
		m := new(dns.Msg)
		m.SetReply(r)
		m.SetRcodeFormatError(r)
		w.WriteMsg(m)
		return
	}
	question := r.Question[0]
	qname := strings.ToLower(question.Name)
	log.Print(question)
	// is not part of the domain
	if !strings.HasSuffix(qname, d.Zone+".") {
		m := new(dns.Msg)
		m.SetReply(r)
		m.SetRcode(r, dns.RcodeRefused)
		w.WriteMsg(m)
	}

	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = true
	m.RecursionAvailable = false

	switch question.Qtype {
	// The Acme servers tries to resolve the NS Domain name for validation
	case dns.TypeA:
		fallthrough
	case dns.TypeAAAA:
		rr := &dns.CNAME{
			Hdr:    dns.RR_Header{Name: question.Name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 1200},
			Target: d.Nsdomain + ".",
		}
		m.SetRcode(r, dns.RcodeSuccess)
		m.Answer = []dns.RR{rr}
	case dns.TypeNS:
		rr := &dns.NS{
			Hdr: dns.RR_Header{Name: question.Name, Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 1200},
			Ns:  d.Nsdomain + ".",
		}
		m.SetRcode(r, dns.RcodeSuccess)
		m.Answer = []dns.RR{rr}
	case dns.TypeSOA:
		soa := &dns.SOA{Hdr: dns.RR_Header{Name: question.Name, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 1200},
			Ns:      d.Nsdomain + ".",
			Mbox:    "hostmaster." + d.Zone + ".",
			Serial:  uint32(time.Now().Unix()),
			Refresh: 28800,
			Retry:   7200,
			Expire:  300,
			Minttl:  0}
		m.SetRcode(r, dns.RcodeSuccess)
		m.Answer = []dns.RR{soa}
	case dns.TypeTXT:
		if rr, ok := ChallengeRecord[qname]; ok {
			if ChallengeRecord != nil {
				m.Answer = []dns.RR{rr}
				m.SetRcode(r, dns.RcodeSuccess)
			}
		}
	default:
		m.SetRcode(r, dns.RcodeNameError)
	}

	log.Printf("Answer dns request for %v with %v", question, m.Answer)
	w.WriteMsg(m)
}

func serveDns(net string, listen string) {
	server := &dns.Server{Addr: listen, Net: net, TsigSecret: nil}
	if err := server.ListenAndServe(); err != nil {
		log.Fatalf("Failed to setup the %s server: %s\n", net, err.Error())
	}
}
