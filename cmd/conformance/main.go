// Command conformance exercises a gateway's implementation of the provider
// contract and reports what it got wrong.
//
// Three gateways in the CertPilot tree are kept honest by live tests against a
// real Vault and a real ACME server, which a stranger cannot run. Without
// something equivalent, "write your own gateway" means "write your own and find
// out in production" — so this is the equivalent: point it at a gateway address
// and it says which parts of the contract hold.
//
// It is deliberately not a test framework. It takes an address, makes real
// calls, and prints sentences. A gateway author should be able to run it
// against a half-finished server on the second day and get something useful.
//
// Exit status is 0 only when every check that ran passed. Checks that could not
// run — issuance without -domain, CA info from a gateway that says it has none —
// are reported as skipped and do not fail the run, because a gateway is allowed
// not to support them and the report says so rather than pretending.
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/certpilot/certpilot-gateway-sdk/grpckit"
	commonv1 "github.com/certpilot/certpilot-gateway-sdk/pb/common/v1"
	providerv1 "github.com/certpilot/certpilot-gateway-sdk/pb/provider/v1"
	"github.com/certpilot/certpilot-gateway-sdk/x509util"
	grpccodes "google.golang.org/grpc/codes"
	grpcstatus "google.golang.org/grpc/status"
)

func main() {
	var (
		addr        = flag.String("addr", "", "gateway address, host:port (required)")
		config      = flag.String("config", "", "provider config JSON, as a CA account would supply it")
		domain      = flag.String("domain", "", "a domain to issue for. Without this, issuance is skipped")
		revoke      = flag.Bool("revoke", false, "revoke what was issued, if the gateway reports it supports revocation")
		timeout     = flag.Duration("timeout", 2*time.Minute, "overall deadline")
		insecureTLS = flag.Bool("insecure", false, "dial without TLS. Loopback only")
		certFile    = flag.String("cert", "", "client certificate for mutual TLS")
		keyFile     = flag.String("key", "", "client private key")
		caFile      = flag.String("ca", "", "CA bundle used to verify the gateway")
		serverName  = flag.String("server-name", "", "override the name expected in the gateway's certificate")
	)
	flag.Parse()

	if *addr == "" {
		fmt.Fprintln(os.Stderr, "conformance: -addr is required")
		flag.Usage()
		os.Exit(2)
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	conn, err := grpckit.Dial(ctx, *addr, grpckit.TLSConfig{
		CertFile: *certFile, KeyFile: *keyFile, CAFile: *caFile,
		ServerName: *serverName, Insecure: *insecureTLS,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "conformance: could not reach a gateway at %s: %v\n", *addr, err)
		os.Exit(1)
	}
	defer conn.Close()

	r := &report{}
	client := providerv1.NewCertificateProviderServiceClient(conn)

	caps := checkCapabilities(ctx, r, client)
	checkHealth(ctx, r, client)
	checkValidateConfig(ctx, r, client, *config)
	checkCAInfo(ctx, r, client, caps, *config)
	checkIssuance(ctx, r, client, caps, *domain, *config, *revoke)

	os.Exit(r.print(*addr))
}

// ── The checks ───────────────────────────────────────────

// checkCapabilities runs first because the rest of the report is read against
// what the gateway says of itself. A gateway that will not answer this cannot
// be registered at all.
func checkCapabilities(ctx context.Context, r *report, c providerv1.CertificateProviderServiceClient) *commonv1.ProviderCapabilities {
	resp, err := c.GetCapabilities(ctx, &providerv1.GetCapabilitiesRequest{})
	if err != nil {
		r.fail("GetCapabilities", "the call failed: %v", err)
		return nil
	}
	caps := resp.GetCapabilities()
	if caps == nil {
		r.fail("GetCapabilities", "answered with no capabilities message at all")
		return nil
	}

	var missing []string
	if caps.GetProviderName() == "" {
		missing = append(missing, "provider_name")
	}
	if caps.GetProviderType() == "" {
		missing = append(missing, "provider_type")
	}
	if len(caps.GetSupportedKeyTypes()) == 0 {
		missing = append(missing, "supported_key_types")
	}
	if len(missing) > 0 {
		// Not cosmetic: the core shows these to an operator choosing a CA
		// account, and an empty key-type list means nothing can be selected.
		r.fail("GetCapabilities", "answered, but left %s empty — the core shows these when an operator picks a CA", strings.Join(missing, ", "))
		return caps
	}
	r.pass("GetCapabilities", "%s (%s), key types %s", caps.GetProviderName(), caps.GetProviderType(),
		strings.Join(caps.GetSupportedKeyTypes(), ", "))
	return caps
}

// checkHealth. An UNSPECIFIED status is the failure worth naming: it is what a
// gateway returns when it has not thought about health, and the core would
// display it as an unknown state for ever.
func checkHealth(ctx context.Context, r *report, c providerv1.CertificateProviderServiceClient) {
	resp, err := c.HealthCheck(ctx, &providerv1.HealthCheckRequest{})
	if err != nil {
		r.fail("HealthCheck", "the call failed: %v", err)
		return
	}
	if resp.GetStatus() == commonv1.HealthStatus_HEALTH_STATUS_UNSPECIFIED {
		r.fail("HealthCheck", "returned HEALTH_STATUS_UNSPECIFIED, which the core can only show as unknown for ever")
		return
	}
	r.pass("HealthCheck", "%s%s", resp.GetStatus(), optional(resp.GetMessage()))
}

// checkValidateConfig probes the one call meant to catch a misconfiguration
// before a certificate depends on it.
//
// The wrong implementation is easy and silent: `return &Response{Valid: true}`
// passes every test an author is likely to write and turns the call into a
// rubber stamp. So the hard check is the one no gateway can argue with —
// syntactically malformed JSON is not a valid configuration for anything, and a
// gateway that calls it valid has not looked at it.
//
// Unknown *keys* are only advisory. A gateway that takes no configuration is
// entitled to accept an empty object, and failing it for that would be this
// program inventing a rule the contract does not contain.
func checkValidateConfig(ctx context.Context, r *report, c providerv1.CertificateProviderServiceClient, config string) {
	resp, err := c.ValidateConfig(ctx, &providerv1.ValidateConfigRequest{
		ConfigJson: `{"certpilot_conformance": this is not JSON at all`,
	})
	switch {
	case err != nil:
		r.fail("ValidateConfig (rejects malformed JSON)", "the call failed: %v", err)
	case resp.GetValid():
		r.fail("ValidateConfig (rejects malformed JSON)",
			"called a string that is not even JSON a valid configuration. The call has not looked at "+
				"its argument, and it is the only thing standing between a typo and a certificate that "+
				"depends on it")
	case len(resp.GetErrors()) == 0:
		r.fail("ValidateConfig (rejects malformed JSON)",
			"refused it but listed no errors, so an operator is told the config is wrong and not why")
	default:
		r.pass("ValidateConfig (rejects malformed JSON)", "%s", resp.GetErrors()[0])
	}

	// Advisory: a key no gateway defines. Reported, never failed.
	if resp, err := c.ValidateConfig(ctx, &providerv1.ValidateConfigRequest{
		ConfigJson: `{"certpilot_conformance_unknown_key": true}`,
	}); err == nil && resp.GetValid() && len(resp.GetWarnings()) == 0 {
		r.note("ValidateConfig (unknown keys)",
			"accepted an unrecognised key silently. Allowed, but a warning here is what turns a typo "+
				"into something an operator can see")
	} else if err == nil {
		r.pass("ValidateConfig (unknown keys)", "noticed a key it does not define")
	}

	if config == "" {
		r.skip("ValidateConfig (accepts the real one)", "no -config was supplied")
		return
	}
	real, err := c.ValidateConfig(ctx, &providerv1.ValidateConfigRequest{ConfigJson: config})
	if err != nil {
		r.fail("ValidateConfig (accepts the real one)", "the call failed: %v", err)
		return
	}
	if !real.GetValid() {
		r.fail("ValidateConfig (accepts the real one)", "refused the config this run was given: %s",
			strings.Join(real.GetErrors(), "; "))
		return
	}
	r.pass("ValidateConfig (accepts the real one)", "accepted")
}

// checkCAInfo. This is what puts issuers into the inventory.
//
// The strictness here is calibrated, not assumed. A first cut failed any
// authority carrying no certificate_pem, and the ACME gateway failed it
// legitimately: ACME exposes no endpoint listing issuer certificates — they
// arrive with each issuance — so the most it can honestly return is who the CA
// claims to be. Failing that would have been this program inventing a
// requirement the protocol cannot meet.
//
// So: a certificate that is present and will not parse is a failure, because
// nothing downstream can read it. An authority with no certificate at all is
// reported as advisory, because it identifies the CA but cannot be monitored
// for expiry — which is worth an operator knowing and is not a defect.
func checkCAInfo(ctx context.Context, r *report, c providerv1.CertificateProviderServiceClient,
	caps *commonv1.ProviderCapabilities, config string) {

	if caps != nil && !caps.GetSupportsCaInfo() {
		r.skip("GetCAInfo", "the gateway reports supports_ca_info=false")
		return
	}
	resp, err := c.GetCAInfo(ctx, &providerv1.GetCAInfoRequest{ProviderConfig: config})
	if err != nil {
		// A gateway that cannot reach a CA without credentials is right to
		// refuse, and refusing with InvalidArgument is right too. Without a
		// -config this probe has not given it what it needs, so the honest
		// result is "not checked" rather than a failure the gateway did not
		// earn. The Vault gateway is the case that taught this.
		if config == "" && grpcstatus.Code(err) == grpccodes.InvalidArgument {
			r.skip("GetCAInfo", "the gateway needs a provider config to reach its CA; pass -config")
			return
		}
		r.fail("GetCAInfo", "supports_ca_info is true but the call failed: %v", err)
		return
	}
	chain := resp.GetCaChain()
	if len(chain) == 0 {
		r.fail("GetCAInfo", "supports_ca_info is true but no authorities were returned. "+
			"This is what puts issuers into the inventory; without it the CA is invisible until it expires")
		return
	}

	var withCert, withoutCert int
	for i, a := range chain {
		if len(a.GetCertificatePem()) == 0 {
			withoutCert++
			continue
		}
		if _, err := x509util.ParseCertificatePEM(a.GetCertificatePem()); err != nil {
			r.fail("GetCAInfo", "authority %d (%q) carries a certificate_pem that will not parse: %v", i, a.GetName(), err)
			return
		}
		withCert++
	}

	switch {
	case withoutCert == len(chain):
		r.note("GetCAInfo", "%d authorit%s returned, none carrying a certificate. They identify the CA "+
			"but cannot be monitored for expiry", len(chain), plural(len(chain), "y", "ies"))
	case withoutCert > 0:
		r.note("GetCAInfo", "%d of %d authorities carry no certificate and cannot be monitored for expiry",
			withoutCert, len(chain))
	default:
		r.pass("GetCAInfo", "%d authorit%s, all parseable", withCert, plural(withCert, "y", "ies"))
	}
}

// checkIssuance is the part that matters, and the CSR check inside it is the
// single most valuable assertion in this program.
func checkIssuance(ctx context.Context, r *report, c providerv1.CertificateProviderServiceClient,
	caps *commonv1.ProviderCapabilities, domain, config string, revoke bool) {

	if domain == "" {
		r.skip("IssueCertificate", "no -domain was supplied")
		r.skip("IssueCertificate (honours csr_pem)", "no -domain was supplied")
		return
	}

	// ── Without a CSR: the gateway generates the key. ──
	resp, err := c.IssueCertificate(ctx, &providerv1.IssueCertificateRequest{
		Domains: []string{domain}, KeyType: "ECDSA", KeySize: 256,
		ValidityDays: 30, ProviderConfig: config,
	})
	switch {
	case err != nil:
		r.fail("IssueCertificate", "the call failed: %v", err)
	case resp.GetCertificate() == nil:
		r.fail("IssueCertificate", "reported success and returned no certificate. "+
			"A success that issued nothing becomes a record of a certificate that does not exist")
	case len(resp.GetCertificate().GetCertificatePem()) == 0:
		r.fail("IssueCertificate", "returned a certificate message with an empty certificate_pem")
	case len(resp.GetCertificate().GetPrivateKeyPem()) == 0:
		r.fail("IssueCertificate", "generated the key itself but returned no private_key_pem, "+
			"so the certificate it just issued can never be used")
	default:
		if _, err := x509util.ParseCertificatePEM(resp.GetCertificate().GetCertificatePem()); err != nil {
			r.fail("IssueCertificate", "returned a certificate_pem that will not parse: %v", err)
		} else {
			r.pass("IssueCertificate", "issued for %s", domain)
		}
	}

	// ── With a CSR: the gateway must sign the key it was given. ──
	//
	// csr_pem is part of the contract and all three reference gateways honour
	// it. A gateway that generates its own key instead silently discards the
	// key the caller is about to deploy, and the failure surfaces much later as
	// a certificate that does not match its private key — usually at 3am, on
	// the host, after the deployment succeeded.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		r.fail("IssueCertificate (honours csr_pem)", "could not generate a key for the probe: %v", err)
		return
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkixName(domain), DNSNames: []string{domain},
	}, key)
	if err != nil {
		r.fail("IssueCertificate (honours csr_pem)", "could not build a CSR for the probe: %v", err)
		return
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})

	withCSR, err := c.IssueCertificate(ctx, &providerv1.IssueCertificateRequest{
		CsrPem: csrPEM, Domains: []string{domain}, ValidityDays: 30, ProviderConfig: config,
	})
	if err != nil {
		r.fail("IssueCertificate (honours csr_pem)", "the call failed: %v", err)
		return
	}
	issued := withCSR.GetCertificate()
	if issued == nil || len(issued.GetCertificatePem()) == 0 {
		r.fail("IssueCertificate (honours csr_pem)", "returned no certificate")
		return
	}
	cert, err := x509util.ParseX509PEM(issued.GetCertificatePem())
	if err != nil {
		r.fail("IssueCertificate (honours csr_pem)", "returned a certificate that will not parse: %v", err)
		return
	}
	issuedKey, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok || !issuedKey.Equal(&key.PublicKey) {
		r.fail("IssueCertificate (honours csr_pem)",
			"a CSR was supplied and the certificate carries a DIFFERENT public key. "+
				"The gateway generated its own key and discarded the caller's. This surfaces later as "+
				"a certificate that does not match its private key")
		return
	}
	if len(issued.GetPrivateKeyPem()) > 0 {
		r.fail("IssueCertificate (honours csr_pem)",
			"signed the supplied CSR correctly but also returned a private_key_pem. "+
				"The caller holds that key; the gateway must never have had it to return")
		return
	}
	r.pass("IssueCertificate (honours csr_pem)", "signed the supplied key, returned no private key")

	// ── Revocation. ──
	if !revoke {
		r.skip("RevokeCertificate", "-revoke was not given")
		return
	}
	if caps != nil && !caps.GetSupportsRevocation() {
		r.skip("RevokeCertificate", "the gateway reports supports_revocation=false")
		return
	}
	rev, err := c.RevokeCertificate(ctx, &providerv1.RevokeCertificateRequest{
		CertificatePem:        issued.GetCertificatePem(),
		ProviderCertificateId: withCSR.GetProviderCertificateId(),
		Reason:                4, // superseded
		ProviderConfig:        config,
	})
	if err != nil {
		r.fail("RevokeCertificate", "the call failed: %v", err)
		return
	}
	if !rev.GetSuccess() {
		r.fail("RevokeCertificate", "reported failure: %s", rev.GetMessage())
		return
	}
	r.pass("RevokeCertificate", "revoked the certificate this run issued")
}
