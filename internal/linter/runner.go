package linter

import (
	certstd "crypto/x509"
	"fmt"
	"io"
	"time"

	"github.com/cavoq/PCL/internal/aia"
	"github.com/cavoq/PCL/internal/cert"
	certzcrypto "github.com/cavoq/PCL/internal/cert/zcrypto"
	"github.com/cavoq/PCL/internal/crl"
	crlzcrypto "github.com/cavoq/PCL/internal/crl/zcrypto"
	"github.com/cavoq/PCL/internal/node"
	"github.com/cavoq/PCL/internal/ocsp"
	ocspzcrypto "github.com/cavoq/PCL/internal/ocsp/zcrypto"
	"github.com/cavoq/PCL/internal/operator"
	"github.com/cavoq/PCL/internal/output"
	"github.com/cavoq/PCL/internal/policy"
	"github.com/cavoq/PCL/internal/zcrypto"
	"github.com/zmap/zcrypto/x509"
)

func Run(cfg Config, w io.Writer) error {
	applyDefaults(&cfg)
	policies, err := policy.ParseDir(cfg.PolicyPath)
	if err != nil {
		policies = nil
		p, err := policy.ParseFile(cfg.PolicyPath)
		if err != nil {
			return fmt.Errorf("failed to parse policies: %w", err)
		}
		policies = append(policies, p)
	}

	reg := operator.DefaultRegistry()
	var results []policy.Result

	// Load CRLs if provided
	var crls []*crl.Info
	if cfg.CRLPath != "" {
		crls, err = crl.GetCRLs(cfg.CRLPath)
		if err != nil {
			return fmt.Errorf("failed to load CRLs: %w", err)
		}
	}

	// Load OCSP if provided
	var ocsps []*ocsp.Info
	if cfg.OCSPPath != "" {
		ocsps, err = ocsp.GetOCSPs(cfg.OCSPPath)
		if err != nil {
			return fmt.Errorf("failed to load OCSP responses: %w", err)
		}
	}

	// Process certificates if provided
	hasCert := cfg.CertPath != "" || len(cfg.CertURLs) > 0
	hasIssuer := len(cfg.IssuerPaths) > 0 || len(cfg.IssuerURLs) > 0

	if hasCert || hasIssuer {
		// Load leaf certificates
		var certs []*cert.Info
		var cleanup func()

		if hasCert {
			certs, cleanup, err = loadCertificates(cfg)
			if err != nil {
				return err
			}
		}

		// Load issuer certificates
		var issuers []*cert.Info
		if hasIssuer {
			issuers, cleanup, err = loadIssuers(cfg, cleanup)
			if err != nil {
				return err
			}
		}

		if cleanup != nil {
			defer cleanup()
		}

		// Build chain: leaf + issuers
		allCerts := append(certs, issuers...)
		if len(allCerts) == 0 {
			return fmt.Errorf("no certificates provided")
		}

		// Auto-validate: climb chain via CA Issuers URLs BEFORE BuildChain
		// This fetches missing intermediates to complete the chain
		if cfg.AutoValidate && cfg.AutoValidateChain {
			// Start from leaf certificates and climb toward root
			// We need to climb from each leaf to find intermediates
			var climbedCerts []*cert.Info
			for _, c := range certs {
				if c.Cert == nil {
					continue
				}
				// Start mini-chain with just this cert
				miniChain := []*cert.Info{c}
				// Climb from this cert via CA Issuers URLs
				miniChain = climbChain(miniChain, cfg.CertTimeout, cfg.MaxChainDepth, w)
				climbedCerts = append(climbedCerts, miniChain...)
			}
			// Merge climbed certs with provided issuers
			allCerts = append(climbedCerts, issuers...)
		}

		chain, err := cert.BuildChain(allCerts)
		if err != nil {
			return fmt.Errorf("failed to build chain: %w", err)
		}

		// Auto-validate: fetch CRLs from CRL Distribution Points
		if cfg.AutoValidate && cfg.AutoValidateCRL {
			autoCRLs := fetchAutoCRL(chain, cfg.OCSPTimeout, w)
			crls = append(crls, autoCRLs...)
		}

		// Auto-validate: fetch OCSP for all certificates in chain
		if cfg.AutoValidate && cfg.AutoValidateOCSP {
			for i := 0; i < len(chain)-1; i++ {
				c := chain[i]
				if c.Cert == nil || len(c.Cert.OCSPServer) == 0 {
					continue
				}
				// Build mini chain for OCSP request: [cert, issuer]
				miniChain := []*cert.Info{c, chain[i+1]}
				autoOCSPs, err := fetchAutoOCSP(miniChain, cfg.OCSPTimeout)
				if err != nil {
					fmt.Fprintf(w, "Warning: auto OCSP fetch failed for cert %d: %v\n", i, err)
					continue
				}
				ocsps = append(ocsps, autoOCSPs...)
			}
		}

		// Auto-fetch OCSP if enabled and chain has issuer (legacy mode)
		if cfg.AutoOCSP && len(chain) >= 2 {
			autoOCSPs, err := fetchAutoOCSP(chain, cfg.OCSPTimeout)
			if err != nil {
				// Log warning but continue - OCSP fetch failure shouldn't stop cert validation
				fmt.Fprintf(w, "Warning: auto OCSP fetch failed: %v\n", err)
			}
			ocsps = append(ocsps, autoOCSPs...)
		}

		for _, c := range chain {
			tree := certzcrypto.BuildTree(c.Cert)

			// Add CRL node to tree if CRLs are present
			if len(crls) > 0 {
				for _, crlInfo := range crls {
					if crlInfo.CRL != nil {
						crlNode := crlzcrypto.BuildTree(crlInfo.CRL)
						if crlNode != nil {
							tree.Children["crl"] = crlNode
						}
						break
					}
				}
			}

			ctxOpts := []operator.ContextOption{
				operator.WithCRLs(crls),
				operator.WithOCSPs(ocsps),
			}
			ctx := operator.NewEvaluationContext(tree, c, chain, ctxOpts...)

			// Filter policies by certificate type
			filteredPolicies := filterPoliciesByCert(policies, c.Cert)
			for _, p := range filteredPolicies {
				res := policy.Evaluate(p, tree, reg, ctx)
				results = append(results, res)
			}
		}

		// Evaluate OCSP policies if OCSP responses were fetched
		if len(ocsps) > 0 {
			for _, ocspInfo := range ocsps {
				if ocspInfo.Response == nil {
					continue
				}

				ocspNode := ocspzcrypto.BuildTree(ocspInfo.Response)
				if ocspNode == nil {
					continue
				}

				tree := ocspNode
				ctxOpts := []operator.ContextOption{operator.WithOCSPs(ocsps)}
				ctx := operator.NewEvaluationContext(tree, nil, chain, ctxOpts...)

				filteredPolicies := filterPoliciesByInput(policies, AppliesToOCSP)
				for _, p := range filteredPolicies {
					res := policy.Evaluate(p, tree, reg, ctx)
					results = append(results, res)
				}
			}
		}
	} else if len(crls) > 0 {
		// Process CRLs independently when no certificates provided
		for _, crlInfo := range crls {
			if crlInfo.CRL == nil {
				continue
			}

			crlNode := crlzcrypto.BuildTree(crlInfo.CRL)
			if crlNode == nil {
				continue
			}

			// Create a minimal tree with just the CRL
			tree := crlNode

			ctxOpts := []operator.ContextOption{operator.WithCRLs(crls)}
			ctx := operator.NewEvaluationContext(tree, nil, nil, ctxOpts...)

			// Filter policies by CRL type
			hasDelta := hasDeltaCRLIndicator(crlInfo.CRL)
			isIndirect := isIndirectCRL(crlInfo.CRL)
			filteredPolicies := filterPoliciesByCRL(policies, hasDelta, isIndirect)
			for _, p := range filteredPolicies {
				res := policy.Evaluate(p, tree, reg, ctx)
				results = append(results, res)
			}
		}
	} else if len(ocsps) > 0 {
		// Process OCSP independently when no certificates/CRLs provided
		for _, ocspInfo := range ocsps {
			if ocspInfo.Response == nil {
				continue
			}

			ocspNode := ocspzcrypto.BuildTree(ocspInfo.Response)
			if ocspNode == nil {
				continue
			}

			// Use OCSP node directly as tree root
			tree := ocspNode

			ctxOpts := []operator.ContextOption{operator.WithOCSPs(ocsps)}
			ctx := operator.NewEvaluationContext(tree, nil, nil, ctxOpts...)

			// Filter policies by input type (OCSP)
			filteredPolicies := filterPoliciesByInput(policies, AppliesToOCSP)
			for _, p := range filteredPolicies {
				res := policy.Evaluate(p, tree, reg, ctx)
				results = append(results, res)
			}
		}
	} else {
		return fmt.Errorf("no certificates, CRLs, or OCSP responses provided")
	}

	outputOpts := output.Options{
		ShowPassed:  cfg.Verbosity >= 1,
		ShowFailed:  true,
		ShowSkipped: cfg.Verbosity >= 2,
		ShowMeta:    cfg.ShowMeta,
	}

	lintOutput := output.FromPolicyResults(results)
	lintOutput = output.FilterRules(lintOutput, outputOpts)

	formatter := output.GetFormatter(cfg.OutputFmt, outputOpts)
	return formatter.Format(w, lintOutput)
}

func loadCertificates(cfg Config) ([]*cert.Info, func(), error) {
	var cleanup func()
	var certs []*cert.Info

	if cfg.CertPath != "" {
		loaded, err := cert.LoadCertificates(cfg.CertPath)
		if err != nil {
			return nil, cleanup, fmt.Errorf("failed to load certificates: %w", err)
		}
		certs = append(certs, loaded...)
	}

	if len(cfg.CertURLs) > 0 {
		dir, tempCleanup, err := cert.DownloadCertificates(cfg.CertURLs, cfg.CertTimeout, cfg.CertSaveDir)
		if err != nil {
			return nil, cleanup, fmt.Errorf("failed to download certificates: %w", err)
		}
		if tempCleanup != nil {
			cleanup = tempCleanup
		}
		loaded, err := cert.LoadCertificates(dir)
		if err != nil {
			return nil, cleanup, fmt.Errorf("failed to load downloaded certificates: %w", err)
		}
		certs = append(certs, loaded...)
	}

	if len(certs) == 0 {
		return nil, cleanup, fmt.Errorf("no leaf certificates provided")
	}

	return certs, cleanup, nil
}

func loadIssuers(cfg Config, existingCleanup func()) ([]*cert.Info, func(), error) {
	var cleanup func() = existingCleanup
	var issuers []*cert.Info

	for _, path := range cfg.IssuerPaths {
		loaded, err := cert.LoadCertificates(path)
		if err != nil {
			return nil, cleanup, fmt.Errorf("failed to load issuer certificates from %s: %w", path, err)
		}
		issuers = append(issuers, loaded...)
	}

	if len(cfg.IssuerURLs) > 0 {
		dir, tempCleanup, err := cert.DownloadCertificates(cfg.IssuerURLs, cfg.CertTimeout, cfg.CertSaveDir)
		if err != nil {
			return nil, cleanup, fmt.Errorf("failed to download issuer certificates: %w", err)
		}
		if tempCleanup != nil {
			cleanup = tempCleanup
		}
		loaded, err := cert.LoadCertificates(dir)
		if err != nil {
			return nil, cleanup, fmt.Errorf("failed to load downloaded issuer certificates: %w", err)
		}
		issuers = append(issuers, loaded...)
	}

	if len(issuers) == 0 {
		return nil, cleanup, fmt.Errorf("no issuer certificates provided")
	}

	return issuers, cleanup, nil
}

func applyDefaults(cfg *Config) {
	if cfg.CertTimeout <= 0 {
		cfg.CertTimeout = 10 * time.Second
	}
	if cfg.OCSPTimeout <= 0 {
		cfg.OCSPTimeout = 5 * time.Second
	}
	if cfg.OutputFmt == "" {
		cfg.OutputFmt = "text"
	}

	// Auto-validate defaults
	if cfg.AutoValidate {
		if cfg.MaxChainDepth <= 0 {
			cfg.MaxChainDepth = 10
		}
		// Default all auto-fetch options to true when AutoValidate is enabled
		// unless explicitly set to false
	}
}

// fetchAutoOCSP automatically fetches OCSP responses for certificates in the chain.
// For leaf certificates, uses the OCSP URL from AIA extension and issuer from chain.
func fetchAutoOCSP(chain []*cert.Info, timeout time.Duration) ([]*ocsp.Info, error) {
	if len(chain) < 2 {
		return nil, fmt.Errorf("chain must have at least 2 certificates for OCSP request")
	}

	var results []*ocsp.Info

	// Convert zcrypto certs to standard certs for OCSP request
	stdChain := make([]*certstd.Certificate, 0, len(chain))
	for _, c := range chain {
		if c.Cert == nil {
			continue
		}
		stdCert, err := zcrypto.ToStdCert(c.Cert)
		if err != nil {
			continue
		}
		stdChain = append(stdChain, stdCert)
	}

	if len(stdChain) < 2 {
		return nil, fmt.Errorf("failed to convert certificates to standard format")
	}

	// Fetch OCSP for leaf certificate
	resp, url, err := ocsp.FetchOCSPFromChain(stdChain, timeout)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch OCSP from %s: %w", url, err)
	}
	if resp == nil {
		// No OCSP URL in certificate, not an error
		return nil, nil
	}

	results = append(results, &ocsp.Info{
		Response: resp,
		FilePath: url, // Use URL as "file path" for auto-fetched responses
	})

	return results, nil
}

// climbChain recursively fetches issuer certificates via CA Issuers URLs.
// Starts from the top of the chain and climbs toward root until:
// - Self-signed certificate found (root)
// - Max depth reached
// - No CA Issuers URL found
// - Circular certificate detected
//
// Handles PKCS#7 bundles: extracts all certificates and selects the correct issuer
// by matching Issuer DN and/or AKI extension.
func climbChain(chain []*cert.Info, timeout time.Duration, maxDepth int, w io.Writer) []*cert.Info {
	if len(chain) == 0 || maxDepth <= 0 {
		return chain
	}

	// Track seen certificates to detect circular chains
	seen := make(map[string]bool)
	for _, c := range chain {
		if c.Cert != nil && c.Cert.SerialNumber != nil {
			seen[c.Cert.SerialNumber.String()] = true
		}
	}

	result := chain
	depth := 0

	for depth < maxDepth {
		// Get the highest certificate in the chain (potential issuer to climb)
		top := result[len(result)-1]
		if top.Cert == nil {
			break
		}

		// Check if it's self-signed (root)
		if top.Cert.Issuer.String() == top.Cert.Subject.String() {
			break
		}

		// Check for CA Issuers URL
		if len(top.Cert.IssuingCertificateURL) == 0 {
			break
		}

		// Fetch issuer(s) from first CA Issuers URL (may be PKCS#7 bundle)
		url := top.Cert.IssuingCertificateURL[0]
		pkcs7Result, err := aia.FetchCAIssuerPKCS7(url, timeout)
		if err != nil {
			fmt.Fprintf(w, "Warning: failed to climb chain from %s: %v\n", url, err)
			break
		}

		// Find the correct issuer certificate from the bundle
		// Match by Issuer DN (subject of issuer should match issuer of cert)
		var issuerCert *x509.Certificate
		for _, cert := range pkcs7Result.Certs {
			// Check if this cert's subject matches the current cert's issuer
			if cert.Subject.String() == top.Cert.Issuer.String() {
				issuerCert = cert
				break
			}
		}

		// If no exact DN match, try AKI-SKI matching
		if issuerCert == nil && len(top.Cert.AuthorityKeyId) > 0 {
			for _, cert := range pkcs7Result.Certs {
				if len(cert.SubjectKeyId) > 0 && string(cert.SubjectKeyId) == string(top.Cert.AuthorityKeyId) {
					issuerCert = cert
					break
				}
			}
		}

		// Fallback: use first certificate if only one, or continue with best guess
		if issuerCert == nil {
			if len(pkcs7Result.Certs) == 1 {
				issuerCert = pkcs7Result.Certs[0]
			} else {
				// Multiple certs with no match - use first as best guess
				issuerCert = pkcs7Result.Certs[0]
				fmt.Fprintf(w, "Warning: PKCS#7 bundle contains %d certs, no exact issuer match found, using first cert\n", len(pkcs7Result.Certs))
			}
		}

		// Check for circular certificate
		if issuerCert.SerialNumber != nil {
			serial := issuerCert.SerialNumber.String()
			if seen[serial] {
				fmt.Fprintf(w, "Warning: circular certificate detected at %s\n", url)
				break
			}
			seen[serial] = true
		}

		// Add issuer to chain
		issuerInfo := &cert.Info{
			Cert:     issuerCert,
			FilePath: url,
			Type:     cert.GetCertType(issuerCert, len(result), len(result)+1),
			Position: len(result),
		}
		result = append(result, issuerInfo)

		depth++
	}

	// Rebuild chain types after climbing is complete
	for i, c := range result {
		c.Position = i
		c.Type = cert.GetCertType(c.Cert, i, len(result))
	}

	return result
}

// fetchAutoCRL fetches CRLs from CRL Distribution Points for certificates in chain.
func fetchAutoCRL(chain []*cert.Info, timeout time.Duration, w io.Writer) []*crl.Info {
	var results []*crl.Info

	for _, c := range chain {
		if c.Cert == nil || len(c.Cert.CRLDistributionPoints) == 0 {
			continue
		}

		for _, url := range c.Cert.CRLDistributionPoints {
			fetchResult, err := crl.FetchCRL(url, timeout)
			if err != nil {
				fmt.Fprintf(w, "Warning: failed to fetch CRL from %s: %v\n", url, err)
				continue
			}

			results = append(results, &crl.Info{
				CRL:      fetchResult.CRL,
				FilePath: url,
			})
		}
	}

	return results
}

// addFetchedInfoToNode adds format and fetch status info to node tree for policy evaluation.
func addFetchedInfoToNode(tree *node.Node, caIssuerFormat aia.Format, crlFormat crl.Format) {
	if caIssuerFormat != "" {
		tree.Children["caIssuersFormat"] = node.New("caIssuersFormat", string(caIssuerFormat))
	}
	if crlFormat != "" {
		tree.Children["crlFormat"] = node.New("crlFormat", string(crlFormat))
	}
}