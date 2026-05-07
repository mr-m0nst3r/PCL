package linter

import (
	certstd "crypto/x509"
	"fmt"
	"io"
	"os"
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

	// Load policies from all specified paths
	var policies []policy.Policy
	var err error
	for _, policyPath := range cfg.PolicyPaths {
		// Check if path is a directory first
		isDir, err2 := isDirectory(policyPath)
		if err2 != nil {
			return fmt.Errorf("checking policy path %s: %w", policyPath, err2)
		}

		if isDir {
			p, err2 := policy.ParseDir(policyPath)
			if err2 != nil {
				return fmt.Errorf("failed to parse policy directory %s: %w", policyPath, err2)
			}
			policies = append(policies, p...)
		} else {
			p, err2 := policy.ParseFile(policyPath)
			if err2 != nil {
				return fmt.Errorf("failed to parse policy file %s: %w", policyPath, err2)
			}
			policies = append(policies, p)
		}
	}

	reg := operator.DefaultRegistry()
	var results []policy.Result
	var cleanup func()

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

	// Build issuer list for CRL/OCSP signature verification (always needed if provided)
	var issuers []*cert.Info
	if hasIssuer {
		var issuerCleanup func()
		issuers, issuerCleanup, err = loadIssuers(cfg, nil)
		if err != nil {
			return err
		}
		if issuerCleanup != nil {
			cleanup = issuerCleanup
		}
	}

	// Schedule cleanup at the end of processing (for downloaded certs/issuers)
	if cleanup != nil {
		defer cleanup()
	}

	if hasCert {
		// Load leaf certificates
		var certs []*cert.Info
		var certCleanup func()

		certs, certCleanup, err = loadCertificates(cfg)
		if err != nil {
			return err
		}
		if certCleanup != nil {
			cleanup = certCleanup
		}

		// Build chain: leaf + issuers
		allCerts := append(certs, issuers...)
		if len(allCerts) == 0 {
			return fmt.Errorf("no certificates provided")
		}

		// Auto-validate: climb chain via CA Issuers URLs BEFORE BuildChain
		// This fetches missing intermediates to complete the chain
		if cfg.AutoValidate && !cfg.NoAutoChain {
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

		// Build nonce options from config
		nonceOpts := buildNonceOptions(cfg)

		// Auto-validate: fetch CRLs from CRL Distribution Points
		if cfg.AutoValidate && !cfg.NoAutoCRL {
			autoCRLs := fetchAutoCRL(chain, cfg.OCSPTimeout, w)
			crls = append(crls, autoCRLs...)
		}

		// Auto-validate: fetch OCSP for all certificates in chain
		if cfg.AutoValidate && !cfg.NoAutoOCSP {
			for i := 0; i < len(chain)-1; i++ {
				c := chain[i]
				if c.Cert == nil || len(c.Cert.OCSPServer) == 0 {
					continue
				}
				// Build mini chain for OCSP request: [cert, issuer]
				miniChain := []*cert.Info{c, chain[i+1]}
				autoOCSPs, err := fetchAutoOCSP(miniChain, cfg.OCSPTimeout, nonceOpts)
				if err != nil {
					_, _ = fmt.Fprintf(w, "Warning: auto OCSP fetch failed for cert %d: %v\n", i, err)
					continue
				}
				// Debug: print OCSP response details when verbosity >= 2
				if cfg.Verbosity >= 2 && len(autoOCSPs) > 0 {
					for _, ocspInfo := range autoOCSPs {
						printOCSPResponseDebug(w, ocspInfo, nonceOpts)
					}
				}
				ocsps = append(ocsps, autoOCSPs...)
			}
		}


		for _, c := range chain {
			tree := certzcrypto.BuildTree(c.Cert)

			// Add download format to tree for PEM format detection rule
			if c.DownloadFormat != "" {
				tree.Children["downloadFormat"] = node.New("downloadFormat", c.DownloadFormat)
				tree.Children["downloadURL"] = node.New("downloadURL", c.DownloadURL)
			}

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

				// Create synthetic cert.Info for OCSP response to set proper CertType
				ocspCertInfo := &cert.Info{
					FilePath: ocspInfo.FilePath,
					Type:     "ocsp",
					Source:   ocspInfo.Source,
				}

				tree := ocspNode
				ctxOpts := []operator.ContextOption{operator.WithOCSPs(ocsps)}
				ctx := operator.NewEvaluationContext(tree, ocspCertInfo, chain, ctxOpts...)

				filteredPolicies := filterPoliciesByInput(policies, AppliesToOCSP)
				for _, p := range filteredPolicies {
					res := policy.Evaluate(p, tree, reg, ctx)
					results = append(results, res)
				}

				// Evaluate OCSP signing certificate if present in response
				if ocspInfo.Response.Certificate != nil {
					// Convert standard cert to zcrypto cert
					zcryptoSignerCert, err := zcrypto.FromStdCert(ocspInfo.Response.Certificate)
					if err != nil || zcryptoSignerCert == nil {
						continue
					}
					ocspSignerTree := certzcrypto.BuildTree(zcryptoSignerCert)
					ocspSignerInfo := &cert.Info{
						Cert:     zcryptoSignerCert,
						FilePath: ocspInfo.FilePath + " (signing cert)",
						Type:     "ocspSigning",
						Source:   "extracted from OCSP response",
					}

					signerCtxOpts := []operator.ContextOption{operator.WithOCSPs(ocsps)}
					signerCtx := operator.NewEvaluationContext(ocspSignerTree, ocspSignerInfo, chain, signerCtxOpts...)

					signerPolicies := filterPoliciesByCert(policies, zcryptoSignerCert)
					for _, p := range signerPolicies {
						res := policy.Evaluate(p, ocspSignerTree, reg, signerCtx)
						results = append(results, res)
					}
				}
			}
		}

			// Evaluate CRLs independently if CRLs were fetched (dual evaluation)
			// This evaluates CRL-specific rules (like signature algorithm params)
			// separately from certificate context
			if len(crls) > 0 {
				for _, crlInfo := range crls {
					if crlInfo.CRL == nil {
						continue
					}

					// Build issuer certificates list from chain
					var issuerCerts []*x509.Certificate
					for _, c := range chain {
						if c.Cert != nil {
							issuerCerts = append(issuerCerts, c.Cert)
						}
					}

					crlNode := crlzcrypto.BuildTreeWithChain(crlInfo.CRL, issuerCerts)
					if crlNode == nil {
						continue
					}

					// Create synthetic cert.Info for CRL to set proper CertType
					crlCertInfo := &cert.Info{
						FilePath: crlInfo.FilePath,
						Type:     "crl",
						Source:   crlInfo.Source,
					}

					tree := crlNode
					ctxOpts := []operator.ContextOption{operator.WithCRLs(crls)}
					ctx := operator.NewEvaluationContext(tree, crlCertInfo, chain, ctxOpts...)

					// Filter policies by CRL type
					hasDelta := hasDeltaCRLIndicator(crlInfo.CRL)
					isIndirect := isIndirectCRL(crlInfo.CRL)
					filteredPolicies := filterPoliciesByCRL(policies, hasDelta, isIndirect)
					for _, p := range filteredPolicies {
						res := policy.Evaluate(p, tree, reg, ctx)
						results = append(results, res)
					}
				}
			}
	} else if len(crls) > 0 {
		// Process CRLs independently when no certificates provided
		// Use issuers as chain for CRL signature verification
		// Also evaluate CRLs in auto-validate mode (dual evaluation)
		for _, crlInfo := range crls {
			if crlInfo.CRL == nil {
				continue
			}

			// Build issuer certificates list for CRL type detection
			var issuerCerts []*x509.Certificate
			for _, issuer := range issuers {
				if issuer.Cert != nil {
					issuerCerts = append(issuerCerts, issuer.Cert)
				}
			}

			crlNode := crlzcrypto.BuildTreeWithChain(crlInfo.CRL, issuerCerts)
			if crlNode == nil {
				continue
			}

			// Create synthetic cert.Info for CRL to set proper CertType
			crlCertInfo := &cert.Info{
				FilePath: crlInfo.FilePath,
				Type:     "crl",
				Source:   crlInfo.Source,
			}

			// Create a minimal tree with just the CRL
			tree := crlNode

			ctxOpts := []operator.ContextOption{operator.WithCRLs(crls)}
			ctx := operator.NewEvaluationContext(tree, crlCertInfo, issuers, ctxOpts...)

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

			// Create synthetic cert.Info for OCSP response to set proper CertType
			ocspCertInfo := &cert.Info{
				FilePath: ocspInfo.FilePath,
				Type:     "ocsp",
				Source:   ocspInfo.Source,
			}

			// Use OCSP node directly as tree root
			tree := ocspNode

			ctxOpts := []operator.ContextOption{operator.WithOCSPs(ocsps)}
			ctx := operator.NewEvaluationContext(tree, ocspCertInfo, nil, ctxOpts...)

			// Filter policies by input type (OCSP)
			filteredPolicies := filterPoliciesByInput(policies, AppliesToOCSP)
			for _, p := range filteredPolicies {
				res := policy.Evaluate(p, tree, reg, ctx)
				results = append(results, res)
			}

			// Evaluate OCSP signing certificate if present in response
			if ocspInfo.Response.Certificate != nil {
				// Convert standard cert to zcrypto cert
				zcryptoSignerCert, err := zcrypto.FromStdCert(ocspInfo.Response.Certificate)
				if err != nil || zcryptoSignerCert == nil {
					continue
				}
				ocspSignerTree := certzcrypto.BuildTree(zcryptoSignerCert)
				ocspSignerInfo := &cert.Info{
					Cert:     zcryptoSignerCert,
					FilePath: ocspInfo.FilePath + " (signing cert)",
					Type:     "ocspSigning",
					Source:   "extracted from OCSP response",
				}

				signerCtxOpts := []operator.ContextOption{operator.WithOCSPs(ocsps)}
				signerCtx := operator.NewEvaluationContext(ocspSignerTree, ocspSignerInfo, nil, signerCtxOpts...)

				signerPolicies := filterPoliciesByCert(policies, zcryptoSignerCert)
				for _, p := range signerPolicies {
					res := policy.Evaluate(p, ocspSignerTree, reg, signerCtx)
					results = append(results, res)
				}
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
func fetchAutoOCSP(chain []*cert.Info, timeout time.Duration, nonceOpts *ocsp.NonceOptions) ([]*ocsp.Info, error) {
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
	fetchResult, url, err := ocsp.FetchOCSPFromChainWithInfo(stdChain, timeout, nonceOpts)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch OCSP from %s: %w", url, err)
	}
	if fetchResult == nil {
		// No OCSP URL in certificate, not an error
		return nil, nil
	}

	info := &ocsp.Info{
		Response: fetchResult.Response,
		FilePath: url, // Use URL as "file path" for auto-fetched responses
		Source:   "downloaded",
	}

	// Populate request debug info
	if fetchResult.RequestInfo != nil {
		info.RequestNonce = fetchResult.RequestInfo.Nonce
		info.RequestNonceHex = fetchResult.RequestInfo.NonceHex
		info.RequestNonceLen = fetchResult.RequestInfo.NonceLen
		info.RequestRawLen = fetchResult.RequestInfo.RequestLen
		info.RequestHashAlgorithm = fetchResult.RequestInfo.HashAlgorithm
	}

	results = append(results, info)

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
			_, _ = fmt.Fprintf(w, "Warning: failed to climb chain from %s: %v\n", url, err)
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
				_, _ = fmt.Fprintf(w, "Warning: PKCS#7 bundle contains %d certs, no exact issuer match found, using first cert\n", len(pkcs7Result.Certs))
			}
		}

		// Check for circular certificate
		if issuerCert.SerialNumber != nil {
			serial := issuerCert.SerialNumber.String()
			if seen[serial] {
				_, _ = fmt.Fprintf(w, "Warning: circular certificate detected at %s\n", url)
				break
			}
			seen[serial] = true
		}

		// Add issuer to chain
		var source string
		switch pkcs7Result.Format {
		case aia.FormatPKCS7:
			source = "extracted from PKCS#7"
		case aia.FormatDER:
			source = "downloaded"
		case aia.FormatPEM:
			source = "downloaded PEM"
			_, _ = fmt.Fprintf(w, "Warning: CA Issuers URL %s returned PEM format (RFC 5280 requires DER/BER)\n", url)
		default:
			source = "downloaded"
		}
		issuerInfo := &cert.Info{
			Cert:           issuerCert,
			FilePath:       url,
			Type:           cert.GetCertType(issuerCert, len(result), len(result)+1),
			Position:       len(result),
			Source:         source,
			DownloadURL:    url,
			DownloadFormat: string(pkcs7Result.Format),
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
				_, _ = fmt.Fprintf(w, "Warning: failed to fetch CRL from %s: %v\n", url, err)
				continue
			}

			results = append(results, &crl.Info{
				CRL:      fetchResult.CRL,
				FilePath: url,
				Source:   "downloaded",
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

// isDirectory checks if the given path is a directory.
func isDirectory(path string) (bool, error) {
	info, err := os.Stat(path)
	if err != nil {
		return false, err
	}
	return info.IsDir(), nil
}

// buildNonceOptions creates nonce options from config for OCSP requests (RFC 9654).
func buildNonceOptions(cfg Config) *ocsp.NonceOptions {
	return &ocsp.NonceOptions{
		Length:   cfg.OCSPNonceLength,
		Value:    cfg.OCSPNonceValue,
		Disabled: cfg.NoOCSPNonce,
		Hash:     cfg.OCSPHashAlgorithm,
	}
}

// printOCSPResponseDebug prints OCSP response details for debugging.
func printOCSPResponseDebug(w io.Writer, ocspInfo *ocsp.Info, nonceOpts *ocsp.NonceOptions) {
	if ocspInfo == nil || ocspInfo.Response == nil {
		return
	}
	resp := ocspInfo.Response

	_, _ = fmt.Fprintf(w, "\n[OCSP Debug]\n")
	_, _ = fmt.Fprintf(w, "  URL: %s\n", ocspInfo.FilePath)

	// Print request info
	_, _ = fmt.Fprintf(w, "  Request:\n")
	if ocspInfo.RequestRawLen > 0 {
		_, _ = fmt.Fprintf(w, "    Length: %d bytes\n", ocspInfo.RequestRawLen)
	} else {
		_, _ = fmt.Fprintf(w, "    Length: (unknown)\n")
	}

	// Print hash algorithm used for CertID
	if ocspInfo.RequestHashAlgorithm != "" {
		_, _ = fmt.Fprintf(w, "    CertID Hash Algorithm: %s\n", ocspInfo.RequestHashAlgorithm)
	} else {
		_, _ = fmt.Fprintf(w, "    CertID Hash Algorithm: SHA256 (default)\n")
	}

	// Print nonce request info
	if ocspInfo.RequestNonceLen > 0 {
		_, _ = fmt.Fprintf(w, "    Nonce Length: %d bytes\n", ocspInfo.RequestNonceLen)
		_, _ = fmt.Fprintf(w, "    Nonce (hex): %s\n", ocspInfo.RequestNonceHex)
	} else if nonceOpts != nil && nonceOpts.Disabled {
		_, _ = fmt.Fprintf(w, "    Nonce: disabled\n")
	} else {
		_, _ = fmt.Fprintf(w, "    Nonce: (not requested)\n")
	}

	// Print response info
	var statusStr string
	switch resp.Status {
	case 0:
		statusStr = "Good"
	case 1:
		statusStr = "Revoked"
	case 2:
		statusStr = "Unknown"
	default:
		statusStr = fmt.Sprintf("Unknown(%d)", resp.Status)
	}
	_, _ = fmt.Fprintf(w, "  Response:\n")
	_, _ = fmt.Fprintf(w, "    Status: %s\n", statusStr)
	_, _ = fmt.Fprintf(w, "    ProducedAt: %s\n", resp.ProducedAt.Format("2006-01-02 15:04:05"))
	_, _ = fmt.Fprintf(w, "    ThisUpdate: %s\n", resp.ThisUpdate.Format("2006-01-02 15:04:05"))
	if !resp.NextUpdate.IsZero() {
		_, _ = fmt.Fprintf(w, "    NextUpdate: %s\n", resp.NextUpdate.Format("2006-01-02 15:04:05"))
	} else {
		_, _ = fmt.Fprintf(w, "    NextUpdate: (not set)\n")
	}
	if !resp.RevokedAt.IsZero() {
		_, _ = fmt.Fprintf(w, "    RevokedAt: %s\n", resp.RevokedAt.Format("2006-01-02 15:04:05"))
		_, _ = fmt.Fprintf(w, "    RevocationReason: %d\n", resp.RevocationReason)
	}
	_, _ = fmt.Fprintf(w, "    SerialNumber: %s\n", resp.SerialNumber.String())
	_, _ = fmt.Fprintf(w, "    SignatureAlgorithm: %s\n", resp.SignatureAlgorithm.String())

	// Parse nonce from raw response
	nonceState := ocspzcrypto.ParseNonceFromRaw(resp.Raw)
	_, _ = fmt.Fprintf(w, "    Response Nonce:\n")
	if nonceState.Present {
		_, _ = fmt.Fprintf(w, "      Present: true\n")
		_, _ = fmt.Fprintf(w, "      Length: %d bytes\n", nonceState.Length)
		_, _ = fmt.Fprintf(w, "      Value (hex): %s\n", nonceState.HexValue)
		// Check if nonce matches request
		if ocspInfo.RequestNonceLen > 0 && nonceState.Length == ocspInfo.RequestNonceLen {
			if nonceState.HexValue == ocspInfo.RequestNonceHex {
				_, _ = fmt.Fprintf(w, "      Match: YES (echoed correctly)\n")
			} else {
				_, _ = fmt.Fprintf(w, "      Match: NO (different value)\n")
			}
		} else if ocspInfo.RequestNonceLen > 0 && nonceState.Length != ocspInfo.RequestNonceLen {
			_, _ = fmt.Fprintf(w, "      Match: NO (different length: requested %d, got %d)\n", ocspInfo.RequestNonceLen, nonceState.Length)
		}
	} else {
		_, _ = fmt.Fprintf(w, "      Present: false\n")
	}
	_, _ = fmt.Fprintf(w, "\n")
}