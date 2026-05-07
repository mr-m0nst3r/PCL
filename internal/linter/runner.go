package linter

import (
	"fmt"
	"io"
	"os"
	"time"

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

	if hasCert {
		// Load leaf certificates
		var certs []*cert.Info //nolint:prealloc // certs is overwritten by loadCertificates
		var certCleanup func()

		certs, certCleanup, err = loadCertificates(cfg)
		if err != nil {
			return err
		}
		if certCleanup != nil {
			// Combine cleanup functions: both issuer and cert cleanups need to run
			prevCleanup := cleanup
			cleanup = func() {
				certCleanup()
				if prevCleanup != nil {
					prevCleanup()
				}
			}
		}

		// Schedule cleanup at the end of processing (for downloaded certs/issuers)
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