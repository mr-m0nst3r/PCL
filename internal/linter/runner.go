package linter

import (
	certstd "crypto/x509"
	"fmt"
	"io"
	"time"

	"github.com/cavoq/PCL/internal/cert"
	certzcrypto "github.com/cavoq/PCL/internal/cert/zcrypto"
	"github.com/cavoq/PCL/internal/crl"
	crlzcrypto "github.com/cavoq/PCL/internal/crl/zcrypto"
	"github.com/cavoq/PCL/internal/ocsp"
	ocspzcrypto "github.com/cavoq/PCL/internal/ocsp/zcrypto"
	"github.com/cavoq/PCL/internal/operator"
	"github.com/cavoq/PCL/internal/output"
	"github.com/cavoq/PCL/internal/policy"
	"github.com/cavoq/PCL/internal/zcrypto"
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

		chain, err := cert.BuildChain(allCerts)
		if err != nil {
			return fmt.Errorf("failed to build chain: %w", err)
		}

		// Auto-fetch OCSP if enabled and chain has issuer
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