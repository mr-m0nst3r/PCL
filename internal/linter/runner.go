package linter

import (
	"fmt"
	"io"
	"time"

	"github.com/cavoq/PCL/internal/cert"
	"github.com/cavoq/PCL/internal/cert/zcrypto"
	"github.com/cavoq/PCL/internal/crl"
	crlzcrypto "github.com/cavoq/PCL/internal/crl/zcrypto"
	"github.com/cavoq/PCL/internal/ocsp"
	"github.com/cavoq/PCL/internal/operator"
	"github.com/cavoq/PCL/internal/output"
	"github.com/cavoq/PCL/internal/policy"
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
	if cfg.CertPath != "" || len(cfg.CertURLs) > 0 {
		certs, cleanup, err := loadCertificates(cfg)
		if cleanup != nil {
			defer cleanup()
		}
		if err != nil {
			return err
		}

		chain, err := cert.BuildChain(certs)
		if err != nil {
			return fmt.Errorf("failed to build chain: %w", err)
		}

		for _, c := range chain {
			tree := zcrypto.BuildTree(c.Cert)

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

			for _, p := range policies {
				res := policy.Evaluate(p, tree, reg, ctx)
				results = append(results, res)
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

			for _, p := range policies {
				res := policy.Evaluate(p, tree, reg, ctx)
				results = append(results, res)
			}
		}
	} else if len(ocsps) > 0 {
		// Process OCSP independently when no certificates/CRLs provided
		// TODO: Add OCSP-only evaluation if needed
		return fmt.Errorf("OCSP-only evaluation requires a certificate")
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
		return nil, cleanup, fmt.Errorf("no certificates provided")
	}

	return certs, cleanup, nil
}

func applyDefaults(cfg *Config) {
	if cfg.CertTimeout <= 0 {
		cfg.CertTimeout = 10 * time.Second
	}
	if cfg.OutputFmt == "" {
		cfg.OutputFmt = "text"
	}
}
