package main

import (
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/cavoq/PCL/internal/linter"
)

func newRootCmd(opts *linter.Config) *cobra.Command {
	root := &cobra.Command{
		Use:   "pcl",
		Short: "Policy-based X.509 certificate linter",
		RunE: func(cmd *cobra.Command, args []string) error {
			if opts.PolicyPath == "" {
				return fmt.Errorf("--policy is required")
			}
			hasCert := opts.CertPath != "" || len(opts.CertURLs) > 0
			hasIssuer := len(opts.IssuerPaths) > 0 || len(opts.IssuerURLs) > 0
			if !hasCert && !hasIssuer && opts.CRLPath == "" && opts.OCSPPath == "" {
				return fmt.Errorf("at least one of --cert, --cert-url, --issuer, --issuer-url, --crl, or --ocsp is required")
			}
			if opts.AutoOCSP && !hasIssuer {
				return fmt.Errorf("--auto-ocsp requires --issuer or --issuer-url")
			}
			return linter.Run(*opts, cmd.OutOrStdout())
		},
	}

	root.Flags().StringVar(&opts.PolicyPath, "policy", "", "Path to policy YAML file or directory")
	root.Flags().StringVar(&opts.CertPath, "cert", "", "Path to certificate file or directory (PEM/DER)")
	root.Flags().StringSliceVar(&opts.CertURLs, "cert-url", nil, "Certificate URL (repeatable)")
	root.Flags().DurationVar(&opts.CertTimeout, "cert-url-timeout", 10*time.Second, "Certificate URL timeout (e.g. 10s, 1m)")
	root.Flags().StringVar(&opts.CertSaveDir, "cert-url-save-dir", "", "Directory to save downloaded certs (optional)")
	root.Flags().StringSliceVar(&opts.IssuerPaths, "issuer", nil, "Path to issuer certificate file or directory (repeatable, PEM/DER)")
	root.Flags().StringSliceVar(&opts.IssuerURLs, "issuer-url", nil, "Issuer certificate URL (repeatable)")
	root.Flags().StringVar(&opts.CRLPath, "crl", "", "Path to CRL file or directory (PEM/DER)")
	root.Flags().StringVar(&opts.OCSPPath, "ocsp", "", "Path to OCSP response file or directory (DER/PEM)")
	root.Flags().BoolVar(&opts.AutoOCSP, "auto-ocsp", false, "Automatically fetch OCSP response from certificate's AIA extension (requires issuer)")
	root.Flags().DurationVar(&opts.OCSPTimeout, "ocsp-url-timeout", 5*time.Second, "OCSP request timeout (e.g. 5s, 10s)")
	root.Flags().StringVar(&opts.OutputFmt, "output", "text", "Output format: text, json, or yaml")
	root.Flags().CountVarP(&opts.Verbosity, "verbose", "v", "Increase output detail: -v shows passed, -vv includes skipped")
	root.Flags().BoolVar(&opts.ShowMeta, "show-meta", true, "Show lint meta information")

	// Auto-validate mode flags
	root.Flags().BoolVar(&opts.AutoValidate, "auto-validate", false, "Enable automatic PKI resource fetching (OCSP, CRL, chain climbing)")
	root.Flags().BoolVar(&opts.AutoValidateOCSP, "auto-ocsp-chain", true, "Fetch OCSP for all certificates in chain (only with --auto-validate)")
	root.Flags().BoolVar(&opts.AutoValidateCRL, "auto-crl", true, "Fetch CRLs from CRL Distribution Points (only with --auto-validate)")
	root.Flags().BoolVar(&opts.AutoValidateChain, "auto-chain", true, "Climb chain via CA Issuers URLs (only with --auto-validate)")
	root.Flags().IntVar(&opts.MaxChainDepth, "max-chain-depth", 10, "Maximum chain depth for climbing (only with --auto-validate)")

	return root
}

func main() {
	var opts linter.Config

	if err := newRootCmd(&opts).Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}