package linter

import "time"

type Config struct {
	PolicyPath   string
	CertPath     string
	CertURLs     []string
	CertTimeout  time.Duration
	CertSaveDir  string
	IssuerPath   string   // Single issuer path (backward compatible)
	IssuerPaths  []string // Multiple issuer paths
	IssuerURLs   []string
	CRLPath      string
	OCSPPath     string
	AutoOCSP     bool
	OCSPTimeout  time.Duration
	OutputFmt    string
	Verbosity    int
	ShowMeta     bool

	// Auto-validate mode options
	AutoValidate     bool   // Enable automatic PKI resource fetching
	AutoValidateOCSP bool   // Fetch OCSP from AIA (default true when AutoValidate)
	AutoValidateCRL  bool   // Fetch CRL from CRL DP (default true when AutoValidate)
	AutoValidateChain bool   // Climb chain via CA Issuers URLs (default true when AutoValidate)
	MaxChainDepth    int    // Maximum chain depth for climbing (default 10)
}
