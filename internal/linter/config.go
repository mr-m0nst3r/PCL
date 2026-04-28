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
}
