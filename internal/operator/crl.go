package operator

import (
	"github.com/cavoq/PCL/internal/node"
	"github.com/zmap/zcrypto/x509"
)

type CRLValid struct{}

func (CRLValid) Name() string { return "crlValid" }

func (CRLValid) Evaluate(_ *node.Node, ctx *EvaluationContext, _ []any) (bool, error) {
	if !ctx.HasCRLs() {
		return false, nil
	}

	for _, crlInfo := range ctx.CRLs {
		if crlInfo.CRL == nil {
			continue
		}
		crl := crlInfo.CRL

		if ctx.Now.Before(crl.ThisUpdate) {
			return false, nil
		}
		if !crl.NextUpdate.IsZero() && ctx.Now.After(crl.NextUpdate) {
			return false, nil
		}
	}

	return true, nil
}

type CRLNotExpired struct{}

func (CRLNotExpired) Name() string { return "crlNotExpired" }

func (CRLNotExpired) Evaluate(_ *node.Node, ctx *EvaluationContext, _ []any) (bool, error) {
	if !ctx.HasCRLs() {
		return false, nil
	}

	for _, crlInfo := range ctx.CRLs {
		if crlInfo.CRL == nil {
			continue
		}
		crl := crlInfo.CRL

		if !crl.NextUpdate.IsZero() && ctx.Now.After(crl.NextUpdate) {
			return false, nil
		}
	}

	return true, nil
}

type CRLSignedBy struct{}

func (CRLSignedBy) Name() string { return "crlSignedBy" }

func (CRLSignedBy) Evaluate(_ *node.Node, ctx *EvaluationContext, _ []any) (bool, error) {
	if !ctx.HasCRLs() || !ctx.HasChain() {
		return false, nil
	}

	// Track if we found any applicable CRL (CRL whose issuer is in chain)
	var foundApplicableCRL bool
	for _, crlInfo := range ctx.CRLs {
		if crlInfo.CRL == nil {
			continue
		}
		crl := crlInfo.CRL

		// Find issuer in chain
		var crlIssuerInChain *x509.Certificate
		for _, certInfo := range ctx.Chain {
			if certInfo.Cert == nil {
				continue
			}

			if crl.Issuer.String() != certInfo.Cert.Subject.String() {
				continue
			}

			crlIssuerInChain = certInfo.Cert
			break
		}

		// If CRL issuer not in chain, skip this CRL (can't verify)
		if crlIssuerInChain == nil {
			continue
		}

		foundApplicableCRL = true

		// Verify signature
		err := crl.CheckSignatureFrom(crlIssuerInChain)
		if err != nil {
			return false, nil
		}
	}

	// If we found and verified at least one applicable CRL, return true
	// If no CRLs were applicable (all skipped - issuers not in chain), return true (not applicable)
	// The cert-not-revoked rule handles checking revocation status
	_ = foundApplicableCRL // track for future use
	return true, nil
}

type NotRevoked struct{}

func (NotRevoked) Name() string { return "notRevoked" }

func (NotRevoked) Evaluate(_ *node.Node, ctx *EvaluationContext, _ []any) (bool, error) {
	if !ctx.HasCert() {
		return false, nil
	}

	if len(ctx.CRLs) == 0 {
		return true, nil
	}

	cert := ctx.Cert.Cert
	certSerial := cert.SerialNumber.String()
	certIssuer := cert.Issuer.String()

	for _, crlInfo := range ctx.CRLs {
		if crlInfo.CRL == nil {
			continue
		}
		crl := crlInfo.CRL

		if crl.Issuer.String() != certIssuer {
			continue
		}

		for _, revoked := range crl.RevokedCertificates {
			if revoked.SerialNumber != nil && revoked.SerialNumber.String() == certSerial {
				return false, nil
			}
		}
	}

	return true, nil
}
