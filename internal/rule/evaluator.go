package rule

import (
	"fmt"
	"slices"
	"strings"

	"github.com/cavoq/PCL/internal/node"
	"github.com/cavoq/PCL/internal/operator"
)

const (
	VerdictPass = "pass"
	VerdictFail = "fail"
	VerdictSkip = "skip"
)

type Result struct {
	RuleID    string `json:"rule_id" yaml:"rule_id"`
	Reference string `json:"reference,omitempty" yaml:"reference,omitempty"`
	Verdict   string `json:"verdict" yaml:"verdict"`
	Severity  string `json:"severity" yaml:"severity"`
	Message   string `json:"message,omitempty" yaml:"message,omitempty"`
}

func Evaluate(
	root *node.Node,
	r Rule,
	reg *operator.Registry,
	ctx *operator.EvaluationContext,
) Result {
	// Check if rule target matches the input type
	if !targetMatchesInputType(root, r.Target) {
		return Result{
			RuleID:    r.ID,
			Reference: r.Reference,
			Verdict:   VerdictSkip,
			Severity:  r.Severity,
			Message:   "rule target does not match input type",
		}
	}

	if !appliesTo(r, ctx) {
		return Result{
			RuleID:    r.ID,
			Reference: r.Reference,
			Verdict:   VerdictSkip,
			Severity:  r.Severity,
		}
	}

	if r.When != nil {
		conditionMet, err := evaluateCondition(root, r.When, reg, ctx)
		if err != nil {
			return Result{
				RuleID:    r.ID,
				Reference: r.Reference,
				Verdict:   VerdictFail,
				Message:   "when condition error: " + err.Error(),
				Severity:  r.Severity,
			}
		}
		if !conditionMet {
			return Result{
				RuleID:    r.ID,
				Reference: r.Reference,
				Verdict:   VerdictSkip,
				Severity:  r.Severity,
			}
		}
	}

	n, found := root.Resolve(r.Target)

	// For presence/absence/null operators, continue evaluation even if target not found
	// present: returns false when target not found (expected behavior)
	// absent: returns true when target not found (expected behavior)
	// isNull: returns false when target not found (absent is not NULL)
	// For eq/neq operators on keyUsage boolean fields, treat missing as implicit false
	// For other operators, skip when target not found (e.g., certificate rules when processing CRLs)
	if !found && r.Operator != "present" && r.Operator != "absent" && r.Operator != "isNull" {
		// Special handling for eq/neq on keyUsage boolean fields
		if (r.Operator == "eq" || r.Operator == "neq") && isKeyUsageBooleanField(r.Target) {
			// Missing keyUsage bit = implicit false
			// For eq true: false != true → FAIL
			// For eq false: false == false → PASS
			// For neq true: false != true → PASS
			// For neq false: false == false → FAIL
			var targetNode *node.Node
			op, err := reg.Get(r.Operator)
			if err != nil {
				return Result{
					RuleID:    r.ID,
					Reference: r.Reference,
					Verdict:   VerdictFail,
					Message:   fmt.Sprintf("operator not found: %s", r.Operator),
					Severity:  r.Severity,
				}
			}
			ok, err := op.Evaluate(targetNode, ctx, r.Operands)
			if err != nil {
				return Result{
					RuleID:    r.ID,
					Reference: r.Reference,
					Verdict:   VerdictFail,
					Message:   fmt.Sprintf("operator %s on %s: %v", r.Operator, r.Target, err),
					Severity:  r.Severity,
				}
			}
			verdict := VerdictPass
			if !ok {
				verdict = VerdictFail
			}
			return Result{
				RuleID:    r.ID,
				Reference: r.Reference,
				Verdict:   verdict,
				Severity:  r.Severity,
			}
		}
		return Result{
			RuleID:    r.ID,
			Reference: r.Reference,
			Verdict:   VerdictSkip,
			Severity:  r.Severity,
			Message:   "target not found: " + r.Target,
		}
	}

	// Pass nil node if target not found (for present/absent operators)
	var targetNode *node.Node
	if found {
		targetNode = n
	}

	op, err := reg.Get(r.Operator)
	if err != nil {
		return Result{
			RuleID:    r.ID,
			Reference: r.Reference,
			Verdict:   VerdictFail,
			Message:   fmt.Sprintf("operator not found: %s", r.Operator),
			Severity:  r.Severity,
		}
	}

	ok, err := op.Evaluate(targetNode, ctx, r.Operands)
	if err != nil {
		return Result{
			RuleID:    r.ID,
			Reference: r.Reference,
			Verdict:   VerdictFail,
			Message:   fmt.Sprintf("operator %s on %s: %v", r.Operator, r.Target, err),
			Severity:  r.Severity,
		}
	}

	verdict := VerdictPass
	if !ok {
		verdict = VerdictFail
	}

	return Result{
		RuleID:    r.ID,
		Reference: r.Reference,
		Verdict:   verdict,
		Severity:  r.Severity,
	}
}

func evaluateCondition(
	root *node.Node,
	cond *Condition,
	reg *operator.Registry,
	ctx *operator.EvaluationContext,
) (bool, error) {
	n, _ := root.Resolve(cond.Target)

	op, err := reg.Get(cond.Operator)
	if err != nil {
		return false, fmt.Errorf("operator not found: %s", cond.Operator)
	}

	return op.Evaluate(n, ctx, cond.Operands)
}

func appliesTo(r Rule, ctx *operator.EvaluationContext) bool {
	if len(r.AppliesTo) == 0 {
		return true
	}
	if ctx == nil || ctx.Cert == nil {
		return true
	}
	return slices.Contains(r.AppliesTo, ctx.Cert.Type)
}

// isKeyUsageBooleanField checks if the target is a keyUsage boolean field.
// These fields represent key usage bits that are implicitly false when not present.
func isKeyUsageBooleanField(target string) bool {
	keyUsageFields := []string{
		"certificate.keyUsage.digitalSignature",
		"certificate.keyUsage.nonRepudiation",
		"certificate.keyUsage.contentCommitment",
		"certificate.keyUsage.keyEncipherment",
		"certificate.keyUsage.dataEncipherment",
		"certificate.keyUsage.keyAgreement",
		"certificate.keyUsage.keyCertSign",
		"certificate.keyUsage.cRLSign",
		"certificate.keyUsage.encipherOnly",
		"certificate.keyUsage.decipherOnly",
	}
	return slices.Contains(keyUsageFields, target)
}

// targetMatchesInputType checks if the rule's target is compatible with the input type.
// Returns true if the target prefix matches the tree structure, or if target is generic.
// Returns false if target prefix doesn't match (e.g., certificate rule on CRL input).
func targetMatchesInputType(root *node.Node, target string) bool {
	if root == nil {
		return true // No tree, can't determine type
	}

	return matchesTreePrefix(root, target)
}

// matchesTreePrefix checks if the target's prefix matches the tree structure.
// Returns true if:
// - target prefix matches root.Name (Resolve will skip this prefix)
// - target prefix exists as child in tree
// - target is generic (no known prefix)
func matchesTreePrefix(root *node.Node, target string) bool {
	// Extract prefix from target (e.g., "certificate" from "certificate.xxx")
	prefix := extractPrefix(target)
	if prefix == "" {
		return true // Generic target, applies to all
	}

	// If prefix matches root name, Resolve will skip it and work correctly
	if root.Name == prefix {
		return true
	}

	// Check if prefix exists as child in tree
	if root.Children != nil {
		_, exists := root.Children[prefix]
		return exists
	}

	return false
}

// extractPrefix extracts the input type prefix from a target string.
// E.g., "certificate.xxx" -> "certificate", "crl.xxx" -> "crl"
func extractPrefix(target string) string {
	// Check known prefixes
	if strings.HasPrefix(target, "certificate.") || target == "certificate" {
		return "certificate"
	}
	if strings.HasPrefix(target, "crl.") || target == "crl" {
		return "crl"
	}
	if strings.HasPrefix(target, "ocsp.") || target == "ocsp" {
		return "ocsp"
	}
	return "" // Unknown or generic target
}