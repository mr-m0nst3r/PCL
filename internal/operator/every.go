package operator

import (
	"fmt"

	"github.com/cavoq/PCL/internal/node"
)

// Every checks that every element in an array-like node satisfies a condition.
// Operands format (map):
//   - path: sub-path relative to each element (optional, empty means check element itself)
//   - check: operator name to apply to each element
//   - values: operands for the check operator (optional)
//   - skipMissing: if true, skip elements where path doesn't exist (default: false)
//
// Example YAML usage:
//   target: crl.revokedCertificates
//   operator: every
//   operands:
//     path: extensions.2.5.29.21.value
//     check: in
//     values: [1, 3, 4, 5, 9]
type Every struct{}

func (Every) Name() string { return "every" }

func (Every) Evaluate(n *node.Node, ctx *EvaluationContext, operands []any) (bool, error) {
	if n == nil {
		return false, nil
	}

	// Parse operands
	if len(operands) == 0 {
		return false, fmt.Errorf("every operator requires operands")
	}

	// Operands can be a map or we parse from slice
	var subPath string
	var checkOp string
	var checkOperands []any
	var skipMissing bool

	// Try parsing as map first
	if m, ok := operands[0].(map[string]any); ok {
		if p, ok := m["path"].(string); ok {
			subPath = p
		}
		if c, ok := m["check"].(string); ok {
			checkOp = c
		}
		if v, ok := m["values"]; ok {
			if slice, ok := v.([]any); ok {
				checkOperands = slice
			} else {
				checkOperands = []any{v}
			}
		}
		if s, ok := m["skipMissing"].(bool); ok {
			skipMissing = s
		}
	} else {
		// Alternative: parse as [path, check, values...]
		if len(operands) >= 2 {
			if p, ok := operands[0].(string); ok {
				subPath = p
			}
			if c, ok := operands[1].(string); ok {
				checkOp = c
			}
			if len(operands) > 2 {
				checkOperands = operands[2:]
			}
		}
	}

	if checkOp == "" {
		return false, fmt.Errorf("every operator requires 'check' operand")
	}

	// Get the check operator from registry
	registry := DefaultRegistry()
	op, err := registry.Get(checkOp)
	if err != nil {
		return false, fmt.Errorf("every: unknown check operator '%s'", checkOp)
	}

	// If node has no children (empty array), trivially true
	if len(n.Children) == 0 {
		return true, nil
	}

	// Check each child
	for _, child := range n.Children {
		if child == nil {
			continue
		}

		// Resolve sub-path if provided
		var targetNode *node.Node
		if subPath == "" {
			targetNode = child
		} else {
			targetNode = resolvePath(child, subPath)
			if targetNode == nil {
				if skipMissing {
					continue // Skip this element
				}
				return false, nil // Element doesn't have required path
			}
		}

		// Apply check operator
		result, err := op.Evaluate(targetNode, ctx, checkOperands)
		if err != nil {
			return false, err
		}
		if !result {
			return false, nil // At least one element failed
		}
	}

	return true, nil
}

// resolvePath resolves a dot-separated path from a node.
// Handles OID-style keys that contain dots (e.g., "2.5.29.21").
func resolvePath(n *node.Node, path string) *node.Node {
	if n == nil || path == "" {
		return n
	}

	current := n
	parts := splitPath(path)

	for i := 0; i < len(parts); i++ {
		if current == nil || current.Children == nil {
			return nil
		}

		// Try to find child with exact match
		part := parts[i]
		next := current.Children[part]

		// If not found and part looks like OID start (numeric),
		// try combining with subsequent parts to find OID key
		if next == nil && isOIDStart(part) && i+1 < len(parts) {
			// Try progressively combining parts until we find a match
			for j := i + 1; j <= len(parts); j++ {
				combined := combineParts(parts, i, j)
				if current.Children[combined] != nil {
					next = current.Children[combined]
					i = j - 1 // Skip the combined parts
					break
				}
			}
		}

		if next == nil {
			return nil
		}
		current = next
	}

	return current
}

// isOIDStart checks if a part looks like the start of an OID (numeric).
func isOIDStart(s string) bool {
	if len(s) == 0 {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// combineParts combines parts from i to j (exclusive) with dots.
func combineParts(parts []string, i, j int) string {
	result := parts[i]
	for k := i + 1; k < j; k++ {
		result += "." + parts[k]
	}
	return result
}

// splitPath splits a path by dots, handling numeric indices.
func splitPath(path string) []string {
	var parts []string
	start := 0
	for i := 0; i < len(path); i++ {
		if path[i] == '.' {
			if i > start {
				parts = append(parts, path[start:i])
			}
			start = i + 1
		}
	}
	if start < len(path) {
		parts = append(parts, path[start:])
	}
	return parts
}