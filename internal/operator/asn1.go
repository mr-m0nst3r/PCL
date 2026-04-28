package operator

import (
	"github.com/cavoq/PCL/internal/node"
)

// IsNull checks if the node represents an ASN.1 NULL value.
// Used for checking AlgorithmIdentifier parameters per RFC 4055.
type IsNull struct{}

func (IsNull) Name() string { return "isNull" }

func (IsNull) Evaluate(n *node.Node, _ *EvaluationContext, _ []any) (bool, error) {
	if n == nil {
		return false, nil
	}

	nullNode, ok := n.Children["null"]
	if !ok {
		return false, nil
	}

	if v, ok := nullNode.Value.(bool); ok {
		return v, nil
	}

	return false, nil
}

// IsAbsent checks if the node represents an absent/missing parameter.
// Used for checking AlgorithmIdentifier parameters that should not be absent per RFC 4055.
type IsAbsent struct{}

func (IsAbsent) Name() string { return "isAbsent" }

func (IsAbsent) Evaluate(n *node.Node, _ *EvaluationContext, _ []any) (bool, error) {
	if n == nil {
		return true, nil
	}

	absentNode, ok := n.Children["absent"]
	if !ok {
		return false, nil
	}

	if v, ok := absentNode.Value.(bool); ok {
		return v, nil
	}

	return false, nil
}