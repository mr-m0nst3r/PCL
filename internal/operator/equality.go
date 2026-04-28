package operator

import (
	"fmt"
	"reflect"

	"github.com/cavoq/PCL/internal/node"
)

type Eq struct{}

func (Eq) Name() string { return "eq" }

func (Eq) Evaluate(n *node.Node, _ *EvaluationContext, operands []any) (bool, error) {
	if len(operands) != 1 {
		return false, nil
	}

	// Handle nil node for implicit false boolean comparison
	if n == nil {
		// For keyUsage boolean fields, nil means implicit false
		// eq false on nil → true (PASS)
		// eq true on nil → false (FAIL)
		if b, ok := operands[0].(bool); ok {
			return !b, nil // nil == false, so eq false = true, eq true = false
		}
		return false, nil
	}

	return reflect.DeepEqual(n.Value, operands[0]), nil
}

type Neq struct{}

func (Neq) Name() string { return "neq" }

func (Neq) Evaluate(n *node.Node, _ *EvaluationContext, operands []any) (bool, error) {
	if len(operands) != 1 {
		return false, nil
	}

	// Handle nil node for implicit false boolean comparison
	if n == nil {
		// For keyUsage boolean fields, nil means implicit false
		// neq false on nil → false (nil == false, so not equal is false)
		// neq true on nil → true (PASS, because nil != true)
		if b, ok := operands[0].(bool); ok {
			return b, nil // nil == false, so neq false = false, neq true = true
		}
		return false, nil
	}

	return !reflect.DeepEqual(n.Value, operands[0]), nil
}

type Matches struct{}

func (Matches) Name() string { return "matches" }

func (Matches) Evaluate(n *node.Node, ctx *EvaluationContext, operands []any) (bool, error) {
	if n == nil || len(operands) != 1 {
		return false, nil
	}

	path, ok := operands[0].(string)
	if !ok {
		return false, fmt.Errorf("matches operator requires a string path operand")
	}

	target, found := ctx.Root.Resolve(path)
	if !found || target == nil {
		return false, nil
	}

	return reflect.DeepEqual(n.Value, target.Value), nil
}
