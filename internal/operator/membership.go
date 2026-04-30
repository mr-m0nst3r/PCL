package operator

import (
	"fmt"
	"reflect"
	"strings"

	"github.com/cavoq/PCL/internal/node"
)

type In struct{}

func (In) Name() string { return "in" }

func (In) Evaluate(n *node.Node, _ *EvaluationContext, operands []any) (bool, error) {
	if n == nil {
		return false, nil
	}
	if len(operands) == 0 {
		return false, fmt.Errorf("in requires at least 1 operand")
	}
	for _, op := range operands {
		if equal(n.Value, op) {
			return true, nil
		}
	}
	return false, nil
}

type NotIn struct{}

func (NotIn) Name() string { return "notIn" }

func (NotIn) Evaluate(n *node.Node, _ *EvaluationContext, operands []any) (bool, error) {
	if n == nil {
		return false, nil
	}
	if len(operands) == 0 {
		return false, fmt.Errorf("notIn requires at least 1 operand")
	}
	for _, op := range operands {
		if equal(n.Value, op) {
			return false, nil
		}
	}
	return true, nil
}

type Contains struct{}

func (Contains) Name() string { return "contains" }

func (Contains) Evaluate(n *node.Node, _ *EvaluationContext, operands []any) (bool, error) {
	if n == nil {
		return false, nil
	}
	if len(operands) == 0 {
		return false, fmt.Errorf("contains requires at least 1 operand")
	}

	val := reflect.ValueOf(n.Value)
	if val.Kind() == reflect.Slice || val.Kind() == reflect.Array {
		for i := 0; i < val.Len(); i++ {
			for _, target := range operands {
				if equal(val.Index(i).Interface(), target) {
					return true, nil
				}
			}
		}
		return false, nil
	}

	if len(n.Children) > 0 {
		// First check child values
		for _, child := range n.Children {
			for _, target := range operands {
				if equal(child.Value, target) {
					return true, nil
				}
			}
		}
		// Also check child names (for cases like certificatePolicies where key is OID)
		for name := range n.Children {
			for _, target := range operands {
				if equal(name, target) {
					return true, nil
				}
			}
		}
		return false, nil
	}

	if str, ok := n.Value.(string); ok {
		for _, target := range operands {
			if substr, ok := target.(string); ok {
				if len(str) > 0 && len(substr) > 0 && strings.Contains(str, substr) {
					return true, nil
				}
			}
		}
		return false, nil
	}

	return false, fmt.Errorf("contains requires a slice, array, node with children, or string")
}

func equal(a, b any) bool {
	if a == b {
		return true
	}
	af, aok := ToFloat64(a)
	bf, bok := ToFloat64(b)
	if aok && bok {
		return af == bf
	}
	return fmt.Sprintf("%v", a) == fmt.Sprintf("%v", b)
}
