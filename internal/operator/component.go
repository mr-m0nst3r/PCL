package operator

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/cavoq/PCL/internal/node"
)

// ComponentMaxLength validates that each component of a delimited string
// does not exceed the specified maximum length.
// This is useful for DNS label validation (max 63 chars per label),
// path segment validation, and other component-based string formats.
//
// Handles both:
// - Single string value: splits by delimiter and validates each component
// - Parent node with children: validates each child's string value
//
// Operands: [maxLength, delimiter]
// - maxLength: maximum length for each component (integer)
// - delimiter: character that separates components (string, default ".")
type ComponentMaxLength struct{}

func (ComponentMaxLength) Name() string { return "componentMaxLength" }

func (ComponentMaxLength) Evaluate(n *node.Node, _ *EvaluationContext, operands []any) (bool, error) {
	if n == nil || len(operands) < 1 {
		return false, nil
	}

	maxLen, ok := ToInt(operands[0])
	if !ok {
		return false, fmt.Errorf("componentMaxLength requires integer max length operand")
	}

	delimiter := "."
	if len(operands) >= 2 {
		if d, ok := operands[1].(string); ok && d != "" {
			delimiter = d
		}
	}

	// Handle parent node with children (like dNSName with indexed children)
	if n.Value == nil && len(n.Children) > 0 {
		for _, child := range n.Children {
			str, ok := child.Value.(string)
			if !ok {
				continue
			}
			if !validateComponentMaxLength(str, maxLen, delimiter) {
				return false, nil
			}
		}
		return true, nil
	}

	// Handle single string value
	str, ok := n.Value.(string)
	if !ok {
		return false, nil
	}

	return validateComponentMaxLength(str, maxLen, delimiter), nil
}

func validateComponentMaxLength(str string, maxLen int, delimiter string) bool {
	components := strings.Split(str, delimiter)
	for _, comp := range components {
		if len(comp) > maxLen {
			return false
		}
	}
	return true
}

// ComponentMinLength validates that each component of a delimited string
// meets the specified minimum length.
//
// Handles both:
// - Single string value: splits by delimiter and validates each component
// - Parent node with children: validates each child's string value
type ComponentMinLength struct{}

func (ComponentMinLength) Name() string { return "componentMinLength" }

func (ComponentMinLength) Evaluate(n *node.Node, _ *EvaluationContext, operands []any) (bool, error) {
	if n == nil || len(operands) < 1 {
		return false, nil
	}

	minLen, ok := ToInt(operands[0])
	if !ok {
		return false, fmt.Errorf("componentMinLength requires integer min length operand")
	}

	delimiter := "."
	if len(operands) >= 2 {
		if d, ok := operands[1].(string); ok && d != "" {
			delimiter = d
		}
	}

	// Handle parent node with children
	if n.Value == nil && len(n.Children) > 0 {
		for _, child := range n.Children {
			str, ok := child.Value.(string)
			if !ok {
				continue
			}
			if !validateComponentMinLength(str, minLen, delimiter) {
				return false, nil
			}
		}
		return true, nil
	}

	// Handle single string value
	str, ok := n.Value.(string)
	if !ok {
		return false, nil
	}

	return validateComponentMinLength(str, minLen, delimiter), nil
}

func validateComponentMinLength(str string, minLen int, delimiter string) bool {
	components := strings.Split(str, delimiter)
	for _, comp := range components {
		if len(comp) < minLen {
			return false
		}
	}
	return true
}

// ComponentRegex validates that each component of a delimited string
// matches the specified regex pattern.
//
// Handles both:
// - Single string value: splits by delimiter and validates each component
// - Parent node with children: validates each child's string value
type ComponentRegex struct{}

func (ComponentRegex) Name() string { return "componentRegex" }

func (ComponentRegex) Evaluate(n *node.Node, _ *EvaluationContext, operands []any) (bool, error) {
	if n == nil || len(operands) < 1 {
		return false, nil
	}

	pattern, ok := operands[0].(string)
	if !ok {
		return false, fmt.Errorf("componentRegex requires string pattern operand")
	}

	re, err := getCompiledRegex(pattern)
	if err != nil {
		return false, err
	}

	delimiter := "."
	if len(operands) >= 2 {
		if d, ok := operands[1].(string); ok && d != "" {
			delimiter = d
		}
	}

	// Handle parent node with children
	if n.Value == nil && len(n.Children) > 0 {
		for _, child := range n.Children {
			str, ok := child.Value.(string)
			if !ok {
				continue
			}
			if !validateComponentRegex(str, re, delimiter) {
				return false, nil
			}
		}
		return true, nil
	}

	// Handle single string value
	str, ok := n.Value.(string)
	if !ok {
		return false, nil
	}

	return validateComponentRegex(str, re, delimiter), nil
}

func validateComponentRegex(str string, re *regexp.Regexp, delimiter string) bool {
	components := strings.Split(str, delimiter)
	for _, comp := range components {
		if !re.MatchString(comp) {
			return false
		}
	}
	return true
}

// ComponentNotRegex validates that each component of a delimited string
// does NOT match the specified regex pattern.
//
// Handles both:
// - Single string value: splits by delimiter and validates each component
// - Parent node with children: validates each child's string value
type ComponentNotRegex struct{}

func (ComponentNotRegex) Name() string { return "componentNotRegex" }

func (ComponentNotRegex) Evaluate(n *node.Node, _ *EvaluationContext, operands []any) (bool, error) {
	if n == nil || len(operands) < 1 {
		return false, nil
	}

	pattern, ok := operands[0].(string)
	if !ok {
		return false, fmt.Errorf("componentNotRegex requires string pattern operand")
	}

	re, err := getCompiledRegex(pattern)
	if err != nil {
		return false, err
	}

	delimiter := "."
	if len(operands) >= 2 {
		if d, ok := operands[1].(string); ok && d != "" {
			delimiter = d
		}
	}

	// Handle parent node with children
	if n.Value == nil && len(n.Children) > 0 {
		for _, child := range n.Children {
			str, ok := child.Value.(string)
			if !ok {
				continue
			}
			if !validateComponentNotRegex(str, re, delimiter) {
				return false, nil
			}
		}
		return true, nil
	}

	// Handle single string value
	str, ok := n.Value.(string)
	if !ok {
		return false, nil
	}

	return validateComponentNotRegex(str, re, delimiter), nil
}

func validateComponentNotRegex(str string, re *regexp.Regexp, delimiter string) bool {
	components := strings.Split(str, delimiter)
	for _, comp := range components {
		if re.MatchString(comp) {
			return false
		}
	}
	return true
}