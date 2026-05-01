package rule

type Condition struct {
	Target   string `yaml:"target"`
	Operator string `yaml:"operator"`
	Operands any    `yaml:"operands"` // Can be []any or map[string]any
}

type Rule struct {
	ID        string     `yaml:"id"`
	Reference string     `yaml:"reference,omitempty"`
	Target    string     `yaml:"target"`
	Operator  string     `yaml:"operator"`
	Operands  any        `yaml:"operands"` // Can be []any or map[string]any
	Severity  string     `yaml:"severity"`
	AppliesTo []string   `yaml:"appliesTo,omitempty"`
	When      *Condition `yaml:"when,omitempty"`
}
