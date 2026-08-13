package adapters

import (
	"fmt"
	"strings"

	"k8s.io/apimachinery/pkg/labels"
)

// Calico does not use Kubernetes LabelSelector objects. Its selectors are a
// small expression language written as a string ("app == 'db' && !has(legacy)"),
// so evaluating a Calico policy at all means parsing it.
//
// This parser covers the label-matching subset: all(), global(), has(k),
// k == 'v', k != 'v', k in {'a','b'}, k not in {...}, !, &&, ||, and grouping.
// The string-matching operators (contains, starts with, ends with) and anything
// else the grammar allows are rejected with an error, which the Calico adapter
// turns into an Unknown verdict rather than a guessed match.

type calicoExpr interface {
	eval(set labels.Set) bool
}

type calicoAll struct{}

func (calicoAll) eval(labels.Set) bool { return true }

// calicoGlobal is global(), which selects global network sets. A pod endpoint
// is never one, so it evaluates false rather than unknown.
type calicoGlobal struct{}

func (calicoGlobal) eval(labels.Set) bool { return false }

type calicoHas struct{ key string }

func (h calicoHas) eval(set labels.Set) bool { _, ok := set[h.key]; return ok }

type calicoEquals struct {
	key, value string
	negate     bool
}

func (e calicoEquals) eval(set labels.Set) bool {
	v, ok := set[e.key]
	return (ok && v == e.value) != e.negate
}

type calicoIn struct {
	key    string
	values []string
	negate bool
}

func (i calicoIn) eval(set labels.Set) bool {
	v, ok := set[i.key]
	found := false
	if ok {
		for _, candidate := range i.values {
			if v == candidate {
				found = true
				break
			}
		}
	}
	return found != i.negate
}

type calicoNot struct{ inner calicoExpr }

func (n calicoNot) eval(set labels.Set) bool { return !n.inner.eval(set) }

type calicoAnd struct{ left, right calicoExpr }

func (a calicoAnd) eval(set labels.Set) bool { return a.left.eval(set) && a.right.eval(set) }

type calicoOr struct{ left, right calicoExpr }

func (o calicoOr) eval(set labels.Set) bool { return o.left.eval(set) || o.right.eval(set) }

// parseCalicoSelector compiles a Calico selector string. The empty string is
// Calico's "match everything", which is why it is not an error.
func parseCalicoSelector(s string) (calicoExpr, error) {
	if strings.TrimSpace(s) == "" {
		return calicoAll{}, nil
	}
	p := &calicoParser{in: []rune(s)}
	expr, err := p.parseOr()
	if err != nil {
		return nil, err
	}
	p.skipSpace()
	if p.pos < len(p.in) {
		return nil, fmt.Errorf("unexpected %q at position %d", string(p.in[p.pos:]), p.pos)
	}
	return expr, nil
}

type calicoParser struct {
	in  []rune
	pos int
}

func (p *calicoParser) skipSpace() {
	for p.pos < len(p.in) && (p.in[p.pos] == ' ' || p.in[p.pos] == '\t' || p.in[p.pos] == '\n') {
		p.pos++
	}
}

func (p *calicoParser) accept(tok string) bool {
	p.skipSpace()
	if strings.HasPrefix(string(p.in[p.pos:]), tok) {
		p.pos += len([]rune(tok))
		return true
	}
	return false
}

// acceptWord accepts a bare keyword only when it is not glued to a longer
// identifier, so "notch == 'x'" is not mistaken for the "not in" operator.
func (p *calicoParser) acceptWord(word string) bool {
	p.skipSpace()
	rest := p.in[p.pos:]
	if !strings.HasPrefix(string(rest), word) {
		return false
	}
	next := len([]rune(word))
	if next < len(rest) && isCalicoKeyRune(rest[next]) {
		return false
	}
	p.pos += next
	return true
}

func (p *calicoParser) parseOr() (calicoExpr, error) {
	left, err := p.parseAnd()
	if err != nil {
		return nil, err
	}
	for p.accept("||") {
		right, err := p.parseAnd()
		if err != nil {
			return nil, err
		}
		left = calicoOr{left: left, right: right}
	}
	return left, nil
}

func (p *calicoParser) parseAnd() (calicoExpr, error) {
	left, err := p.parseUnary()
	if err != nil {
		return nil, err
	}
	for p.accept("&&") {
		right, err := p.parseUnary()
		if err != nil {
			return nil, err
		}
		left = calicoAnd{left: left, right: right}
	}
	return left, nil
}

func (p *calicoParser) parseUnary() (calicoExpr, error) {
	if p.accept("!") {
		inner, err := p.parseUnary()
		if err != nil {
			return nil, err
		}
		return calicoNot{inner: inner}, nil
	}
	if p.accept("(") {
		inner, err := p.parseOr()
		if err != nil {
			return nil, err
		}
		if !p.accept(")") {
			return nil, fmt.Errorf("missing closing parenthesis")
		}
		return inner, nil
	}
	return p.parseAtom()
}

func (p *calicoParser) parseAtom() (calicoExpr, error) {
	if p.acceptWord("all()") {
		return calicoAll{}, nil
	}
	if p.acceptWord("global()") {
		return calicoGlobal{}, nil
	}
	if p.acceptWord("has") {
		if !p.accept("(") {
			return nil, fmt.Errorf("has must be followed by (")
		}
		key, err := p.parseKey()
		if err != nil {
			return nil, err
		}
		if !p.accept(")") {
			return nil, fmt.Errorf("missing ) after has(%s", key)
		}
		return calicoHas{key: key}, nil
	}

	key, err := p.parseKey()
	if err != nil {
		return nil, err
	}
	switch {
	case p.accept("=="):
		value, err := p.parseValue()
		if err != nil {
			return nil, err
		}
		return calicoEquals{key: key, value: value}, nil
	case p.accept("!="):
		value, err := p.parseValue()
		if err != nil {
			return nil, err
		}
		return calicoEquals{key: key, value: value, negate: true}, nil
	case p.acceptWord("not"):
		if !p.acceptWord("in") {
			return nil, fmt.Errorf("expected \"in\" after \"not\" for key %q", key)
		}
		values, err := p.parseSet()
		if err != nil {
			return nil, err
		}
		return calicoIn{key: key, values: values, negate: true}, nil
	case p.acceptWord("in"):
		values, err := p.parseSet()
		if err != nil {
			return nil, err
		}
		return calicoIn{key: key, values: values}, nil
	}
	return nil, fmt.Errorf("unsupported operator after key %q", key)
}

func (p *calicoParser) parseSet() ([]string, error) {
	if !p.accept("{") {
		return nil, fmt.Errorf("expected { to open a value set")
	}
	var values []string
	for {
		value, err := p.parseValue()
		if err != nil {
			return nil, err
		}
		values = append(values, value)
		if p.accept(",") {
			continue
		}
		if p.accept("}") {
			return values, nil
		}
		return nil, fmt.Errorf("expected , or } in value set")
	}
}

func (p *calicoParser) parseValue() (string, error) {
	p.skipSpace()
	if p.pos >= len(p.in) {
		return "", fmt.Errorf("expected a value")
	}
	quote := p.in[p.pos]
	if quote != '\'' && quote != '"' {
		return p.parseKey()
	}
	p.pos++
	start := p.pos
	for p.pos < len(p.in) && p.in[p.pos] != quote {
		p.pos++
	}
	if p.pos >= len(p.in) {
		return "", fmt.Errorf("unterminated string")
	}
	value := string(p.in[start:p.pos])
	p.pos++
	return value, nil
}

func (p *calicoParser) parseKey() (string, error) {
	p.skipSpace()
	start := p.pos
	for p.pos < len(p.in) && isCalicoKeyRune(p.in[p.pos]) {
		p.pos++
	}
	if start == p.pos {
		return "", fmt.Errorf("expected a label key at position %d", start)
	}
	return string(p.in[start:p.pos]), nil
}

func isCalicoKeyRune(r rune) bool {
	return r == '.' || r == '/' || r == '-' || r == '_' ||
		(r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')
}
