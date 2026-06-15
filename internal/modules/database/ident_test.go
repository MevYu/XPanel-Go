package database

import "testing"

func TestValidIdentRejectsInjection(t *testing.T) {
	bad := []string{
		"", "a b", "db; DROP DATABASE x", "back`tick", `dq"uote`,
		"a'b", "dash-name", "name.dot", "name*", "über", "tab\tname",
		"newline\nname", "0123456789012345678901234567890123456789012345678901234567890123456", // 65 chars
	}
	for _, s := range bad {
		if validIdent(s) {
			t.Errorf("validIdent(%q) = true, want false", s)
		}
	}
	good := []string{"a", "db1", "my_db", "USER_42", "A", "_x",
		"0123456789012345678901234567890123456789012345678901234567890123"} // 64 chars
	for _, s := range good {
		if !validIdent(s) {
			t.Errorf("validIdent(%q) = false, want true", s)
		}
	}
}

func TestQuoteRejectsBadIdent(t *testing.T) {
	for _, s := range []string{"a b", "x;y", ""} {
		if _, err := quoteMySQL(s); err == nil {
			t.Errorf("quoteMySQL(%q) should error", s)
		}
		if _, err := quotePG(s); err == nil {
			t.Errorf("quotePG(%q) should error", s)
		}
	}
}

func TestQuoteValid(t *testing.T) {
	q, err := quoteMySQL("my_db")
	if err != nil || q != "`my_db`" {
		t.Errorf("quoteMySQL = %q, %v", q, err)
	}
	q, err = quotePG("my_db")
	if err != nil || q != `"my_db"` {
		t.Errorf("quotePG = %q, %v", q, err)
	}
}

func TestQuoteStringLiteralEscapes(t *testing.T) {
	if got := quoteStringLiteral("p'wd"); got != "'p''wd'" {
		t.Errorf("quoteStringLiteral single quote = %q", got)
	}
	if got := quoteStringLiteral(`a\b`); got != `'a\\b'` {
		t.Errorf("quoteStringLiteral backslash = %q", got)
	}
}
