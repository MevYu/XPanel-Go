package mysqlrepl

import "testing"

func TestValidIdentRejectsInjection(t *testing.T) {
	bad := []string{
		"", "a b", "u; DROP USER x", "back`tick", `dq"uote`,
		"a'b", "dash-name", "name.dot", "name*", "tab\tname", "new\nline",
		"0123456789012345678901234567890123456789012345678901234567890123456", // 65 chars
	}
	for _, s := range bad {
		if validIdent(s) {
			t.Errorf("validIdent(%q) = true, want false", s)
		}
	}
	good := []string{"a", "repl", "repl_user", "USER_42", "_x",
		"0123456789012345678901234567890123456789012345678901234567890123"} // 64 chars
	for _, s := range good {
		if !validIdent(s) {
			t.Errorf("validIdent(%q) = false, want true", s)
		}
	}
}

func TestQuoteMySQLRejectsBadIdent(t *testing.T) {
	for _, s := range []string{"a b", "x;y", ""} {
		if _, err := quoteMySQL(s); err == nil {
			t.Errorf("quoteMySQL(%q) should error", s)
		}
	}
	q, err := quoteMySQL("repl_user")
	if err != nil || q != "`repl_user`" {
		t.Errorf("quoteMySQL = %q, %v", q, err)
	}
}

func TestQuoteStringLiteralEscapes(t *testing.T) {
	if got := quoteStringLiteral("p'wd"); got != "'p''wd'" {
		t.Errorf("single quote = %q", got)
	}
	if got := quoteStringLiteral(`a\b`); got != `'a\\b'` {
		t.Errorf("backslash = %q", got)
	}
	if got := quoteStringLiteral("%"); got != "'%'" {
		t.Errorf("percent = %q", got)
	}
}
