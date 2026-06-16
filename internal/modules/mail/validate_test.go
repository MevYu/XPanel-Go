package mail

import "testing"

func TestValidDomain(t *testing.T) {
	good := []string{"example.com", "mail.example.com", "a.io", "xn--p1ai.ru", "sub-domain.example.co"}
	for _, d := range good {
		if !validDomain(d) {
			t.Errorf("validDomain(%q) = false, want true", d)
		}
	}
	bad := []string{
		"", "example", ".example.com", "example.com.", "ex ample.com",
		"example.com\nrm -rf", "a;b.com", "exa$mple.com", "-bad.com", "bad-.com",
		"foo@bar.com", "../etc.com",
	}
	for _, d := range bad {
		if validDomain(d) {
			t.Errorf("validDomain(%q) = true, want false", d)
		}
	}
}

func TestValidEmail(t *testing.T) {
	good := []string{"bob@example.com", "a.b+tag@mail.example.com", "user_1@x.io"}
	for _, e := range good {
		if !validEmail(e) {
			t.Errorf("validEmail(%q) = false, want true", e)
		}
	}
	bad := []string{
		"", "bob", "bob@", "@example.com", "bob@@example.com",
		"bob@example", "bo b@example.com", "bob@exa mple.com",
		"bob@example.com\nevil@x.com", "a;rm@example.com", "bob@example.com OK",
	}
	for _, e := range bad {
		if validEmail(e) {
			t.Errorf("validEmail(%q) = true, want false", e)
		}
	}
}

func TestValidPassword(t *testing.T) {
	if !validPassword("S3cret!pw") {
		t.Error("normal password should pass")
	}
	bad := []string{"", "a\nb", "a\tb", "a\x00b", "a\x7fb"}
	for _, p := range bad {
		if validPassword(p) {
			t.Errorf("validPassword(%q) = true, want false", p)
		}
	}
	long := make([]byte, 257)
	for i := range long {
		long[i] = 'a'
	}
	if validPassword(string(long)) {
		t.Error("257-char password should fail")
	}
}
