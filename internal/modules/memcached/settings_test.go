package memcached

import "testing"

func TestDefaultSettingsValid(t *testing.T) {
	if err := DefaultSettings().Validate(); err != nil {
		t.Fatalf("default settings must be valid: %v", err)
	}
	d := DefaultSettings()
	if d.Addr != "127.0.0.1:11211" || d.ServiceUnit != "memcached" {
		t.Fatalf("unexpected defaults: %+v", d)
	}
}

func TestSettingsValidate(t *testing.T) {
	cases := []struct {
		name string
		s    Settings
		ok   bool
	}{
		{"good", Settings{Addr: "127.0.0.1:11211", ServiceUnit: "memcached"}, true},
		{"good hostname", Settings{Addr: "cache.local:11211", ServiceUnit: "memcached.service"}, true},
		{"no port", Settings{Addr: "127.0.0.1", ServiceUnit: "memcached"}, false},
		{"empty host", Settings{Addr: ":11211", ServiceUnit: "memcached"}, false},
		{"empty addr", Settings{Addr: "", ServiceUnit: "memcached"}, false},
		{"newline addr", Settings{Addr: "127.0.0.1:1\n1", ServiceUnit: "memcached"}, false},
		{"bad unit injection", Settings{Addr: "127.0.0.1:11211", ServiceUnit: "memcached; rm -rf"}, false},
		{"empty unit", Settings{Addr: "127.0.0.1:11211", ServiceUnit: ""}, false},
	}
	for _, c := range cases {
		err := c.s.Validate()
		if (err == nil) != c.ok {
			t.Errorf("%s: ok=%v but err=%v", c.name, c.ok, err)
		}
	}
}
