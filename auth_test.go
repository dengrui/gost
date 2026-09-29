package gost

import (
	"bytes"
	"fmt"
	"io"
	"net/url"
	"testing"
	"time"
)

var localAuthenticatorTests = []struct {
	clientUser  *url.Userinfo
	serverUsers []*url.Userinfo
	valid       bool
}{
	{nil, nil, true},
	{nil, []*url.Userinfo{url.User("admin")}, false},
	{nil, []*url.Userinfo{url.UserPassword("", "123456")}, false},
	{nil, []*url.Userinfo{url.UserPassword("admin", "123456")}, false},

	{url.User("admin"), nil, true},
	{url.User("admin"), []*url.Userinfo{url.User("admin")}, true},
	{url.User("admin"), []*url.Userinfo{url.User("test")}, false},
	{url.User("admin"), []*url.Userinfo{url.UserPassword("test", "123456")}, false},
	{url.User("admin"), []*url.Userinfo{url.UserPassword("admin", "123456")}, false},
	{url.User("admin"), []*url.Userinfo{url.UserPassword("admin", "")}, true},
	{url.User("admin"), []*url.Userinfo{url.UserPassword("", "123456")}, false},

	{url.UserPassword("", ""), nil, true},
	{url.UserPassword("", "123456"), nil, true},
	{url.UserPassword("", "123456"), []*url.Userinfo{url.UserPassword("", "123456")}, true},
	{url.UserPassword("", "123456"), []*url.Userinfo{url.UserPassword("admin", "")}, false},
	{url.UserPassword("", "123456"), []*url.Userinfo{url.UserPassword("admin", "123456")}, false},

	{url.UserPassword("admin", "123456"), nil, true},
	{url.UserPassword("admin", "123456"), []*url.Userinfo{url.User("admin")}, true},
	{url.UserPassword("admin", "123456"), []*url.Userinfo{url.User("test")}, false},
	{url.UserPassword("admin", "123456"), []*url.Userinfo{url.UserPassword("admin", "")}, true},
	{url.UserPassword("admin", "123456"), []*url.Userinfo{url.UserPassword("", "123456")}, false},
	{url.UserPassword("admin", "123456"), []*url.Userinfo{url.UserPassword("admin", "123")}, false},
	{url.UserPassword("admin", "123456"), []*url.Userinfo{url.UserPassword("test", "123456")}, false},
	{url.UserPassword("admin", "123456"), []*url.Userinfo{url.UserPassword("admin", "123456")}, true},

	{url.UserPassword("admin", "123456"), []*url.Userinfo{
		url.UserPassword("test", "123"),
		url.UserPassword("admin", "123456"),
	}, true},
}

func TestLocalAuthenticator(t *testing.T) {
	for i, tc := range localAuthenticatorTests {
		tc := tc
		t.Run(fmt.Sprintf("#%d", i), func(t *testing.T) {
			au := NewLocalAuthenticator(nil)
			for _, u := range tc.serverUsers {
				if u != nil {
					p, _ := u.Password()
					au.Add(u.Username(), p)
				}
			}

			var u, p string
			if tc.clientUser != nil {
				u = tc.clientUser.Username()
				p, _ = tc.clientUser.Password()
			}
			if au.Authenticate(u, p) != tc.valid {
				t.Error("authenticate result should be", tc.valid)
			}
		})
	}
}

var localAuthenticatorReloadTests = []struct {
	r       io.Reader
	period  time.Duration
	kvs     map[string]string
	stopped bool
}{
	{
		r:      nil,
		period: 0,
		kvs:    nil,
	},
	{
		r:      bytes.NewBufferString(""),
		period: 0,
	},
	{
		r:      bytes.NewBufferString("reload 10s"),
		period: 10 * time.Second,
	},
	{
		r: bytes.NewBufferString("# reload 10s\n"),
	},
	{
		r:      bytes.NewBufferString("reload 10s\n#admin"),
		period: 10 * time.Second,
	},
	{
		r:      bytes.NewBufferString("reload 10s\nadmin"),
		period: 10 * time.Second,
		kvs: map[string]string{
			"admin": "",
		},
	},
	{
		r: bytes.NewBufferString("# reload 10s\nadmin"),
		kvs: map[string]string{
			"admin": "",
		},
	},
	{
		r: bytes.NewBufferString("# reload 10s\nadmin #123456"),
		kvs: map[string]string{
			"admin": "#123456",
		},
		stopped: true,
	},
	{
		r: bytes.NewBufferString("admin \t #123456\n\n\ntest \t 123456"),
		kvs: map[string]string{
			"admin": "#123456",
			"test":  "123456",
		},
		stopped: true,
	},
	{
		r: bytes.NewBufferString(`
		$test.admin$ $123456$
		@test.admin@ @123456@
		test.admin# #123456#
		test.admin\admin 123456
		`),
		kvs: map[string]string{
			"$test.admin$":      "$123456$",
			"@test.admin@":      "@123456@",
			"test.admin#":       "#123456#",
			"test.admin\\admin": "123456",
		},
		stopped: true,
	},
}

func TestLocalAuthenticatorReload(t *testing.T) {
	isEquals := func(a, b map[string]string) bool {
		if len(a) == 0 && len(b) == 0 {
			return true
		}
		if len(a) != len(b) {
			return false
		}

		for k, v := range a {
			if b[k] != v {
				return false
			}
		}
		return true
	}
	for i, tc := range localAuthenticatorReloadTests {
		tc := tc
		t.Run(fmt.Sprintf("#%d", i), func(t *testing.T) {
			au := NewLocalAuthenticator(nil)

			if err := au.Reload(tc.r); err != nil {
				t.Error(err)
			}
			if au.Period() != tc.period {
				t.Errorf("#%d test failed: period value should be %v, got %v",
					i, tc.period, au.Period())
			}
			if !isEquals(au.kvs, tc.kvs) {
				t.Errorf("#%d test failed: %v, %s", i, au.kvs, tc.kvs)
			}

			if tc.stopped {
				au.Stop()
				if au.Period() >= 0 {
					t.Errorf("period of the stopped reloader should be minus value")
				}
				au.Stop()
			}
			if au.Stopped() != tc.stopped {
				t.Errorf("#%d test failed: stopped value should be %v, got %v",
					i, tc.stopped, au.Stopped())
			}
		})
	}
}

func TestLocalAuthenticatorYQPrefix(t *testing.T) {
	tests := []struct {
		name, user, password string
		valid                bool
	}{
		{"prefixed user", "YQ_12345678_tom", "secret", true},
		{"incorrect password", "YQ_12345678_tom", "wrong", false},
		{"unknown user", "YQ_12345678_bob", "secret", false},
		{"ordinary user", "tom", "secret", true},
		{"other prefix unchanged", "YQ@12345678_tom", "secret", false},
		{"case sensitive prefix", "yq_12345678_tom", "secret", false},
		{"short username unchanged", "YQ_short", "short", true},
		{"exactly twelve bytes unchanged", "YQ_12345678_", "boundary", true},
		{"one byte suffix", "YQ_12345678_a", "single", true},
		{"unicode suffix", "YQ_12345678_用户", "unicode", true},
		{"empty stored password", "YQ_12345678_guest", "anything", true},
	}
	au := NewLocalAuthenticator(map[string]string{
		"tom": "secret", "YQ_short": "short", "YQ_12345678_": "boundary",
		"a": "single", "用户": "unicode", "guest": "",
	})
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := au.Authenticate(tc.user, tc.password); got != tc.valid {
				t.Fatalf("Authenticate(%q) = %v, want %v", tc.user, got, tc.valid)
			}
		})
	}
	var nilAuth *LocalAuthenticator
	if !nilAuth.Authenticate("YQ_12345678_tom", "anything") {
		t.Fatal("nil authenticator behavior changed")
	}
	if !NewLocalAuthenticator(nil).Authenticate("YQ_12345678_tom", "anything") {
		t.Fatal("empty authenticator behavior changed")
	}
}
