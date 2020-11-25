package multicookie

import (
	"encoding/gob"
	"fmt"
	"net/http"
	"strings"

	"github.com/gorilla/securecookie"
	"github.com/gorilla/sessions"
)

var _ sessions.Store = (*MultiCookie)(nil)

// ser is a wrapper type to encode, gob doesn't always deal with concrete types
// so well, and json doesn't round trip consistently. should be about as compact
// as it can be.
type ser struct {
	V interface{}
}

// MultiCookie is a gorilla session store that saves each value to individual
// cookies, rather than to a single cookie. This enables larger values to be
// saved. All cookies are prefixed with `<sessionname>-`, it is the
// responsibility of the application to avoid conflict. Otherwise, it works
// similar to the built-in cookie store.
type MultiCookie struct {
	Codecs []securecookie.Codec
	// Options are use to default cookie options
	Options *sessions.Options
}

// New returns a new MultiCookie.
//
// The key options are the same as github.com/gorilla/sessions#NewCookieStore
func New(keyPairs ...[]byte) *MultiCookie {
	gob.Register(ser{}) // ensure we're registered.
	codecs := securecookie.CodecsFromPairs(keyPairs...)
	cs := &MultiCookie{
		Codecs: codecs,
		Options: &sessions.Options{
			Path:   "/",
			MaxAge: 86400 * 30,
		},
	}

	cs.MaxAge(cs.Options.MaxAge)
	return cs
}

// Get returns the caches session
func (m *MultiCookie) Get(r *http.Request, name string) (*sessions.Session, error) {
	return sessions.GetRegistry(r).Get(m, name)
}

// New should create and return a new session.
//
// Note that New should never return a nil session, even in the case of
// an error if using the Registry infrastructure to cache the session.
func (m *MultiCookie) New(r *http.Request, name string) (*sessions.Session, error) {
	session := sessions.NewSession(m, name)
	opts := *m.Options
	session.Options = &opts
	session.IsNew = true
	var errs []string
	for _, c := range r.Cookies() {
		if strings.HasPrefix(c.Name, session.Name()+"-") {
			var decoded ser
			err := securecookie.DecodeMulti(c.Name, c.Value, &decoded, m.Codecs...)
			if err != nil {
				errs = append(errs, err.Error())
			} else {
				session.IsNew = false
				vn := strings.TrimPrefix(c.Name, session.Name()+"-")
				session.Values[vn] = decoded.V
			}
		}
	}

	if len(errs) > 0 {
		return session, fmt.Errorf("creating session: %v", strings.Join(errs, ", "))
	}

	return session, nil
}

// Save should persist session to the underlying store implementation.
func (m *MultiCookie) Save(r *http.Request, w http.ResponseWriter, s *sessions.Session) error {
	var errs []string
	for k, v := range s.Values {
		var ks string
		switch sv := k.(type) {
		case string:
			ks = sv
		case fmt.Stringer:
			ks = sv.String()
		default:
			errs = append(errs, fmt.Sprintf("non-stringable key type %T found", k))
			continue
		}

		cn := s.Name() + "-" + ks

		encoded, err := securecookie.EncodeMulti(cn, &ser{V: v}, m.Codecs...)
		if err != nil {
			errs = append(errs, err.Error())
			continue
		}
		http.SetCookie(w, sessions.NewCookie(cn, encoded, s.Options))
	}

	if len(errs) > 0 {
		return fmt.Errorf("creating session: %v", strings.Join(errs, ", "))
	}

	return nil
}

// MaxAge sets the maximum age for the store and the underlying cookie
// implementation. Individual sessions can be deleted by setting Options.MaxAge
// = -1 for that session.
func (m *MultiCookie) MaxAge(age int) {
	m.Options.MaxAge = age

	// Set the maxAge for each securecookie instance.
	for _, codec := range m.Codecs {
		if sc, ok := codec.(*securecookie.SecureCookie); ok {
			sc.MaxAge(age)
		}
	}
}
