# Multicookie

Multicookie is a [gorilla sessions](https://github.com/gorilla/sessions)
[store](https://godoc.org/github.com/gorilla/sessions#Store) implementation.

For the most part, it is similar to the built-in
[CookieStore](https://godoc.org/github.com/gorilla/sessions#CookieStore). The
main difference is each session value is stored in it's own cookie, rather than
all stored in the same cookie. This enables storing larger values. The cookie
naming scheme is `<session name>-<value name>`, it is the responsibility of the
application to keep the `<session name>-` prefix clear.
