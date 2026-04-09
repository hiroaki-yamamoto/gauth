# JWT-based session middleware for go

[![CircleCI]][CircleCi Link]
[![Maintainability]][Maintainability Link]
[![Test Coverage]][Test Coverage Link]
[![Go Report Card]][Go Report Card Link]

[CircleCI]: https://circleci.com/gh/hiroaki-yamamoto/gauth.svg?style=svg
[CircleCi Link]: https://circleci.com/gh/hiroaki-yamamoto/gauth
[Maintainability]: https://qlty.sh/gh/hiroaki-yamamoto/projects/gauth/maintainability.svg
[Maintainability Link]: https://qlty.sh/gh/hiroaki-yamamoto/projects/gauth
[Test Coverage]: https://qlty.sh/gh/hiroaki-yamamoto/projects/gauth/coverage.svg
[Test Coverage Link]: https://qlty.sh/gh/hiroaki-yamamoto/projects/gauth
[Go Report Card]: https://goreportcard.com/badge/github.com/hiroaki-yamamoto/gauth
[Go Report Card Link]: https://goreportcard.com/report/github.com/hiroaki-yamamoto/gauth

## What this?

When you code web-backend app, you might want an authentication system. For example,
providing login authentication service might be problematic; authenticate the user,
managing sessoin, etc, etc... However, golang doesn't provide the authentication system
in the standard library though it provides HTTP client / server.

Fortunately, the third-party package can provide JWT token generation / decode, so
I wrote this package to provide a minimum authentication function.

## Installation

You can include this package in your project by importing it.

```go
import "github.com/hiroaki-yamamoto/gauth"
```

## How to use

This package has 2 modules:

* **core** provides the core functions like token composer and decoder. In the
    future, this module will provide password hashing function that would
    be easy-to-use.
* **middleware** provides request-wrapping functions, and they are called
    `middleware` in Django (that is a web-framework in Python).

### Using Token Composer and Decoder

Please visit [go-gql-sample] for example. On `backend/main.go`, the handlers
are wrapped with `HeaderMiddleware` and `HeaderLoginRequired`. In addition to
this, `backend/prv/resolver.go` shows the example of `GetUser`.

[go-gql-sample]: https://github.com/hiroaki-yamamoto/go-gql-sample

### Contirbution
Writing a PR or Issue is appreciated when you found a bug, or you want to share
an improvements.
