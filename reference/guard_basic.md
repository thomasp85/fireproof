# Basic authentication guard

Basic authentication is a HTTP scheme that sends username and password
as a `:` separated, base64 encoded string in the authorization header.
Because it is effectively send in plain text (base64 encoding can easily
be decoded) this should only ever be used along with other security
measures such as https/ssl to avoid username and passwords being snooped
from the request.

## Usage

``` r
guard_basic(validate, user_info = NULL, realm = "private", name = "BasicAuth")
```

## Arguments

- validate:

  A function that will be called with the arguments `username`,
  `password`, `realm`, `request`, and `response` and returns `TRUE` if
  the user is valid, and `FALSE` otherwise. If the function returns a
  character vector it is considered to be authenticated and the return
  value will be understood as scopes the user is granted.

- user_info:

  A function to extract user information from the username. It is called
  with a single argument: `user` which is the username used for the
  successful authentication. The function should return a new
  [user_info](https://thomasp85.github.io/fireproof/reference/new_user_info.md)
  list.

- realm:

  The realm this authentication corresponds to. Will be returned to the
  client on a failed authentication attempt to inform them of the
  credentials required, though most often these days it is kept from the
  user.

- name:

  The name of the guard

## Value

A
[GuardBasic](https://thomasp85.github.io/fireproof/reference/GuardBasic.md)
R6 object

## Details

This guard will use a user-provided function to test a username/password
pair. It is up to the server implementation to handle the storage and
testing of the passwords in a sensible and responsible way. See
[`sodium::password_store()`](https://docs.ropensci.org/sodium/reference/password.html)
for a good first step towards responsible design.

## User information

`guard_basic()` automatically adds [user
information](https://thomasp85.github.io/fireproof/reference/new_user_info.md)
after authentication. By default it will set the `provider` field to
`"local"` and the `id` field to the username used for logging in.
Further, it will set the `scopes` field to any scopes returned by the
`authenticator` function.

## References

[Basic authentication
RFC](https://datatracker.ietf.org/doc/html/rfc7617)

## Examples

``` r
# Create a guard of dubious quality
basic <- guard_basic(
  validate = function(user, password) {
    user == "thomas" && password == "pedersen"
  },
  user_info = function(user) {
    new_user_info(
      name_given = "Thomas",
      name_middle = "Lin",
      name_family = "Pedersen"
    )
  }
)

# Add it to a fireproof plugin
fp <- Fireproof$new()
fp$add_guard(basic, "basic_auth")

# Use it in an endpoint
fp$add_auth("get", "/*", basic_auth)
```
