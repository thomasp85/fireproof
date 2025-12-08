# Shared secret guard

This guard is based on a mutually shared secret between the server and
the client. The client provides the secret either as a header or in a
cookie, and the server verifies the authenticity of the secret. Like
with [basic
authentication](https://thomasp85.github.io/fireproof/reference/guard_basic.md),
this scheme relies on additional technology like HTTPS/SSL to make it
secure since the secret can otherwise easily be extracted from the
request by man-in-the-middle attack.

## Usage

``` r
guard_key(
  key_name,
  validate,
  user_info = NULL,
  cookie = TRUE,
  name = "KeyAuth"
)
```

## Arguments

- key_name:

  The name of the header or cookie to store the secret under

- validate:

  Either a single string with the secret or a function that will be
  called with the arguments `key`, `request`, and `response` and returns
  `TRUE` if its a valid secret (useful if you have multiple or rotating
  secrets). If the function returns a character vector it is considered
  to be authenticated and the return value will be understood as scopes
  the user is granted. Make sure never to store secrets in plain text
  and avoid checking them into version control.

- user_info:

  A function to extract user information from the key. It is called with
  a single argument: `key` which is the key used for the successful
  authentication. The function should return a new
  [user_info](https://thomasp85.github.io/fireproof/reference/new_user_info.md)
  list.

- cookie:

  Boolean. Should the secret be transmitted as a cookie. If `FALSE` it
  is expected to be transmitted as a header.

- name:

  The name of the guard

## Value

A
[GuardKey](https://thomasp85.github.io/fireproof/reference/GuardKey.md)
object

## Details

This authentication is not a classic HTTP authentication scheme and thus
doesn't return a `401` response with a `WWW-Authenticate` header.
Instead it returns a `400` response unless another guard has already set
the response status to something else.

## User information

`guard_key()` automatically adds [user
information](https://thomasp85.github.io/fireproof/reference/new_user_info.md)
after authentication. By default it will set the `provider` field to
`"local"`. Further, it will set the `scopes` field to any scopes
returned by the `validate` function (provided `validate` is passed a
function).

Since key-based authentication is seldom used with user specific keys it
is unlikely that it makes sense to populate the information any further.

## Examples

``` r
# Create a guard of dubious quality
key <- guard_key(
  key_name = "my-key-location",
  validate = "SHHH!!DONT_TELL_ANYONE"
)

# Add it to a fireproof plugin
fp <- Fireproof$new()
fp$add_guard(key, "key_auth")

# Use it in an endpoint
fp$add_auth("get", "/*", key_auth)
```
