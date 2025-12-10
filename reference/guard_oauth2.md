# Guard based on OAuth 2.0

OAuth 2.0 is an authorization scheme that is powering much of the modern
internet and is behind things like "log in with GitHub" etc. It
separates the responsibility of authentication away from the server, and
allows a user to grant limited access to a service on the users behalf.
While OAuth also allows a server to make request on the users behalf the
main purpose in the context of `fireproof` is to validate that the user
can perform a successful login and potentially extract basic information
about the user. The `guard_oauth2()` function is the base constructor
which can be used to create guards with any provider. For ease of use
`fireproof` comes with a range of predefined constructors for popular
services such as GitHub etc. Central for all of these is the need for
your server to register itself with the provider and get a client id and
a client secret which must be used when logging users in.

## Usage

``` r
guard_oauth2(
  token_url,
  redirect_url,
  client_id,
  client_secret,
  auth_url = NULL,
  grant_type = c("authorization_code", "password"),
  oauth_scopes = NULL,
  validate = function(info) TRUE,
  redirect_path = get_path(redirect_url),
  on_auth = replay_request,
  user_info = NULL,
  service_params = list(),
  scopes_delim = " ",
  name = "OAuth2Auth"
)
```

## Arguments

- token_url:

  The URL to the authorization servers token endpoint

- redirect_url:

  The URL the authorization server should redirect to following a
  successful authorization. Must be equivalent to one provided when
  registering your application

- client_id:

  The ID issued by the authorization server when registering your
  application

- client_secret:

  The secret issued by the authorization server when registering your
  application. Do NOT store this in plain text

- auth_url:

  The URL to redirect the user to when requesting authorization (only
  needed for `grant_type = "authorization_code"`)

- grant_type:

  The type of authorization scheme to use, either `"authorization_code"`
  or `"password"`

- oauth_scopes:

  Optional character vector of scopes to request the user to grant you
  during authorization. These will *not* influence the scopes granted by
  the `validate` function and fireproof scoping. If named, the names are
  taken as scopes and the elements as descriptions of the scopes, e.g.
  given a scope, `read`, it can either be provided as `c("read")` or
  `c(read = "Grant read access")`

- validate:

  Function to validate the user once logged in. It will be called with a
  single argument `info`, which gets the information of the user as
  provided by the `user_info` function in the. By default it returns
  `TRUE` on everything meaning that anyone who can log in with the
  provider will be accepted, but you can provide a different function to
  e.g. restrict access to certain user names etc. If the function
  returns a character vector it is considered to be authenticated and
  the return value will be understood as scopes the user is granted.

- redirect_path:

  The path that should capture redirects after successful authorization.
  By default this is derived from `redirect_url` by removing the domain
  part of the url, but if for some reason this doesn't yields the
  correct result for your server setup you can overwrite it here.

- on_auth:

  A function which will handle the result of a successful authorization.
  It will be called with four arguments: `request`, `response`,
  `session_state`, and `server`. The first contains the current request
  being responded to, the second is the response being send back, the
  third is a list recording the state of the original request which
  initiated the authorization (containing `method`, `url`, `headers`,
  and `body` fields with information from the original request). By
  default it will use
  [replay_request](https://thomasp85.github.io/fireproof/reference/on_auth.md)
  to internally replay the original request and send back the response.

- user_info:

  A function to extract user information from the access token. It is
  called with a single argument: `token_info` which is the access token
  information returned by the OAuth 2 server after a successful
  authentication. The function should return a new
  [user_info](https://thomasp85.github.io/fireproof/reference/new_user_info.md)
  list.

- service_params:

  A named list of additional query params to add to the url when
  constructing the authorization url in the `"authorization_code"` grant
  type

- scopes_delim:

  The separator of the scopes as returned by the service. The default
  `" "` is the spec recommendation but some services *cough* github
  *cough* are non-compliant

- name:

  The name of the guard

## Value

A
[GuardOAuth2](https://thomasp85.github.io/fireproof/reference/GuardOAuth2.md)
object

## User information

`guard_oauth2()` automatically adds some [user
information](https://thomasp85.github.io/fireproof/reference/new_user_info.md)
after authentication, but it is advised to consult the service provider
for more information (this is done automatically for the provider
specific guards. See their documentation for details about what
information is assigned to which field). The base constructor will set
the `scopes` field to any scopes returned by the `validate` function. It
will also set the `token` field to a list with the token data provided
by the service during authorization. Some standard fields in the list
are:

- `access_token`: The actual token value

- `token_type`: The type of token (usually `"bearer"`)

- `expires_in`: The lifetime of the token in seconds

- `refresh_token`: A long-lived token that can be used to issue a new
  access token if the current becomes stale

- `timestamp`: The time the token was received

- `scopes`: The scopes granted by the user for this token

But OAuth 2.0 providers may choose to supply others. Consult the
documentation for the provider to learn of additional fields it may
provide.

## References

[The OAuth 2.0 RFC](https://datatracker.ietf.org/doc/html/rfc6749)

## Examples

``` r
# Example using GitHub endpoints (use `guard_github()` in real code)
github <- guard_oauth2(
  token_url = "https://github.com/login/oauth/access_token",
  redirect_url = "https://example.com/auth",
  client_id = "MY_APP_ID",
  client_secret = "SUCHASECRET",
  auth_url = "https://github.com/login/oauth/authorize",
  grant_type = "authorization_code"
)

# Add it to a fireproof plugin
fp <- Fireproof$new()
fp$add_guard(github, "github_auth")

# Use it in an endpoint
fp$add_auth("get", "/*", github_auth)
```
