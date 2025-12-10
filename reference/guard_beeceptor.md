# Guard using the mock OAuth servers provided by Beeceptor

These two functions sets up mock OAuth 2.0 guards based on tools
provided by
[Beeceptor](https://app.beeceptor.com/mock-server/oauth-mock). They
should obviously not be used for production because they allow anyone to
be authenticated, but they can be used while testing your authentication
setup.

## Usage

``` r
guard_beeceptor_github(
  redirect_url,
  client_id = "MOCK_CLIENT",
  ...,
  name = "beeceptor_github"
)

guard_beeceptor_google(
  redirect_url,
  client_id = "MOCK_CLIENT",
  ...,
  name = "beeceptor_google"
)
```

## Arguments

- redirect_url:

  The URL the authorization server should redirect to following a
  successful authorization. Must be equivalent to one provided when
  registering your application

- client_id:

  The ID issued by the authorization server when registering your
  application

- ...:

  Arguments passed on to
  [`guard_oauth2`](https://thomasp85.github.io/fireproof/reference/guard_oauth2.md)

  `token_url`

  :   The URL to the authorization servers token endpoint

  `client_secret`

  :   The secret issued by the authorization server when registering
      your application. Do NOT store this in plain text

  `auth_url`

  :   The URL to redirect the user to when requesting authorization
      (only needed for `grant_type = "authorization_code"`)

  `grant_type`

  :   The type of authorization scheme to use, either
      `"authorization_code"` or `"password"`

  `oauth_scopes`

  :   Optional character vector of scopes to request the user to grant
      you during authorization. These will *not* influence the scopes
      granted by the `validate` function and fireproof scoping. If
      named, the names are taken as scopes and the elements as
      descriptions of the scopes, e.g. given a scope, `read`, it can
      either be provided as `c("read")` or
      `c(read = "Grant read access")`

  `validate`

  :   Function to validate the user once logged in. It will be called
      with a single argument `info`, which gets the information of the
      user as provided by the `user_info` function in the. By default it
      returns `TRUE` on everything meaning that anyone who can log in
      with the provider will be accepted, but you can provide a
      different function to e.g. restrict access to certain user names
      etc. If the function returns a character vector it is considered
      to be authenticated and the return value will be understood as
      scopes the user is granted.

  `redirect_path`

  :   The path that should capture redirects after successful
      authorization. By default this is derived from `redirect_url` by
      removing the domain part of the url, but if for some reason this
      doesn't yields the correct result for your server setup you can
      overwrite it here.

  `on_auth`

  :   A function which will handle the result of a successful
      authorization. It will be called with four arguments: `request`,
      `response`, `session_state`, and `server`. The first contains the
      current request being responded to, the second is the response
      being send back, the third is a list recording the state of the
      original request which initiated the authorization (containing
      `method`, `url`, `headers`, and `body` fields with information
      from the original request). By default it will use
      [replay_request](https://thomasp85.github.io/fireproof/reference/on_auth.md)
      to internally replay the original request and send back the
      response.

  `user_info`

  :   A function to extract user information from the access token. It
      is called with a single argument: `token_info` which is the access
      token information returned by the OAuth 2 server after a
      successful authentication. The function should return a new
      [user_info](https://thomasp85.github.io/fireproof/reference/new_user_info.md)
      list.

  `service_params`

  :   A named list of additional query params to add to the url when
      constructing the authorization url in the `"authorization_code"`
      grant type

  `scopes_delim`

  :   The separator of the scopes as returned by the service. The
      default `" "` is the spec recommendation but some services *cough*
      github *cough* are non-compliant

- name:

  The name of the guard

## Value

A
[GuardOAuth2](https://thomasp85.github.io/fireproof/reference/GuardOAuth2.md)
object

## Examples

``` r
beeceptor <- guard_beeceptor_github(
  redirect_url = "https://example.com/auth"
)

# Add it to a fireproof plugin
fp <- Fireproof$new()
fp$add_guard(beeceptor, "beeceptor_auth")

# Use it in an endpoint
fp$add_auth("get", "/*", beeceptor_auth)
```
