# Guard based on OpenID Connect

OpenID Connect is an authentication standard build on top of [OAuth
2.0](https://thomasp85.github.io/fireproof/reference/guard_oauth2.md).
OAuth 2.0 at its core is only about authorization and doesn't provide a
standardized approach to extracting user information that can be used
for authentication. OpenID Connect fills this gap in a number of ways.
First, the token returned is a JSON Web Token (JWT) that contains claims
about the user, signed by the issuer. Second, the authentication service
provides means for discovery of all relevant end points making rotation
of credentials etc easier. Third, the claims about users are
standardized so authentication services are easily interchangable. Not
all OAuth 2.0 authorization services provide an OpenID Connect layer,
but if they do, it is generally preferable to use that. The
`guard_oidc()` function is the base constructor which can be used to
create authenticators with any provider. For ease of use `fireproof`
comes with a range of predefined constructors for popular services such
as Google etc. Central for all of these is the need for your server to
register itself with the provider and get a client id and a client
secret which must be used when logging users in.

## Usage

``` r
guard_oidc(
  service_url,
  redirect_url,
  client_id,
  client_secret,
  grant_type = c("authorization_code", "password"),
  oauth_scopes = c("profile"),
  request_user_info = FALSE,
  validate = function(info) TRUE,
  redirect_path = get_path(redirect_url),
  on_auth = replay_request,
  service_name = service_url,
  service_params = list(),
  name = "OIDCAuth"
)
```

## Arguments

- service_url:

  The url to the authentication service

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

- request_user_info:

  Logical. Should the userinfo endpoint be followed to add information
  about the user not present in the JWT token. Setting this to `TRUE`
  will add an additional API call to your authentication flow but
  potentially provide richer information about the user.

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

- service_name:

  The name of the service provider. Will be passed on to the `provider`
  slot in the user info list

- service_params:

  A named list of additional query params to add to the url when
  constructing the authorization url in the `"authorization_code"` grant
  type

- name:

  The name of the guard

## Value

An
[GuardOIDC](https://thomasp85.github.io/fireproof/reference/GuardOIDC.md)
object

## User information

`guard_oidc()` automatically adds [user
information](https://thomasp85.github.io/fireproof/reference/new_user_info.md)
after authentication, based on the standardized user claims provided in
the `id_token` as well as any additional user information provided at
the `userinfo_endpoint` of the service if `request_user_info = TRUE`.
You can see a list of standard user information defined by OpenID
Connect at the [OpenID
website](https://openid.net/specs/openid-connect-core-1_0.html#StandardClaims).
The mapping of these to
[`new_user_info()`](https://thomasp85.github.io/fireproof/reference/new_user_info.md)
is as follows:

- `sub` -\> `id`

- `name` -\> `name_display`

- `given_name` -\> `name_given`

- `middle_name` -\> `name_middle`

- `family_name` -\> `name_family`

- `email` -\> `emails`

- `picture` -\> `photos`

Further, it will set the `scopes` field to any scopes returned by the
`validate` function, the `provider` field to `service_name`, the `token`
field to the token information as described in
[`guard_oauth2()`](https://thomasp85.github.io/fireproof/reference/guard_oauth2.md),
and `.raw` to the full list of user information as provided unaltered by
the service. Be aware that the information reported by the service
depends on the `oauth_scopes` requested by fireproof and granted by the
user. You can therefore never assume the existence of any information
besides `id`, `provider` and `token`.

## Examples

``` r
# Example using Google endpoint (use `guard_google()` in real code)
google <- guard_oidc(
  service_url = "https://accounts.google.com/",
  redirect_url = "https://example.com/auth",
  client_id = "MY_APP_ID",
  client_secret = "SUCHASECRET"
)

# Add it to a fireproof plugin
fp <- Fireproof$new()
fp$add_guard(google, "google_auth")

# Use it in an endpoint
fp$add_auth("get", "/*", google_auth)
```
