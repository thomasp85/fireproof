# R6 class for the OAuth 2.0 Guard

This class encapsulates the logic of the oauth 2.0 based authentication
scheme. See
[`guard_oauth2()`](https://thomasp85.github.io/fireproof/reference/guard_oauth2.md)
for more information

## Super class

[`fireproof::Guard`](https://thomasp85.github.io/fireproof/reference/Guard.md)
-\> `GuardOAuth2`

## Active bindings

- `open_api`:

  An OpenID compliant security scheme description

## Methods

### Public methods

- [`GuardOAuth2$new()`](#method-GuardOAuth2-new)

- [`GuardOAuth2$check_request()`](#method-GuardOAuth2-check_request)

- [`GuardOAuth2$reject_response()`](#method-GuardOAuth2-reject_response)

- [`GuardOAuth2$register_handler()`](#method-GuardOAuth2-register_handler)

- [`GuardOAuth2$refresh_token()`](#method-GuardOAuth2-refresh_token)

- [`GuardOAuth2$clone()`](#method-GuardOAuth2-clone)

Inherited methods

- [`fireproof::Guard$forbid_user()`](https://thomasp85.github.io/fireproof/reference/Guard.html#method-forbid_user)

------------------------------------------------------------------------

### Method `new()`

Constructor for the class

#### Usage

    GuardOAuth2$new(
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
      name = NULL
    )

#### Arguments

- `token_url`:

  The URL to the authorization servers token endpoint

- `redirect_url`:

  The URL the authorization server should redirect to following a
  successful authorization. Must be equivalent to one provided when
  registering your application

- `client_id`:

  The ID issued by the authorization server when registering your
  application

- `client_secret`:

  The secret issued by the authorization server when registering your
  application. Do NOT store this in plain text

- `auth_url`:

  The URL to redirect the user to when requesting authorization (only
  needed for `grant_type = "authorization_code"`)

- `grant_type`:

  The type of authorization scheme to use, either `"authorization_code"`
  or `"password"`

- `oauth_scopes`:

  Optional character vector of scopes to request the user to grant you
  during authorization. These will *not* influence the scopes granted by
  the `validate` function and fireproof scoping. If named, the names are
  taken as scopes and the elements as descriptions of the scopes, e.g.
  given a scope, `read`, it can either be provided as `c("read")` or
  `c(read = "Grant read access")`

- `validate`:

  Function to validate the user once logged in. It will be called with a
  single argument `info`, which gets the information of the user as
  provided by the `user_info` function. By default it returns `TRUE` on
  everything meaning that anyone who can log in with the provider will
  be accepted, but you can provide a different function to e.g. restrict
  access to certain user names etc. If the function returns a character
  vector it is considered to be authenticated and the return value will
  be understood as scopes the user is granted.

- `redirect_path`:

  The path that should capture redirects after successful authorization.
  By default this is derived from `redirect_url` by removing the domain
  part of the url, but if for some reason this doesn't yields the
  correct result for your server setup you can overwrite it here.

- `on_auth`:

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

- `user_info`:

  A function to extract user information from the access token. It is
  called with a single argument: `token_info` which is the access token
  information returned by the OAuth 2 server after a successful
  authentication. The function should return a new
  [user_info](https://thomasp85.github.io/fireproof/reference/new_user_info.md)
  list.

- `service_params`:

  A named list of additional query params to add to the url when
  constructing the authorization url in the `"authorization_code"` grant
  type

- `scopes_delim`:

  The separator of the scopes as returned by the service. The default
  `" "` is the spec recommendation but some services *cough* github
  *cough* are non-compliant

- `name`:

  The name of the guard.

------------------------------------------------------------------------

### Method `check_request()`

A function that validates an incoming request, returning `TRUE` if it is
valid and `FALSE` if not.

#### Usage

    GuardOAuth2$check_request(request, response, keys, ..., .datastore)

#### Arguments

- `request`:

  The request to validate as a
  [Request](https://reqres.data-imaginist.com/reference/Request.html)
  object

- `response`:

  The corresponding response to the request as a
  [Response](https://reqres.data-imaginist.com/reference/Response.html)
  object

- `keys`:

  A named list of path parameters from the path matching

- `...`:

  Ignored

- `.datastore`:

  The data storage from firesale

------------------------------------------------------------------------

### Method `reject_response()`

Upon rejection this guard initiates the grant flow to obtain
authorization. This can sound a bit backwards, but we don't want to
initiate authorization if the authorization flow doesn't need it

#### Usage

    GuardOAuth2$reject_response(response, scope, ..., .datastore)

#### Arguments

- `response`:

  The response object

- `scope`:

  The scope of the endpoint

- `...`:

  Ignored

- `.datastore`:

  The data storage from firesale

------------------------------------------------------------------------

### Method `register_handler()`

Hook for registering endpoint handlers needed for this authentication
method

#### Usage

    GuardOAuth2$register_handler(add_handler)

#### Arguments

- `add_handler`:

  The `add_handler` method from
  [Fireproof](https://thomasp85.github.io/fireproof/reference/Fireproof.md)
  to be called for adding additional handlers

------------------------------------------------------------------------

### Method `refresh_token()`

Refresh the access token of the session. Will return `TRUE` upon success
and `FALSE` upon failure. Failure can either be issues with the token
provider, but also lack of a refresh token.

#### Usage

    GuardOAuth2$refresh_token(session, force = FALSE)

#### Arguments

- `session`:

  The session data store

- `force`:

  Boolean. Should the token be refreshed even if it hasn't expired yet

------------------------------------------------------------------------

### Method `clone()`

The objects of this class are cloneable with this method.

#### Usage

    GuardOAuth2$clone(deep = FALSE)

#### Arguments

- `deep`:

  Whether to make a deep clone.

## Examples

``` r
# Example using GitHub endpoints (use `guard_github()` in real code)
github <- GuardOAuth2$new(
  token_url = "https://github.com/login/oauth/access_token",
  redirect_url = "https://example.com/auth",
  client_id = "MY_APP_ID",
  client_secret = "SUCHASECRET",
  auth_url = "https://github.com/login/oauth/authorize",
  grant_type = "authorization_code"
)
```
