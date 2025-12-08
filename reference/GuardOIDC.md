# R6 class for the OpenID Connect guard

This class encapsulates the logic of the OpenID Connect based
authentication scheme. See
[`guard_oidc()`](https://thomasp85.github.io/fireproof/reference/guard_oidc.md)
for more information

## Super classes

[`fireproof::Guard`](https://thomasp85.github.io/fireproof/reference/Guard.md)
-\>
[`fireproof::GuardOAuth2`](https://thomasp85.github.io/fireproof/reference/GuardOAuth2.md)
-\> `GuardOIDC`

## Active bindings

- `open_api`:

  An OpenID compliant security scheme description

## Methods

### Public methods

- [`GuardOIDC$new()`](#method-GuardOIDC-new)

- [`GuardOIDC$clone()`](#method-GuardOIDC-clone)

Inherited methods

- [`fireproof::Guard$forbid_user()`](https://thomasp85.github.io/fireproof/reference/Guard.html#method-forbid_user)
- [`fireproof::GuardOAuth2$check_request()`](https://thomasp85.github.io/fireproof/reference/GuardOAuth2.html#method-check_request)
- [`fireproof::GuardOAuth2$refresh_token()`](https://thomasp85.github.io/fireproof/reference/GuardOAuth2.html#method-refresh_token)
- [`fireproof::GuardOAuth2$register_handler()`](https://thomasp85.github.io/fireproof/reference/GuardOAuth2.html#method-register_handler)
- [`fireproof::GuardOAuth2$reject_response()`](https://thomasp85.github.io/fireproof/reference/GuardOAuth2.html#method-reject_response)

------------------------------------------------------------------------

### Method `new()`

Constructor for the class

#### Usage

    GuardOIDC$new(
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
      name = NULL
    )

#### Arguments

- `service_url`:

  The url to the authentication service

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

- `request_user_info`:

  Logical. Should the userinfo endpoint be followed to add information
  about the user not present in the JWT token. Setting this to `TRUE`
  will add an additional API call to your authentication flow but
  potentially provide richer information about the user.

- `validate`:

  Function to validate the user once logged in. It must have a single
  argument `info`, which gets the information of the user as provided by
  the `user_info` function in the. By default it returns `TRUE` on
  everything meaning that anyone who can log in with the provider will
  be accepted, but you can provide a different function to e.g. restrict
  access to certain user names etc.

- `redirect_path`:

  The path that should capture redirects after successful authorization.
  By default this is derived from `redirect_url` by removing the domain
  part of the url, but if for some reason this doesn't yields the
  correct result for your server setup you can overwrite it here.

- `on_auth`:

  A function which will handle the result of a successful authorization.
  It must have four arguments: `request`, `response`, `session_state`,
  and `server`. The first contains the current request being responded
  to, the second is the response being send back, the third is a list
  recording the state of the original request which initiated the
  authorization (containing `method`, `url`, `headers`, and `body`
  fields with information from the original request). By default it will
  use
  [replay_request](https://thomasp85.github.io/fireproof/reference/on_auth.md)
  to internally replay the original request and send back the response.

- `service_name`:

  The name of the service provider. Will be passed on to the `provider`
  slot in the user info list

- `service_params`:

  A named list of additional query params to add to the url when
  constructing the authorization url in the `"authorization_code"` grant
  type

- `name`:

  The name of the scheme instance. This will also be the name under
  which token info and user info is saved in the session store

------------------------------------------------------------------------

### Method `clone()`

The objects of this class are cloneable with this method.

#### Usage

    GuardOIDC$clone(deep = FALSE)

#### Arguments

- `deep`:

  Whether to make a deep clone.

## Examples

``` r
# Example using Google endpoint (use `guard_google()` in real code)
google <- GuardOIDC$new(
  service_url = "https://accounts.google.com/",
  redirect_url = "https://example.com/auth",
  client_id = "MY_APP_ID",
  client_secret = "SUCHASECRET"
)
```
