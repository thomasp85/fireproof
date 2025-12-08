# R6 class for the Bearer authentication guard

This class encapsulates the logic of the [Bearer authentication
scheme](https://datatracker.ietf.org/doc/html/rfc6750). See
[`guard_bearer()`](https://thomasp85.github.io/fireproof/reference/guard_bearer.md)
for more information.

## Super class

[`fireproof::Guard`](https://thomasp85.github.io/fireproof/reference/Guard.md)
-\> `GuardBearer`

## Active bindings

- `open_api`:

  An OpenID compliant security scheme description

## Methods

### Public methods

- [`GuardBearer$new()`](#method-GuardBearer-new)

- [`GuardBearer$check_request()`](#method-GuardBearer-check_request)

- [`GuardBearer$reject_response()`](#method-GuardBearer-reject_response)

- [`GuardBearer$clone()`](#method-GuardBearer-clone)

Inherited methods

- [`fireproof::Guard$forbid_user()`](https://thomasp85.github.io/fireproof/reference/Guard.html#method-forbid_user)
- [`fireproof::Guard$register_handler()`](https://thomasp85.github.io/fireproof/reference/Guard.html#method-register_handler)

------------------------------------------------------------------------

### Method `new()`

Constructor for the class

#### Usage

    GuardBearer$new(
      validate,
      user_info = NULL,
      realm = "private",
      allow_body_token = TRUE,
      allow_query_token = FALSE,
      name = NULL
    )

#### Arguments

- `validate`:

  A function that will be called with the arguments `token`, `realm`,
  `request`, and `response` and returns `TRUE` if the token is valid,
  and `FALSE` otherwise. If the function returns a character vector it
  is considered to be authenticated and the return value will be
  understood as scopes the user is granted.

- `user_info`:

  A function to extract user information from the token. It is called
  with a single argument: `token` which is the token used for the
  successful authentication. The function should return a new
  [user_info](https://thomasp85.github.io/fireproof/reference/new_user_info.md)
  list.

- `realm`:

  The realm this authentication corresponds to. Will be returned to the
  client on a failed authentication attempt to inform them of the
  credentials required, though most often these days it is kept from the
  user.

- `allow_body_token`:

  Should it be allowed to pass the token in the request body as a query
  form type with the `access_token` name. Defaults to `TRUE` but you can
  turn it off to force the client to use the `Authorization` header.

- `allow_query_token`:

  Should it be allowed to pass the token in the query string of the url
  with the `access_token` name. Default to `FALSE` due to severe
  security implications but can be turned on if you have very
  well-thought-out reasons to do so.

- `name`:

  The name of the authentication

------------------------------------------------------------------------

### Method `check_request()`

A function that validates an incoming request, returning `TRUE` if it is
valid and `FALSE` if not. It fetches the token from the request
according to the `allow_body_token` and `allow_query_token` settings and
validates it according to the provided function. If the token is present
multiple times it will fail with `400` as this is not allowed.

#### Usage

    GuardBearer$check_request(request, response, keys, ..., .session)

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

- `.session`:

  The session storage for the current session

------------------------------------------------------------------------

### Method `reject_response()`

Upon rejection this scheme sets the response status to `401` and sets
the `WWW-Authenticate` header to `Bearer realm="<realm>"`. If any scope
is provided by the endpoint it will be appended as `, scope="<scope>"`
and if the token is present but invalid, it will append
`, error="invalid_token"`

#### Usage

    GuardBearer$reject_response(response, scope, ..., .session)

#### Arguments

- `response`:

  The response object

- `scope`:

  The scope of the endpoint

- `...`:

  Ignored

- `.session`:

  The session storage for the current session

------------------------------------------------------------------------

### Method `clone()`

The objects of this class are cloneable with this method.

#### Usage

    GuardBearer$clone(deep = FALSE)

#### Arguments

- `deep`:

  Whether to make a deep clone.

## Examples

``` r
# Create a guard of dubious quality
bearer <- GuardBearer$new(
  validate = function(token) {
    token == "abcd1234"
  },
  user_info = function(user) {
    new_user_info(
      name_given = "Thomas",
      name_middle = "Lin",
      name_family = "Pedersen"
    )
  }
)
```
