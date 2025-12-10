# R6 class for the Basic authentication guard

This class encapsulates the logic of the [Basic authentication
scheme](https://datatracker.ietf.org/doc/html/rfc7617). See
[`guard_basic()`](https://thomasp85.github.io/fireproof/reference/guard_basic.md)
for more information.

## Super class

[`fireproof::Guard`](https://thomasp85.github.io/fireproof/reference/Guard.md)
-\> `GuardBasic`

## Active bindings

- `open_api`:

  An OpenID compliant security scheme description

## Methods

### Public methods

- [`GuardBasic$new()`](#method-GuardBasic-new)

- [`GuardBasic$check_request()`](#method-GuardBasic-check_request)

- [`GuardBasic$reject_response()`](#method-GuardBasic-reject_response)

- [`GuardBasic$clone()`](#method-GuardBasic-clone)

Inherited methods

- [`fireproof::Guard$forbid_user()`](https://thomasp85.github.io/fireproof/reference/Guard.html#method-forbid_user)
- [`fireproof::Guard$register_handler()`](https://thomasp85.github.io/fireproof/reference/Guard.html#method-register_handler)

------------------------------------------------------------------------

### Method `new()`

Constructor for the class

#### Usage

    GuardBasic$new(validate, user_info = NULL, realm = "private", name = NULL)

#### Arguments

- `validate`:

  A function that will be called with the arguments `username`,
  `password`, `realm`, `request`, and `response` and returns `TRUE` if
  the user is valid, and `FALSE` otherwise. If the function returns a
  character vector it is considered to be authenticated and the return
  value will be understood as scopes the user is granted.

- `user_info`:

  A function to extract user information from the username. It is called
  with a single argument: `user` which is the username used for the
  successful authentication. The function should return a new
  [user_info](https://thomasp85.github.io/fireproof/reference/new_user_info.md)
  list.

- `realm`:

  The realm this authentication corresponds to. Will be returned to the
  client on a failed authentication attempt to inform them of the
  credentials required, though most often these days it is kept from the
  user.

- `name`:

  The name of the authentication

------------------------------------------------------------------------

### Method `check_request()`

A function that validates an incoming request, returning `TRUE` if it is
valid and `FALSE` if not. It decodes the credentials in the
`Authorization` header, splits it into username and password and then
calls the `validate` function provided at construction.

#### Usage

    GuardBasic$check_request(request, response, keys, ..., .datastore)

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

Upon rejection this scheme sets the response status to `401` and sets
the `WWW-Authenticate` header to `Basic realm="<realm>", charset=UTF-8`

#### Usage

    GuardBasic$reject_response(response, scope, ..., .datastore)

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

### Method `clone()`

The objects of this class are cloneable with this method.

#### Usage

    GuardBasic$clone(deep = FALSE)

#### Arguments

- `deep`:

  Whether to make a deep clone.

## Examples

``` r
# Create a guard of dubious quality
basic <- GuardBasic$new(
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
```
