# R6 class for the Key guard

This class encapsulates the logic of the key based authentication
scheme. See
[`guard_key()`](https://thomasp85.github.io/fireproof/reference/guard_key.md)
for more information

## Super class

[`fireproof::Guard`](https://thomasp85.github.io/fireproof/reference/Guard.md)
-\> `GuardKey`

## Active bindings

- `location`:

  The location of the secret in the request, either `"cookie"` or
  `"header"`

- `open_api`:

  An OpenID compliant security scheme description

## Methods

### Public methods

- [`GuardKey$new()`](#method-GuardKey-new)

- [`GuardKey$check_request()`](#method-GuardKey-check_request)

- [`GuardKey$reject_response()`](#method-GuardKey-reject_response)

- [`GuardKey$clone()`](#method-GuardKey-clone)

Inherited methods

- [`fireproof::Guard$forbid_user()`](https://thomasp85.github.io/fireproof/reference/Guard.html#method-forbid_user)
- [`fireproof::Guard$register_handler()`](https://thomasp85.github.io/fireproof/reference/Guard.html#method-register_handler)

------------------------------------------------------------------------

### Method `new()`

Constructor for the class

#### Usage

    GuardKey$new(key_name, validate, user_info = NULL, cookie = TRUE, name = NULL)

#### Arguments

- `key_name`:

  The name of the header or cookie to store the secret under

- `validate`:

  Either a single string with the secret or a function that will be
  called with the arguments `key`, `request`, and `response` and returns
  `TRUE` if its a valid secret (useful if you have multiple or rotating
  secrets). If the function returns a character vector it is considered
  to be authenticated and the return value will be understood as scopes
  the user is granted. Make sure never to store secrets in plain text
  and avoid checking them into version control.

- `user_info`:

  A function to extract user information from the key. It is called with
  a single argument: `key` which is the key used for the successful
  authentication. The function should return a new
  [user_info](https://thomasp85.github.io/fireproof/reference/new_user_info.md)
  list.

- `cookie`:

  Boolean. Should the secret be transmitted as a cookie. If `FALSE` it
  is expected to be transmitted as a header.

- `name`:

  The name of the guard

------------------------------------------------------------------------

### Method `check_request()`

A function that validates an incoming request, returning `TRUE` if it is
valid and `FALSE` if not. It extracts the secret from either the cookie
or header based on the provided `key_name` and test it using the
provided `validate` function.

#### Usage

    GuardKey$check_request(request, response, keys, ..., .datastore)

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

Upon rejection this guard sets the response status to `400` if it has
not already been set by others. In contrast to some of the other guards
which implements proper HTTP schemes, this one doesn't set a
`WWW-Authenticate` header.

#### Usage

    GuardKey$reject_response(response, scope, ..., .datastore)

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

    GuardKey$clone(deep = FALSE)

#### Arguments

- `deep`:

  Whether to make a deep clone.

## Examples

``` r
# Create a guard of dubious quality
key <- GuardKey$new(
  key = "my-key-location",
  validate = "SHHH!!DONT_TELL_ANYONE"
)
```
