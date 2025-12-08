# R6 base class for guards

All guards inherit from this base class and adapts it for the particular
scheme it implements. Additional schemes can be implemented as
subclasses of this and will work transparently with fireproof.

## Usage

``` r
is_guard(x)
```

## Arguments

- x:

  An object

## Active bindings

- `name`:

  The name of the instance

- `open_api`:

  An OpenID compliant security scheme description

## Methods

### Public methods

- [`Guard$new()`](#method-Guard-new)

- [`Guard$check_request()`](#method-Guard-check_request)

- [`Guard$reject_response()`](#method-Guard-reject_response)

- [`Guard$forbid_user()`](#method-Guard-forbid_user)

- [`Guard$register_handler()`](#method-Guard-register_handler)

- [`Guard$clone()`](#method-Guard-clone)

------------------------------------------------------------------------

### Method `new()`

Constructor for the class

#### Usage

    Guard$new(name = NULL)

#### Arguments

- `name`:

  The name of the scheme instance

------------------------------------------------------------------------

### Method `check_request()`

A function that validates an incoming request, returning `TRUE` if it is
valid and `FALSE` if not. The base class simply returns `TRUE` for all
requests

#### Usage

    Guard$check_request(request, response, keys, ..., .session)

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

Action to perform on the response in case the request fails to get
validated by any instance in the flow. All failing instances will have
this method called one by one so be mindful if you are overwriting
information set by another instance

#### Usage

    Guard$reject_response(response, scope, ..., .session)

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

### Method `forbid_user()`

Action to perform on the response in case the request does not have the
necessary permissions for the endpoint. All succeeding instances will
have this method called one by one if permissions are insufficient so be
mindful if you are overwriting information set by another instance

#### Usage

    Guard$forbid_user(response, scope, ..., .session)

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

### Method `register_handler()`

Hook for registering endpoint handlers needed for this auth method

#### Usage

    Guard$register_handler(add_handler)

#### Arguments

- `add_handler`:

  The `add_handler` method from
  [Fireproof](https://thomasp85.github.io/fireproof/reference/Fireproof.md)
  to be called for adding additional handlers

------------------------------------------------------------------------

### Method `clone()`

The objects of this class are cloneable with this method.

#### Usage

    Guard$clone(deep = FALSE)

#### Arguments

- `deep`:

  Whether to make a deep clone.

## Examples

``` r
# You'd never actually do this, rather you'd use the subclasses
guard <- Guard$new(name = "base_auth")
```
