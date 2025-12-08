# A plugin that handles authentication and/or authorization

This plugin orchestrates all guards for your fiery app. It is a special
Route that manages all the different guards you have defined as well as
testing all the endpoints that have auth requirements.

## Details

A guard is an object deriving from the
[Guard](https://thomasp85.github.io/fireproof/reference/Guard.md) class
which is usually created with one of the `guard_*()` constructors. You
can provide it with a name as you register it and can thus have multiple
instances of the same scheme (e.g. two
[`guard_basic()`](https://thomasp85.github.io/fireproof/reference/guard_basic.md)
with different user lists)

An auth handler is a handler that consists of a method, path, and flow.
The flow is a logical expression of the various guards the request must
pass to get access to that endpoint. For example, if you have two guards
named `auth1` and `auth2`, a flow could be `auth1 || auth2` to allow a
request if it passes either of the guards. Given an additional guard,
`auth3`, it could also be something like `auth1 || (auth2 && auth3)`.
The flow is given as a bare expression, not as a string. In addition to
the three required arguments you can also supply a character vector of
scopes that are required to have access to the endpoint. If your guard
has scope support then the request will be tested against these to see
if the (otherwise valid) user has permission to the resource.

## Super class

[`routr::Route`](https://routr.data-imaginist.com/reference/Route-class.html)
-\> `Fireproof`

## Active bindings

- `name`:

  The name of the plugin: `"fireproof"`

- `require`:

  Required plugins for Fireproof

- `guards`:

  The name of all the guards currently added to the plugin

## Methods

### Public methods

- [`Fireproof$print()`](#method-Fireproof-print)

- [`Fireproof$add_auth()`](#method-Fireproof-add_auth)

- [`Fireproof$add_guard()`](#method-Fireproof-add_guard)

- [`Fireproof$add_handler()`](#method-Fireproof-add_handler)

- [`Fireproof$flow_to_openapi()`](#method-Fireproof-flow_to_openapi)

- [`Fireproof$on_attach()`](#method-Fireproof-on_attach)

- [`Fireproof$clone()`](#method-Fireproof-clone)

Inherited methods

- [`routr::Route$dispatch()`](https://routr.data-imaginist.com/reference/Route-class.html#method-dispatch)
- [`routr::Route$get_handler()`](https://routr.data-imaginist.com/reference/Route-class.html#method-get_handler)
- [`routr::Route$initialize()`](https://routr.data-imaginist.com/reference/Route-class.html#method-initialize)
- [`routr::Route$merge_route()`](https://routr.data-imaginist.com/reference/Route-class.html#method-merge_route)
- [`routr::Route$remap_handlers()`](https://routr.data-imaginist.com/reference/Route-class.html#method-remap_handlers)
- [`routr::Route$remove_handler()`](https://routr.data-imaginist.com/reference/Route-class.html#method-remove_handler)

------------------------------------------------------------------------

### Method [`print()`](https://rdrr.io/r/base/print.html)

Print method for the class

#### Usage

    Fireproof$print(...)

#### Arguments

- `...`:

  Ignored

------------------------------------------------------------------------

### Method `add_auth()`

Add a new authentication handler. It invisibly returns the parsed flow
so it can be used for generating OpenAPI specs with.

#### Usage

    Fireproof$add_auth(method, path, flow, scope = NULL)

#### Arguments

- `method`:

  The http method to match the handler to

- `path`:

  The URL path to match to

- `flow`:

  The authentication flow the request must pass to be valid. See
  *Details*. If `NULL` then authentication is turned off for the
  endpoint.

- `scope`:

  An optional character vector of scopes that the request must have
  permission for to access the resource

------------------------------------------------------------------------

### Method `add_guard()`

Add a guard to the plugin

#### Usage

    Fireproof$add_guard(guard, name = NULL)

#### Arguments

- `guard`:

  Either a
  [Guard](https://thomasp85.github.io/fireproof/reference/Guard.md)
  object defining the guard (preferred) or a function taking the
  standard route handler arguments (`request`, `response`, `keys`, and
  `...`) and returns `TRUE` if the request is valid and `FALSE` if not.

- `name`:

  The name of the guard to be used when defining flow for endpoint auth.

------------------------------------------------------------------------

### Method `add_handler()`

Defunct overwrite of the `add_handler()` method to prevent this route to
be used for anything other than auth. Will throw an error if called.

#### Usage

    Fireproof$add_handler(method, path, handler, reject_missing_methods = FALSE)

#### Arguments

- `method`:

  ignored

- `path`:

  ignored

- `handler`:

  ignored

- `reject_missing_methods`:

  ignored

------------------------------------------------------------------------

### Method `flow_to_openapi()`

Turns a parsed flow (as returned by `add_auth()`) into an OpenAPI
Security Requirement compliant list. Not all flows can be represented by
the OpenAPI spec and the method will return `NULL` with a warning if so.
Scope is added to all schemes, even if not applicable, so the final
OpenAPI doc should be run through
[`prune_openapi()`](https://thomasp85.github.io/fireproof/reference/prune_openapi.md)
before serving it.

#### Usage

    Fireproof$flow_to_openapi(flow, scope)

#### Arguments

- `flow`:

  A parsed flow as returned by `add_auth()`

- `scope`:

  A character vector of scopes required for this particular flow

------------------------------------------------------------------------

### Method `on_attach()`

Method for use by fiery when attached as a plugin. Should not be called
directly. This method looks for a header route stack in the app and if
it doesn't exist it creates one. It then attaches the plugin as the
first route to it.

#### Usage

    Fireproof$on_attach(app, ...)

#### Arguments

- `app`:

  The Fire object to attach the router to

- `...`:

  Ignored

------------------------------------------------------------------------

### Method `clone()`

The objects of this class are cloneable with this method.

#### Usage

    Fireproof$clone(deep = FALSE)

#### Arguments

- `deep`:

  Whether to make a deep clone.

## Examples

``` r
# Create a fireproof plugin
fp <- Fireproof$new()

# Create some authentication schemes and add them
basic <- guard_basic(
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
fp$add_guard(basic, "basic_auth")

key <- guard_key(
  key_name = "my-key-location",
  validate = "SHHH!!DONT_TELL_ANYONE"
)
fp$add_guard(key, "key_auth")

google <- guard_google(
  redirect_url = "https://example.com/auth",
  client_id = "MY_APP_ID",
  client_secret = "SUCHASECRET",
)
fp$add_guard(google, "google_auth")

# Add authentication to different paths
fp$add_auth("get", "/require_basic", basic_auth)

fp$add_auth("get", "/require_basic_and_key", basic_auth && key_auth)

fp$add_auth(
  "get",
  "/require_google_or_the_others",
  google_auth || (basic_auth && key_auth)
)

# Add plugin to fiery app
app <- fiery::Fire$new()

# First add the firesale plugin as it is required
fs <- firesale::FireSale$new(storr::driver_environment(new.env()))
app$attach(fs)

# Then add the fireproof plugin
app$attach(fp)
```
