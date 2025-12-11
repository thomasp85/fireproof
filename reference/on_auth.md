# Predefined functions for handling successful OAuth 2.0 authentication

When using the `"authorization code"` grant type in an OAuth 2.0
authorization flow, you have to decide what to do after an access token
has been successfully retrieved. Since the flow goes through multiple
redirection the original request is no longer available once the access
token has been retrieved. The `replay_request()` function will use the
saved session_state from the original request to construct a "fake"
request and replay that on the server to obtain the response it would
have given had the user already been authorized. The `redirect_back()`
function will try to redirect the user back to the location they where
at when they send the request that prompted authorization. You can also
create your own function that e.g. presents a "Successfully logged on"
webpage. See *Details* for information on the requirements for such a
function.

## Usage

``` r
replay_request(request, response, session_state, server)

redirect_back(request, response, session_state, server)

redirect_to(url)
```

## Arguments

- request:

  The current request being handled, as a
  [reqres::Request](https://reqres.data-imaginist.com/reference/Request.html)
  object. The result of a redirection from the authorization server.

- response:

  The response being returned to the user as a
  [reqres::Response](https://reqres.data-imaginist.com/reference/Response.html)
  object.

- session_state:

  A list of stored information from the original request. Contains the
  following fields: `state` (a random string identifying the
  authorization attempt), `time` (the timestamp of the original
  request), `method` (the http method of the original request), `url`
  (the full url of the original request, including any query string),
  `headers` (A named list of all the headers of the original request),
  `body` (a raw vector of the body of the original request), and `from`
  (The url the original request was sent from)

- server:

  The fiery server handling the request

- url:

  The URL to redirect to after successful authentication

## Value

`TRUE` if the request should continue processing in the server or
`FALSE` if the response should be send straight away

## Details

Creating your own success handler is easy and just requires that you
conform to the input arguments of the functions described here. The main
purpose of the function is to modify the response object that is being
send back to the user to fit your needs. As with any routr handler it
should return a boolean indicating if further processing should happen.
For this situation it is usually sensible to return `FALSE`.

## Examples

``` r
# These functions are never called directly but passed on to the `on_auth`
# argument in OAuth 2.0 and OpenID Connect authentication flows

# Default
google <- guard_google(
  redirect_url = "https://example.com/auth",
  client_id = "MY_APP_ID",
  client_secret = "SUCHASECRET",
  on_auth = replay_request
)

# Alternative
google <- guard_google(
  redirect_url = "https://example.com/auth",
  client_id = "MY_APP_ID",
  client_secret = "SUCHASECRET",
  on_auth = redirect_back
)
```
