# Guard for authenticating with the GitHub OAuth 2.0 server

This guard requests you to log in with GitHub and authenticates yourself
through their service. Your server must be registered and have a valid
client ID and client secret for this to work. Register an application at
<https://github.com/settings/applications/new>. If you want to limit
access to only select users you should make sure to provide a `validate`
function that checks the userinfo against a whitelist.

## Usage

``` r
guard_github(redirect_url, client_id, client_secret, ..., name = "github")
```

## Arguments

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

- ...:

  Arguments passed on to
  [`guard_oauth2`](https://thomasp85.github.io/fireproof/reference/guard_oauth2.md)

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

  `service_params`

  :   A named list of additional query params to add to the url when
      constructing the authorization url in the `"authorization_code"`
      grant type

- name:

  The name of the guard

## Value

A
[GuardOAuth2](https://thomasp85.github.io/fireproof/reference/GuardOAuth2.md)
object

## User information

`guard_github()` automatically adds user information according to the
description in
[`guard_oauth2()`](https://thomasp85.github.io/fireproof/reference/guard_oauth2.md).
It sets the `provider` field to `"github"`. Further, extracts
information from the `https://api.github.com/user` endpoint and maps the
information accordingly:

- `id` -\> `id`

- `name` -\> `name_display`

- `login` -\> `name_user`

- `email` -\> `emails`

- `avatar_url` -\> `photos`

It also sets the `.raw` field to the full list of information returned
from github.

## References

[Documentation for GitHub's OAuth 2
flow](https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/generating-a-user-access-token-for-a-github-app)

## Examples

``` r
github <- guard_github(
  redirect_url = "https://example.com/auth",
  client_id = "MY_APP_ID",
  client_secret = "SUCHASECRET"
)

# Add it to a fireproof plugin
fp <- Fireproof$new()
fp$add_guard(github, "github_auth")

# Use it in an endpoint
fp$add_auth("get", "/*", github_auth)
```
