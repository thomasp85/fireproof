
<!-- README.md is generated from README.Rmd. Please edit that file -->

# fireproof

<!-- badges: start -->

[![R-CMD-check](https://github.com/thomasp85/fireproof/actions/workflows/R-CMD-check.yaml/badge.svg)](https://github.com/thomasp85/fireproof/actions/workflows/R-CMD-check.yaml)
[![Codecov test
coverage](https://codecov.io/gh/thomasp85/fireproof/graph/badge.svg)](https://app.codecov.io/gh/thomasp85/fireproof)
<!-- badges: end -->

fireproof is a plugin for [fiery](https://fiery.data-imaginist.com/)
based servers. It provides a unified framework for adding authentication
to your server backend.

There is currently support for Basic and Bearer authentication as well
as Key based authentication.

fireproof supports multiple authentication routes for each endpoint so
that you can specify that access to a certain endpoint requires either
passing this and/or this challenges. The logic can be arbitrarily
complex though for your own sanity it probably shouldn’t.

## Installation

You can install the development version of fireproof from
[GitHub](https://github.com/) with:

``` r
# install.packages("pak")
pak::pak("thomasp85/fireproof")
```

## Example

This is a basic example which shows you how to solve a common problem:

``` r
library(fireproof)

# Create the plugin
proof <- Fireproof$new()

# Create two different authenticators
key_auth <- auth_key(
  key = "FireproofKey",
  secret = "VerySecretString",
  cookie = FALSE
)
basic_auth <- auth_basic(
  authenticator = function(user, password, ...) {
    user == "thomas" && password == "1234"
  }
)

# Add them to the plugin
proof$add_auth(key_auth, "key")
proof$add_auth(basic_auth, "basic")

# Add authentication to some endpoints with varying combinations of requirements
proof$add_auth_handler("get", "/user/settings", basic) # must pass basic auth
proof$add_auth_handler("get", "/api/predict", key || basic) # must pass either
proof$add_auth_handler("get", "/strong/auth", key && basic) # must pass both

# If you have even more authenticators you can group conditions with () as well


# Create a fiery app and attach the plugin
app <- fiery::Fire$new()
app$attach(proof)
```
