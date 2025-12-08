# Extract the path from a URL

This function is a simple helper that extract the path part of a URL. It
is useful when constructing OAuth 2.0 derived authenticators for the
`redirect_path` argument.

## Usage

``` r
get_path(url, root = NULL)
```

## Arguments

- url:

  The url to extract the path from

- root:

  An optional root to remove from the path as well

## Value

The "path" part of the URL

## Examples

``` r
get_path("https://example.com/auth")
#> [1] "/auth"

get_path("https://example.com/api/auth", root = "/api")
#> [1] "/auth"
```
