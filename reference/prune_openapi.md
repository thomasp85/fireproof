# Ensure consistency of OpenAPI auth description

Prune an OpenAPI doc so that security descriptions only contains
references to the schemes defined in `securitySchemes` and only contains
scopes for the schemes that are OAuth2.0 and OpenID. For OAuth2.0
specifically, scopes are removed if they are not explicitly named in
`securitySchemes`.

## Usage

``` r
prune_openapi(doc)
```

## Arguments

- doc:

  A list describing a full OpenAPI documentation

## Value

The `doc` modified so the auth descriptions are internally consistent

## Examples

``` r
# OpenAPI stub only containing relevant info for example
openapi <- list(
  components = list(
    securitySchemes = list(
      auth1 = list(
        type = "http",
        scheme = "basic"
      ),
      auth2 = list(
        type = "oauth2",
        flows = list(
          authorizationCode = list(
            scopes = list(
              read = "read data",
              write = "change data"
            )
          )
        )
      )
    )
  ),
  # Global auth settings
  security = list(
    list(auth1 = c("read", "write"))
  ),
  # Path specific auth settings
  paths = list(
    "/user/{username}" = list(
      get = list(
        security = list(
          list(auth2 = c("read", "write", "commit")),
          list(auth3 = c("read"))
        )
      )
    )
  )
)

prune_openapi(openapi)
#> $components
#> $components$securitySchemes
#> $components$securitySchemes$auth1
#> $components$securitySchemes$auth1$type
#> [1] "http"
#> 
#> $components$securitySchemes$auth1$scheme
#> [1] "basic"
#> 
#> 
#> $components$securitySchemes$auth2
#> $components$securitySchemes$auth2$type
#> [1] "oauth2"
#> 
#> $components$securitySchemes$auth2$flows
#> $components$securitySchemes$auth2$flows$authorizationCode
#> $components$securitySchemes$auth2$flows$authorizationCode$scopes
#> $components$securitySchemes$auth2$flows$authorizationCode$scopes$read
#> [1] "read data"
#> 
#> $components$securitySchemes$auth2$flows$authorizationCode$scopes$write
#> [1] "change data"
#> 
#> 
#> 
#> 
#> 
#> 
#> 
#> $security
#> $security[[1]]
#> $security[[1]]$auth1
#> character(0)
#> 
#> 
#> 
#> $paths
#> $paths$`/user/{username}`
#> $paths$`/user/{username}`$get
#> $paths$`/user/{username}`$get$security
#> $paths$`/user/{username}`$get$security[[1]]
#> $paths$`/user/{username}`$get$security[[1]]$auth2
#> [1] "read"  "write"
#> 
#> 
#> 
#> 
#> 
#> 
```
