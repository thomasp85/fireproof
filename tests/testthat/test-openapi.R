test_that("prune_openapi removes undefined schemes from global security", {
  openapi <- list(
    components = list(
      securitySchemes = list(
        auth1 = list(type = "http", scheme = "basic")
      )
    ),
    security = list(
      list(auth1 = character()),
      list(auth2 = character())  # auth2 not defined
    )
  )

  result <- prune_openapi(openapi)

  # auth2 should be removed, only auth1 remains
  expect_equal(length(result$security), 1)
  expect_true("auth1" %in% names(result$security[[1]]))
  expect_false("auth2" %in% names(result$security[[1]]))
})

test_that("prune_openapi removes scopes from non-OAuth schemes", {
  openapi <- list(
    components = list(
      securitySchemes = list(
        basic_auth = list(type = "http", scheme = "basic"),
        bearer_auth = list(type = "http", scheme = "bearer")
      )
    ),
    security = list(
      list(basic_auth = c("read", "write")),
      list(bearer_auth = c("admin"))
    )
  )

  result <- prune_openapi(openapi)

  # Non-OAuth schemes should have empty character vector (no scopes)
  expect_equal(result$security[[1]]$basic_auth, character())
  expect_equal(result$security[[2]]$bearer_auth, character())
})

test_that("prune_openapi preserves valid OAuth2 scopes", {
  openapi <- list(
    components = list(
      securitySchemes = list(
        oauth = list(
          type = "oauth2",
          flows = list(
            authorizationCode = list(
              scopes = list(
                read = "Read access",
                write = "Write access"
              )
            )
          )
        )
      )
    ),
    security = list(
      list(oauth = c("read", "write"))
    )
  )

  result <- prune_openapi(openapi)

  expect_equal(result$security[[1]]$oauth, c("read", "write"))
})

test_that("prune_openapi removes invalid OAuth2 scopes", {
  openapi <- list(
    components = list(
      securitySchemes = list(
        oauth = list(
          type = "oauth2",
          flows = list(
            authorizationCode = list(
              scopes = list(
                read = "Read access",
                write = "Write access"
              )
            )
          )
        )
      )
    ),
    security = list(
      list(oauth = c("read", "write", "delete", "admin"))
    )
  )

  result <- prune_openapi(openapi)

  # Only read and write are valid, delete and admin should be removed
  expect_equal(result$security[[1]]$oauth, c("read", "write"))
  expect_false("delete" %in% result$security[[1]]$oauth)
  expect_false("admin" %in% result$security[[1]]$oauth)
})

test_that("prune_openapi handles OpenID Connect scopes", {
  openapi <- list(
    components = list(
      securitySchemes = list(
        oidc = list(
          type = "openIdConnect",
          openIdConnectUrl = "https://example.com/.well-known/openid-configuration"
        )
      )
    ),
    security = list(
      list(oidc = c("openid", "profile", "email"))
    )
  )

  result <- prune_openapi(openapi)

  # OpenID Connect allows scopes
  expect_equal(result$security[[1]]$oidc, c("openid", "profile", "email"))
})

test_that("prune_openapi processes path-specific security", {
  openapi <- list(
    components = list(
      securitySchemes = list(
        auth1 = list(type = "http", scheme = "basic")
      )
    ),
    paths = list(
      "/users" = list(
        get = list(
          security = list(
            list(auth1 = character()),
            list(auth2 = character())  # undefined
          )
        )
      )
    )
  )

  result <- prune_openapi(openapi)

  # auth2 should be removed from path security
  expect_equal(length(result$paths[["/users"]]$get$security), 1)
  expect_true("auth1" %in% names(result$paths[["/users"]]$get$security[[1]]))
  expect_false("auth2" %in% names(result$paths[["/users"]]$get$security[[1]]))
})

test_that("prune_openapi handles multiple OAuth2 flows", {
  openapi <- list(
    components = list(
      securitySchemes = list(
        oauth = list(
          type = "oauth2",
          flows = list(
            authorizationCode = list(
              scopes = list(
                read = "Read",
                write = "Write"
              )
            ),
            implicit = list(
              scopes = list(
                read = "Read",
                admin = "Admin"
              )
            )
          )
        )
      )
    ),
    security = list(
      list(oauth = c("read", "write", "admin", "delete"))
    )
  )

  result <- prune_openapi(openapi)

  # Should include scopes from all flows: read, write, admin
  # Should exclude: delete
  expect_setequal(result$security[[1]]$oauth, c("read", "write", "admin"))
  expect_false("delete" %in% result$security[[1]]$oauth)
})

test_that("prune_openapi handles mixed security schemes", {
  openapi <- list(
    components = list(
      securitySchemes = list(
        basic = list(type = "http", scheme = "basic"),
        oauth = list(
          type = "oauth2",
          flows = list(
            authorizationCode = list(
              scopes = list(read = "Read", write = "Write")
            )
          )
        ),
        api_key = list(type = "apiKey", "in" = "header", name = "X-API-Key")
      )
    ),
    security = list(
      list(
        basic = c("invalid_scope"),
        oauth = c("read", "write", "admin"),
        api_key = c("also_invalid")
      )
    )
  )

  result <- prune_openapi(openapi)

  # basic and api_key should have no scopes
  expect_equal(result$security[[1]]$basic, character())
  expect_equal(result$security[[1]]$api_key, character())

  # oauth should only have valid scopes
  expect_equal(result$security[[1]]$oauth, c("read", "write"))
})

test_that("prune_openapi removes empty security definitions", {
  openapi <- list(
    components = list(
      securitySchemes = list(
        auth1 = list(type = "http", scheme = "basic")
      )
    ),
    security = list(
      list(auth1 = character()),
      list(auth2 = character()),  # undefined - will be removed
      list(auth3 = character())   # undefined - will be removed
    )
  )

  result <- prune_openapi(openapi)

  # Only auth1 should remain, empty entries removed
  expect_equal(length(result$security), 1)
  expect_true("auth1" %in% names(result$security[[1]]))
})

test_that("prune_openapi handles NULL global security", {
  openapi <- list(
    components = list(
      securitySchemes = list(
        auth1 = list(type = "http", scheme = "basic")
      )
    ),
    security = NULL,
    paths = list(
      "/test" = list(
        get = list(
          security = list(list(auth1 = character()))
        )
      )
    )
  )

  result <- prune_openapi(openapi)

  # Should not error with NULL security
  expect_null(result$security)
  expect_equal(length(result$paths[["/test"]]$get$security), 1)
})

test_that("prune_openapi handles paths without security", {
  openapi <- list(
    components = list(
      securitySchemes = list(
        auth1 = list(type = "http", scheme = "basic")
      )
    ),
    paths = list(
      "/public" = list(
        get = list(
          description = "Public endpoint"
          # No security field
        )
      ),
      "/private" = list(
        get = list(
          security = list(list(auth1 = character()))
        )
      )
    )
  )

  result <- prune_openapi(openapi)

  # Public endpoint should remain unchanged (no security field)
  expect_null(result$paths[["/public"]]$get$security)

  # Private endpoint should have security
  expect_length(result$paths[["/private"]]$get$security, 1)
})

test_that("prune_openapi handles multiple methods per path", {
  openapi <- list(
    components = list(
      securitySchemes = list(
        auth1 = list(type = "http", scheme = "basic")
      )
    ),
    paths = list(
      "/resource" = list(
        get = list(
          security = list(list(auth1 = character()))
        ),
        post = list(
          security = list(list(auth1 = character(), auth2 = character()))
        ),
        delete = list(
          security = list(list(auth1 = character()))
        )
      )
    )
  )

  result <- prune_openapi(openapi)

  # All methods should be processed
  expect_true("auth1" %in% names(result$paths[["/resource"]]$get$security[[1]]))
  expect_true("auth1" %in% names(result$paths[["/resource"]]$post$security[[1]]))
  expect_false("auth2" %in% names(result$paths[["/resource"]]$post$security[[1]]))
  expect_true("auth1" %in% names(result$paths[["/resource"]]$delete$security[[1]]))
})

test_that("prune_openapi handles API key authentication", {
  openapi <- list(
    components = list(
      securitySchemes = list(
        api_key = list(
          type = "apiKey",
          "in" = "header",
          name = "X-API-Key"
        )
      )
    ),
    security = list(
      list(api_key = c("invalid_scope"))
    )
  )

  result <- prune_openapi(openapi)

  # API key doesn't use scopes
  expect_equal(result$security[[1]]$api_key, character())
})

test_that("prune_openapi handles Bearer token authentication", {
  openapi <- list(
    components = list(
      securitySchemes = list(
        bearer = list(
          type = "http",
          scheme = "bearer",
          bearerFormat = "JWT"
        )
      )
    ),
    security = list(
      list(bearer = c("some_scope"))
    )
  )

  result <- prune_openapi(openapi)

  # Bearer doesn't use scopes (unless it's OAuth2)
  expect_equal(result$security[[1]]$bearer, character())
})

test_that("prune_openapi handles duplicate scopes in OAuth2", {
  openapi <- list(
    components = list(
      securitySchemes = list(
        oauth = list(
          type = "oauth2",
          flows = list(
            authorizationCode = list(
              scopes = list(read = "Read", write = "Write")
            ),
            implicit = list(
              scopes = list(read = "Read again", admin = "Admin")
            )
          )
        )
      )
    ),
    security = list(
      list(oauth = c("read", "write", "admin"))
    )
  )

  result <- prune_openapi(openapi)

  # Should handle duplicate 'read' across flows
  expect_setequal(result$security[[1]]$oauth, c("read", "write", "admin"))
  expect_equal(length(result$security[[1]]$oauth), 3)
})
