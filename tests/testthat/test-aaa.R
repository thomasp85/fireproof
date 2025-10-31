test_that("get_path extracts path from simple URL", {
  result <- get_path("https://example.com/auth")
  expect_equal(result, "/auth")

  result <- get_path("http://example.com/callback")
  expect_equal(result, "/callback")
})

test_that("get_path extracts path with multiple segments", {
  result <- get_path("https://example.com/api/v1/auth")
  expect_equal(result, "/api/v1/auth")

  result <- get_path("https://example.com/auth/oauth/callback")
  expect_equal(result, "/auth/oauth/callback")
})

test_that("get_path handles URL with query parameters", {
  result <- get_path("https://example.com/auth?param=value")
  expect_equal(result, "/auth?param=value")

  result <- get_path("https://example.com/callback?code=123&state=abc")
  expect_equal(result, "/callback?code=123&state=abc")
})

test_that("get_path handles URL with fragment", {
  result <- get_path("https://example.com/auth#section")
  expect_equal(result, "/auth#section")

  result <- get_path("https://example.com/page#fragment?query=value")
  expect_equal(result, "/page#fragment?query=value")
})

test_that("get_path handles URL with port", {
  result <- get_path("https://example.com:8080/auth")
  expect_equal(result, "/auth")

  result <- get_path("http://localhost:3000/callback")
  expect_equal(result, "/callback")
})

test_that("get_path handles URL with subdomain", {
  result <- get_path("https://api.example.com/auth")
  expect_equal(result, "/auth")

  result <- get_path("https://auth.services.example.com/oauth/callback")
  expect_equal(result, "/oauth/callback")
})

test_that("get_path returns / for root URL", {
  result <- get_path("https://example.com")
  expect_equal(result, "/")

  result <- get_path("https://example.com/")
  expect_equal(result, "/")

  result <- get_path("http://localhost")
  expect_equal(result, "/")
})

test_that("get_path removes root from path", {
  result <- get_path("https://example.com/api/auth", root = "/api")
  expect_equal(result, "/auth")

  result <- get_path("https://example.com/v1/callback", root = "/v1")
  expect_equal(result, "/callback")
})

test_that("get_path removes root with or without leading slash", {
  result <- get_path("https://example.com/api/auth", root = "/api")
  expect_equal(result, "/auth")

  result <- get_path("https://example.com/api/auth", root = "api")
  expect_equal(result, "/auth")
})

test_that("get_path handles root that doesn't match", {
  expect_snapshot(
    get_path("https://example.com/auth", root = "/api"),
    error = TRUE
  )

  expect_snapshot(
    get_path("https://example.com/v1/auth", root = "/v2"),
    error = TRUE
  )
})

test_that("get_path handles root of / or empty string", {
  result <- get_path("https://example.com/auth", root = "/")
  expect_equal(result, "/auth")

  result <- get_path("https://example.com/auth", root = "")
  expect_equal(result, "/auth")
})

test_that("get_path returns / when root matches entire path", {
  result <- get_path("https://example.com/api", root = "/api")
  expect_equal(result, "/")

  result <- get_path("https://example.com/v1", root = "/v1")
  expect_equal(result, "/")
})

test_that("get_path handles complex root paths", {
  result <- get_path("https://example.com/api/v1/auth", root = "/api/v1")
  expect_equal(result, "/auth")

  result <- get_path(
    "https://example.com/services/oauth/callback",
    root = "/services/oauth"
  )
  expect_equal(result, "/callback")
})

test_that("get_path handles URLs with special characters", {
  result <- get_path("https://example.com/auth%20callback")
  expect_equal(result, "/auth%20callback")

  result <- get_path("https://example.com/auth+callback")
  expect_equal(result, "/auth+callback")
})

test_that("get_path handles both http and https", {
  result_http <- get_path("http://example.com/auth")
  result_https <- get_path("https://example.com/auth")

  expect_equal(result_http, "/auth")
  expect_equal(result_https, "/auth")
  expect_equal(result_http, result_https)
})

test_that("get_path preserves trailing slash", {
  result <- get_path("https://example.com/auth/")
  expect_equal(result, "/auth/")

  result <- get_path("https://example.com/api/v1/")
  expect_equal(result, "/api/v1/")
})

test_that("get_path handles root with trailing slash", {
  result <- get_path("https://example.com/api/auth", root = "/api/")

  expect_equal(result, "/auth")
})

test_that("abort_auth creates proper error", {
  err <- rlang::catch_cnd(abort_auth("Test error message"))

  expect_s3_class(err, "reqres_problem")
  expect_equal(err$message, "Test error message")
  expect_equal(err$status, 503L)
  expect_equal(err$detail, "Unable to complete authentication")
  expect_equal(err$title, "authentication_failed")
})

test_that("with_dots adds ... to function without it", {
  test_fn <- function(a, b) {
    a + b
  }

  modified_fn <- with_dots(test_fn)

  # Should now accept extra arguments
  expect_no_error(modified_fn(1, 2, extra = "ignored"))
  expect_equal(modified_fn(1, 2), 3)
  expect_equal(modified_fn(1, 2, x = 1, y = 2, z = 3), 3)
})

test_that("with_dots preserves existing ... in function", {
  test_fn <- function(a, b, ...) {
    a + b
  }

  modified_fn <- with_dots(test_fn)

  # Should work the same
  expect_equal(modified_fn(1, 2), 3)
  expect_equal(modified_fn(1, 2, extra = "arg"), 3)

  # Should not have duplicate ...
  fmls <- formals(modified_fn)
  dots_count <- sum(names(fmls) == "...")
  expect_equal(dots_count, 1)
})

test_that("with_dots handles function with default arguments", {
  test_fn <- function(a, b = 10) {
    a + b
  }

  modified_fn <- with_dots(test_fn)

  expect_equal(modified_fn(5), 15)
  expect_equal(modified_fn(5, 20), 25)
  expect_equal(modified_fn(5, extra = "ignored"), 15)
})

test_that("with_dots handles zero-argument functions", {
  test_fn <- function() {
    42
  }

  modified_fn <- with_dots(test_fn)

  expect_equal(modified_fn(), 42)
  expect_equal(modified_fn(extra = "arg"), 42)
})

test_that("with_dots preserves function environment", {
  x <- 10
  test_fn <- function(a) a + x

  modified_fn <- with_dots(test_fn)

  expect_equal(modified_fn(5), 15)
})
