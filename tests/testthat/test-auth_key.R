test_that("auth_key can be constructed and verify", {
  auth <- auth_key(
    key = "x-api-key",
    secret = function(key, request, response) {
      if (key == "secret123") {
        return("scope1")
      }
      FALSE
    },
    user_info = function(key, setter) {
      setter(
        name_given = "API User"
      )
    },
    cookie = FALSE,
    name = "test2"
  )

  expect_equal(auth$location, "header")
  expect_equal(auth$open_api, list(type = "apiKey", `in` = "header", name = "x-api-key"))

  session <- new.env()
  no_auth <- reqres::Request$new(fiery::fake_request("http://example.com"))

  pass <- auth$check_request(
    request = no_auth,
    response = no_auth$respond(),
    keys = list(),
    .session = session
  )
  expect_false(pass)
  expect_null(session$test2)

  auth$reject_response(no_auth$respond(), .session = session)
  expect_equal(no_auth$response$status, 400L)

  session <- new.env()
  wrong_auth <- reqres::Request$new(fiery::fake_request(
    "http://example.com",
    headers = list(
      `x-api-key` = "wrong_secret"
    )
  ))

  pass <- auth$check_request(
    request = wrong_auth,
    response = wrong_auth$respond(),
    keys = list(),
    .session = session
  )
  expect_false(pass)
  expect_equal(session$test2, list())

  auth$reject_response(wrong_auth$respond(), .session = session)
  expect_equal(wrong_auth$response$status, 403L)
  expect_null(session$test2)

  session <- new.env()
  good_auth <- reqres::Request$new(fiery::fake_request(
    "http://example.com",
    headers = list(
      `x-api-key` = "secret123"
    )
  ))

  pass <- auth$check_request(
    request = good_auth,
    response = good_auth$respond(),
    keys = list(),
    .session = session
  )
  expect_true(pass)
  expect_equal(
    session$test2,
    user_info(id = NULL, provider = "local", name_given = "API User", scopes = "scope1")
  )
  auth$forbid_user(good_auth$respond(), .session = session)
  expect_equal(good_auth$response$status, 403L)
  expect_null(session$test2)
})

test_that("auth_key works with cookie-based authentication", {
  auth <- auth_key(
    key = "api_token",
    secret = "my_secret_token",
    cookie = TRUE,
    name = "cookie_test"
  )

  expect_equal(auth$location, "cookie")
  expect_equal(auth$open_api, list(type = "apiKey", `in` = "cookie", name = "api_token"))

  session <- new.env()
  good_auth <- reqres::Request$new(fiery::fake_request(
    "http://example.com",
    headers = list(
      cookie = "api_token=my_secret_token"
    )
  ))

  pass <- auth$check_request(
    request = good_auth,
    response = good_auth$respond(),
    keys = list(),
    .session = session
  )
  expect_true(pass)
  expect_equal(
    session$cookie_test,
    user_info(provider = "local", scopes = character(0))
  )
})

test_that("auth_key works with simple string secret", {
  auth <- auth_key(
    key = "authorization",
    secret = "simple_secret",
    cookie = FALSE,
    name = "string_test"
  )

  session <- new.env()
  wrong_secret <- reqres::Request$new(fiery::fake_request(
    "http://example.com",
    headers = list(
      authorization = "wrong_secret"
    )
  ))

  pass <- auth$check_request(
    request = wrong_secret,
    response = wrong_secret$respond(),
    keys = list(),
    .session = session
  )
  expect_false(pass)

  session <- new.env()
  correct_secret <- reqres::Request$new(fiery::fake_request(
    "http://example.com",
    headers = list(
      authorization = "simple_secret"
    )
  ))

  pass <- auth$check_request(
    request = correct_secret,
    response = correct_secret$respond(),
    keys = list(),
    .session = session
  )
  expect_true(pass)
})

test_that("auth_key respects existing response status on rejection", {
  auth <- auth_key(
    key = "x-api-key",
    secret = "my_secret",
    cookie = FALSE,
    name = "status_test"
  )

  session <- new.env()
  no_auth <- reqres::Request$new(fiery::fake_request("http://example.com"))
  response <- no_auth$respond()
  response$status <- 500L

  auth$reject_response(response, .session = session)
  # Should not overwrite non-404 status
  expect_equal(response$status, 500L)
})

test_that("auth_key passes if session already has valid user info", {
  auth <- auth_key(
    key = "x-api-key",
    secret = "my_secret",
    cookie = FALSE,
    name = "session_test"
  )

  session <- new.env()
  # Pre-populate session with user info from previous authentication
  session$session_test <- user_info(
    provider = "local",
    id = "user123",
    name_given = "Existing User",
    scopes = "scope1"
  )

  # Request without any authentication header
  no_auth <- reqres::Request$new(fiery::fake_request("http://example.com"))

  pass <- auth$check_request(
    request = no_auth,
    response = no_auth$respond(),
    keys = list(),
    .session = session
  )
  # Should pass because session already has valid info
  expect_true(pass)
  # Session should remain unchanged
  expect_equal(session$session_test$name, c(given = "Existing User"))
})
