test_that("Auth can be constructed", {
  auth <- Auth$new()
  expect_s3_class(auth, "Auth")
  expect_s3_class(auth, "R6")
  expect_null(auth$name)

  auth_named <- Auth$new(name = "my_auth")
  expect_equal(auth_named$name, "my_auth")
})

test_that("Auth name can be get and set", {
  auth <- Auth$new(name = "initial")
  expect_equal(auth$name, "initial")

  auth$name <- "updated"
  expect_equal(auth$name, "updated")

  auth$name <- "final_name"
  expect_equal(auth$name, "final_name")
})

test_that("Auth name must be a string", {
  auth <- Auth$new()
  expect_error(auth$name <- 123, "string")
  expect_error(auth$name <- c("a", "b"), "string")
  expect_error(Auth$new(name = TRUE), "string")
})

test_that("Auth check_request returns TRUE by default", {
  auth <- Auth$new(name = "test")
  session <- new.env()
  request <- reqres::Request$new(fiery::fake_request("http://example.com"))

  pass <- auth$check_request(
    request = request,
    response = request$respond(),
    keys = list(),
    .session = session
  )
  expect_true(pass)
})

test_that("Auth reject_response clears session and sets 400 status", {
  auth <- Auth$new(name = "test")
  session <- new.env()
  session$test <- list(user = "data")

  request <- reqres::Request$new(fiery::fake_request("http://example.com"))
  response <- request$respond()

  auth$reject_response(response, scope = NULL, .session = session)
  expect_equal(response$status, 400L)
  expect_null(session$test)
})

test_that("Auth forbid_user clears session and sets 403 status", {
  auth <- Auth$new(name = "test")
  session <- new.env()
  session$test <- list(user = "authenticated")

  request <- reqres::Request$new(fiery::fake_request("http://example.com"))
  response <- request$respond()

  auth$forbid_user(response, scope = NULL, .session = session)
  expect_equal(response$status, 403L)
  expect_null(session$test)
})

test_that("Auth register_handler does nothing by default", {
  auth <- Auth$new(name = "test")
  handlers_added <- list()
  mock_add_handler <- function(method, path, handler) {
    handlers_added[[length(handlers_added) + 1]] <<- list(
      method = method,
      path = path,
      handler = handler
    )
  }

  result <- auth$register_handler(mock_add_handler)
  expect_null(result)
  expect_equal(length(handlers_added), 0)
})

test_that("Auth open_api returns empty list by default", {
  auth <- Auth$new(name = "test")
  expect_equal(auth$open_api, list())
})

test_that("is_auth identifies Auth objects", {
  auth <- Auth$new()
  expect_true(is_auth(auth))

  expect_false(is_auth("not an auth"))
  expect_false(is_auth(123))
  expect_false(is_auth(NULL))
  expect_false(is_auth(list()))
})

test_that("is_auth identifies Auth subclasses", {
  basic <- auth_basic(
    authenticator = function(username, password) TRUE,
    name = "basic_test"
  )
  expect_true(is_auth(basic))

  key <- auth_key(
    key = "api-key",
    secret = "secret",
    name = "key_test"
  )
  expect_true(is_auth(key))
})

test_that("Auth methods accept additional arguments via ...", {
  auth <- Auth$new(name = "test")
  session <- new.env()
  request <- reqres::Request$new(fiery::fake_request("http://example.com"))

  # check_request should accept extra args
  expect_no_error(
    auth$check_request(
      request = request,
      response = request$respond(),
      keys = list(),
      extra_arg = "value",
      another = 123,
      .session = session
    )
  )

  # reject_response should accept extra args
  expect_no_error(
    auth$reject_response(
      request$respond(),
      scope = NULL,
      extra_arg = "value",
      .session = session
    )
  )

  # forbid_user should accept extra args
  expect_no_error(
    auth$forbid_user(
      request$respond(),
      scope = NULL,
      extra_arg = "value",
      .session = session
    )
  )
})

test_that("Auth clears only its own session data", {
  auth <- Auth$new(name = "test_auth")
  session <- new.env()
  session$test_auth <- list(user = "data")
  session$other_auth <- list(user = "other_data")
  session$app_data <- "should_remain"

  request <- reqres::Request$new(fiery::fake_request("http://example.com"))

  auth$reject_response(request$respond(), scope = NULL, .session = session)

  expect_null(session$test_auth)
  expect_equal(session$other_auth, list(user = "other_data"))
  expect_equal(session$app_data, "should_remain")
})
