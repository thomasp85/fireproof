test_that("Guard can be constructed", {
  auth <- Guard$new()
  expect_s3_class(auth, "Guard")
  expect_s3_class(auth, "R6")
  expect_null(auth$name)

  auth_named <- Guard$new(name = "my_auth")
  expect_equal(auth_named$name, "my_auth")
})

test_that("Guard name can be get and set", {
  auth <- Guard$new(name = "initial")
  expect_equal(auth$name, "initial")

  auth$name <- "updated"
  expect_equal(auth$name, "updated")

  auth$name <- "final_name"
  expect_equal(auth$name, "final_name")
})

test_that("Guard name must be a string", {
  auth <- Guard$new()
  expect_error(auth$name <- 123, "string")
  expect_error(auth$name <- c("a", "b"), "string")
  expect_error(Guard$new(name = TRUE), "string")
})

test_that("Guard check_request returns TRUE by default", {
  auth <- Guard$new(name = "test")
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

test_that("Guard reject_response clears session and sets 400 status", {
  auth <- Guard$new(name = "test")
  session <- new.env()
  session$test <- list(user = "data")

  request <- reqres::Request$new(fiery::fake_request("http://example.com"))
  response <- request$respond()

  auth$reject_response(response, scope = NULL, .session = session)
  expect_equal(response$status, 400L)
  expect_null(session$test)
})

test_that("Guard forbid_user clears session and sets 403 status", {
  auth <- Guard$new(name = "test")
  session <- new.env()
  session$test <- list(user = "authenticated")

  request <- reqres::Request$new(fiery::fake_request("http://example.com"))
  response <- request$respond()

  auth$forbid_user(response, scope = NULL, .session = session)
  expect_equal(response$status, 403L)
  expect_null(session$test)
})

test_that("Guard register_handler does nothing by default", {
  auth <- Guard$new(name = "test")
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

test_that("Guard open_api returns empty list by default", {
  auth <- Guard$new(name = "test")
  expect_equal(auth$open_api, list())
})

test_that("is_auth identifies Guard objects", {
  auth <- Guard$new()
  expect_true(is_guard(auth))

  expect_false(is_guard("not an auth"))
  expect_false(is_guard(123))
  expect_false(is_guard(NULL))
  expect_false(is_guard(list()))
})

test_that("is_guard identifies Guard subclasses", {
  basic <- guard_basic(
    validate = function(username, password) TRUE,
    name = "basic_test"
  )
  expect_true(is_guard(basic))

  key <- guard_key(
    key_name = "api-key",
    validate = "secret",
    name = "key_test"
  )
  expect_true(is_guard(key))
})

test_that("Guard methods accept additional arguments via ...", {
  auth <- Guard$new(name = "test")
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

test_that("Guard clears only its own session data", {
  auth <- Guard$new(name = "test_auth")
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
