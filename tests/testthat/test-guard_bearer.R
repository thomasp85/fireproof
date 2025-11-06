test_that("guard_bearer can be constructed and verify", {
  auth <- guard_bearer(
    validate = function(token, realm, request, response) {
      if (token == "abcd1234") {
        return("scope1")
      }
      FALSE
    },
    user_info = function(token) {
      new_user_info(
        name_given = "Thomas"
      )
    },
    name = "test2"
  )

  expect_equal(auth$open_api, list(type = "http", scheme = "bearer"))

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

  auth$reject_response(no_auth$respond(), scope = NULL, .session = session)
  expect_equal(no_auth$response$status, 401L)
  expect_equal(
    no_auth$response$get_header("www-authenticate"),
    "Bearer realm=\"private\""
  )

  session <- new.env()
  wrong_auth <- reqres::Request$new(fiery::fake_request(
    "http://example.com",
    headers = list(
      authorization = "Basic abcd1234"
    )
  ))

  pass <- auth$check_request(
    request = wrong_auth,
    response = wrong_auth$respond(),
    keys = list(),
    .session = session
  )
  expect_false(pass)
  expect_null(session$test2)

  auth$reject_response(wrong_auth$respond(), scope = NULL, .session = session)
  expect_equal(wrong_auth$response$status, 401L)
  expect_equal(
    wrong_auth$response$get_header("www-authenticate"),
    "Bearer realm=\"private\""
  )

  session <- new.env()
  bad_auth <- reqres::Request$new(fiery::fake_request(
    "http://example.com",
    headers = list(
      authorization = "Bearer wrongtoken"
    )
  ))

  pass <- auth$check_request(
    request = bad_auth,
    response = bad_auth$respond(),
    keys = list(),
    .session = session
  )
  expect_false(pass)
  expect_equal(session$test2, list())

  auth$reject_response(bad_auth$respond(), .session = session)
  expect_equal(bad_auth$response$status, 403L)
  expect_null(session$test2)

  session <- new.env()
  good_auth <- reqres::Request$new(fiery::fake_request(
    "http://example.com",
    headers = list(
      authorization = "Bearer abcd1234"
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
    new_user_info(
      id = NULL,
      provider = "local",
      name_given = "Thomas",
      scopes = "scope1",
      token = list(
        access_token = "abcd1234",
        token_type = "bearer",
        scope = "scope1"
      )
    )
  )
  auth$forbid_user(good_auth$respond(), .session = session)
  expect_equal(good_auth$response$status, 403L)
  expect_null(session$test2)
})

test_that("guard_bearer works with custom realm", {
  auth <- guard_bearer(
    validate = function(token) token == "secret",
    realm = "my-api",
    name = "realm_test"
  )

  session <- new.env()
  no_auth <- reqres::Request$new(fiery::fake_request("http://example.com"))

  pass <- auth$check_request(
    request = no_auth,
    response = no_auth$respond(),
    keys = list(),
    .session = session
  )
  expect_false(pass)

  auth$reject_response(no_auth$respond(), scope = NULL, .session = session)
  expect_equal(no_auth$response$status, 401L)
  expect_equal(
    no_auth$response$get_header("www-authenticate"),
    "Bearer realm=\"my-api\""
  )
})

test_that("guard_bearer includes scope in WWW-Authenticate header", {
  auth <- guard_bearer(
    validate = function(token) token == "secret",
    name = "scope_test"
  )

  session <- new.env()
  no_auth <- reqres::Request$new(fiery::fake_request("http://example.com"))

  pass <- auth$check_request(
    request = no_auth,
    response = no_auth$respond(),
    keys = list(),
    .session = session
  )
  expect_false(pass)

  auth$reject_response(
    no_auth$respond(),
    scope = c("read", "write"),
    .session = session
  )
  expect_equal(no_auth$response$status, 401L)
  expect_equal(
    no_auth$response$get_header("www-authenticate"),
    "Bearer realm=\"private\", scope=\"read write\""
  )
})

test_that("guard_bearer handles body token transmission", {
  auth <- guard_bearer(
    validate = function(token) {
      if (token == "body_token") {
        return("scope1")
      }
      FALSE
    },
    allow_body_token = TRUE,
    name = "body_test"
  )

  session <- new.env()
  body_auth <- reqres::Request$new(fiery::fake_request(
    "http://example.com",
    method = "post",
    headers = list(
      `content-type` = "application/x-www-form-urlencoded"
    ),
    content = "access_token=body_token"
  ))

  pass <- auth$check_request(
    request = body_auth,
    response = body_auth$respond(),
    keys = list(),
    .session = session
  )
  expect_true(pass)
  expect_equal(session$body_test$scopes, "scope1")
})

test_that("guard_bearer rejects body token when disabled", {
  auth <- guard_bearer(
    validate = function(token) token == "body_token",
    allow_body_token = FALSE,
    name = "no_body_test"
  )

  session <- new.env()
  body_auth <- reqres::Request$new(fiery::fake_request(
    "http://example.com",
    method = "post",
    headers = list(
      `content-type` = "application/x-www-form-urlencoded"
    ),
    body = "access_token=body_token"
  ))

  pass <- auth$check_request(
    request = body_auth,
    response = body_auth$respond(),
    keys = list(),
    .session = session
  )
  expect_false(pass)
})

test_that("guard_bearer handles query token transmission when enabled", {
  auth <- guard_bearer(
    validate = function(token) {
      if (token == "query_token") {
        return("scope1")
      }
      FALSE
    },
    allow_query_token = TRUE,
    name = "query_test"
  )

  session <- new.env()
  query_auth <- reqres::Request$new(fiery::fake_request(
    "http://example.com?access_token=query_token",
    headers = list(
      `cache-control` = "no-store"
    )
  ))

  pass <- auth$check_request(
    request = query_auth,
    response = query_auth$respond(),
    keys = list(),
    .session = session
  )
  expect_true(pass)
  expect_equal(query_auth$response$get_header("cache-control"), "private")
})

test_that("guard_bearer rejects query token when disabled", {
  auth <- guard_bearer(
    validate = function(token) token == "query_token",
    allow_query_token = FALSE,
    name = "no_query_test"
  )

  session <- new.env()
  query_auth <- reqres::Request$new(fiery::fake_request(
    "http://example.com?access_token=query_token",
    headers = list(
      `cache-control` = "no-store"
    )
  ))

  pass <- auth$check_request(
    request = query_auth,
    response = query_auth$respond(),
    keys = list(),
    .session = session
  )
  expect_false(pass)
})

test_that("guard_bearer rejects multiple token transmission methods", {
  auth <- guard_bearer(
    validate = function(token) TRUE,
    allow_body_token = TRUE,
    allow_query_token = TRUE,
    name = "multi_test"
  )

  session <- new.env()
  multi_auth <- reqres::Request$new(fiery::fake_request(
    "http://example.com?access_token=query_token",
    method = "post",
    headers = list(
      authorization = "Bearer header_token",
      `content-type` = "application/x-www-form-urlencoded",
      `cache-control` = "no-store"
    ),
    body = "access_token=body_token"
  ))

  expect_error(
    auth$check_request(
      request = multi_auth,
      response = multi_auth$respond(),
      keys = list(),
      .session = session
    ),
    "more than one method"
  )
})

test_that("guard_bearer authenticator can return TRUE for simple validation", {
  auth <- guard_bearer(
    validate = function(token) token == "simple_token",
    name = "simple_test"
  )

  session <- new.env()
  good_auth <- reqres::Request$new(fiery::fake_request(
    "http://example.com",
    headers = list(
      authorization = "Bearer simple_token"
    )
  ))

  pass <- auth$check_request(
    request = good_auth,
    response = good_auth$respond(),
    keys = list(),
    .session = session
  )
  expect_true(pass)
  expect_equal(session$simple_test$scopes, character(0))
})

test_that("guard_bearer respects existing response status on rejection", {
  auth <- guard_bearer(
    validate = function(token) token == "secret",
    name = "status_test"
  )

  session <- new.env()
  no_auth <- reqres::Request$new(fiery::fake_request("http://example.com"))
  response <- no_auth$respond()
  response$status <- 500L

  auth$reject_response(response, .session = session)
  # Should not overwrite non-404/400 status
  expect_equal(response$status, 500L)
})

test_that("guard_bearer passes if session already has valid user info", {
  auth <- guard_bearer(
    validate = function(token) token == "secret",
    name = "session_test"
  )

  session <- new.env()
  # Pre-populate session with user info from previous authentication
  session$session_test <- new_user_info(
    provider = "local",
    id = "user456",
    name_given = "Bearer User",
    scopes = c("read", "write"),
    token = list(
      access_token = "previous_token",
      token_type = "bearer",
      scope = "read write"
    )
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
  expect_equal(session$session_test$name, c(given = "Bearer User"))
  expect_equal(session$session_test$token$access_token, "previous_token")
})
