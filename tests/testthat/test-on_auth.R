test_that("replay_request replays the original request", {
  # Create a mock server
  app <- fiery::Fire$new()
  app$on("request", function(server, request, ...) {
    response <- request$respond()
    response$status <- 200L
    response$body <- request$headers$user_agent
    response$type <- "text/plain"
    TRUE
  })

  # Create session state from an original request
  session_state <- list(
    state = "random_state_123",
    time = Sys.time(),
    method = "GET",
    url = "http://example.com/api/data?param=value",
    headers = list(
      host = "example.com",
      `user-agent` = "test-agent"
    ),
    body = raw(0),
    from = "http://example.com/previous"
  )

  # Create current request (callback from OAuth provider)
  current_request <- reqres::Request$new(fiery::fake_request(
    "http://example.com/auth/callback?code=auth_code&state=random_state_123"
  ))
  response <- current_request$respond()

  # Call replay_request
  result <- replay_request(current_request, response, session_state, app)

  # Should return FALSE (don't continue processing)
  expect_false(result)

  # Response should have the replayed content
  expect_equal(response$status, 200L)
  expect_equal(response$body, "test-agent")
})

test_that("replay_request handles POST requests with body", {
  # Create a mock server that echoes the body
  app <- fiery::Fire$new()
  app$on("request", function(server, request, ...) {
    response <- request$respond()
    response$status <- 201L
    response$body <- paste("Received:", rawToChar(request$body_raw))
    response$type <- "text/plain"
    TRUE
  })

  # Create session state from a POST request
  post_body <- charToRaw('{"key":"value"}')
  session_state <- list(
    state = "state_456",
    time = Sys.time(),
    method = "POST",
    url = "http://example.com/api/create",
    headers = list(
      host = "example.com",
      `content-type` = "application/json"
    ),
    body = post_body,
    from = "http://example.com/form"
  )

  current_request <- reqres::Request$new(fiery::fake_request(
    "http://example.com/auth/callback?code=auth_code"
  ))
  response <- current_request$respond()

  result <- replay_request(current_request, response, session_state, app)

  expect_false(result)
  expect_equal(response$status, 201L)
  expect_match(response$body, "Received.*key.*value")
})

test_that("replay_request handles query parameters", {
  app <- fiery::Fire$new()
  app$on("request", function(server, request, ...) {
    response <- request$respond()
    response$status <- 200L
    # Echo back the query parameters
    response$body <- jsonlite::toJSON(request$query)
    TRUE
  })

  session_state <- list(
    state = "state_query",
    time = Sys.time(),
    method = "GET",
    url = "http://example.com/search?q=test&page=2",
    headers = list(host = "example.com"),
    body = raw(0),
    from = "http://example.com/"
  )

  current_request <- reqres::Request$new(fiery::fake_request(
    "http://example.com/auth/callback"
  ))
  response <- current_request$respond()

  result <- replay_request(current_request, response, session_state, app)

  expect_false(result)
  expect_equal(jsonlite::fromJSON(response$body)$q, "test")
})

test_that("redirect_back redirects to original location", {
  session_state <- list(
    state = "state_redirect",
    time = Sys.time(),
    method = "GET",
    url = "http://example.com/protected",
    headers = list(host = "example.com"),
    body = raw(0),
    from = "http://example.com/landing-page"
  )

  current_request <- reqres::Request$new(fiery::fake_request(
    "http://example.com/auth/callback"
  ))
  response <- current_request$respond()

  # Mock server (not used by redirect_back but required by signature)
  app <- fiery::Fire$new()

  result <- redirect_back(current_request, response, session_state, app)

  # Should return FALSE
  expect_false(result)

  # Should set 307 redirect status
  expect_equal(response$status, 307L)

  # Should redirect to the 'from' location
  expect_equal(response$get_header("location"), "http://example.com/landing-page")
})

test_that("custom on_auth function can be created", {
  # Example custom on_auth function
  custom_success_page <- function(request, response, session_state, server) {
    response$status <- 200L
    response$body <- "Successfully logged in!"
    response$type <- "text/html"
    FALSE
  }

  session_state <- list(
    state = "state",
    time = Sys.time(),
    method = "GET",
    url = "http://example.com/protected",
    headers = list(host = "example.com"),
    body = raw(0),
    from = "http://example.com/"
  )

  current_request <- reqres::Request$new(fiery::fake_request(
    "http://example.com/auth/callback"
  ))
  response <- current_request$respond()
  app <- fiery::Fire$new()

  result <- custom_success_page(current_request, response, session_state, app)

  expect_false(result)
  expect_equal(response$status, 200L)
  expect_equal(response$body, "Successfully logged in!")
})

test_that("replay_request handles empty headers", {
  app <- fiery::Fire$new()
  app$on("request", function(server, request, ...) {
    response <- request$respond()
    response$status <- 200L
    response$body <- "OK"
    TRUE
  })

  session_state <- list(
    state = "state",
    time = Sys.time(),
    method = "GET",
    url = "http://example.com/api",
    headers = list(),  # Empty headers
    body = raw(0),
    from = "http://example.com/"
  )

  current_request <- reqres::Request$new(fiery::fake_request(
    "http://example.com/auth/callback"
  ))
  response <- current_request$respond()

  result <- replay_request(current_request, response, session_state, app)

  expect_false(result)
  expect_equal(response$status, 200L)
})

test_that("replay_request handles empty body", {
  app <- fiery::Fire$new()
  app$on("request", function(server, request, ...) {
    response <- request$respond()
    response$status <- 200L
    response$body <- "OK"
    TRUE
  })

  session_state <- list(
    state = "state",
    time = Sys.time(),
    method = "GET",
    url = "http://example.com/api",
    headers = list(host = "example.com"),
    body = raw(0),  # Empty body
    from = "http://example.com/"
  )

  current_request <- reqres::Request$new(fiery::fake_request(
    "http://example.com/auth/callback"
  ))
  response <- current_request$respond()

  result <- replay_request(current_request, response, session_state, app)

  expect_false(result)
  expect_equal(response$status, 200L)
})
