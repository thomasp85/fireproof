test_that("auth_oauth2 can be constructed with authorization_code grant", {
  auth <- auth_oauth2(
    token_url = "https://example.com/oauth/token",
    redirect_url = "https://myapp.com/auth/callback",
    client_id = "my_client_id",
    client_secret = "my_client_secret",
    auth_url = "https://example.com/oauth/authorize",
    grant_type = "authorization_code",
    scopes = c("read", "write"),
    user_info = function(token_info, setter) {
      setter(
        provider = "example",
        name_given = "Test User"
      )
    },
    name = "test"
  )

  expect_equal(
    auth$open_api,
    list(
      type = "oauth2",
      flows = list(
        authorizationCode = list(
          authorizationUrl = "https://example.com/oauth/authorize",
          tokenUrl = "https://example.com/oauth/token",
          refreshUrl = "https://example.com/oauth/token",
          scopes = c(read = "", write = "")
        )
      )
    )
  )
})

test_that("auth_oauth2 can be constructed with password grant", {
  auth <- auth_oauth2(
    token_url = "https://example.com/oauth/token",
    redirect_url = "https://myapp.com/auth/callback",
    client_id = "my_client_id",
    client_secret = "my_client_secret",
    grant_type = "password",
    scopes = c("read"),
    name = "password_test"
  )

  expect_equal(
    auth$open_api,
    list(
      type = "oauth2",
      flows = list(
        password = list(
          tokenUrl = "https://example.com/oauth/token",
          refreshUrl = "https://example.com/oauth/token",
          scopes = c(read = "")
        )
      )
    )
  )
})

test_that("auth_oauth2 check_request validates session info", {
  auth <- auth_oauth2(
    token_url = "https://example.com/oauth/token",
    redirect_url = "https://myapp.com/auth/callback",
    client_id = "my_client_id",
    client_secret = "my_client_secret",
    auth_url = "https://example.com/oauth/authorize",
    grant_type = "authorization_code",
    name = "test"
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
  expect_null(session$test)

  # Simulate authenticated session
  session$test <- user_info(
    provider = "example",
    id = "user123",
    scopes = c("read")
  )

  pass <- auth$check_request(
    request = no_auth,
    response = no_auth$respond(),
    keys = list(),
    .session = session
  )
  expect_true(pass)
})

test_that("auth_oauth2 check_request uses custom validate function", {
  auth <- auth_oauth2(
    token_url = "https://example.com/oauth/token",
    redirect_url = "https://myapp.com/auth/callback",
    client_id = "my_client_id",
    client_secret = "my_client_secret",
    auth_url = "https://example.com/oauth/authorize",
    grant_type = "authorization_code",
    validate = function(info) {
      "admin" %in% info$scopes
    },
    name = "validate_test"
  )

  session <- new.env()
  no_auth <- reqres::Request$new(fiery::fake_request("http://example.com"))

  # User without admin scope
  session$validate_test <- user_info(
    provider = "example",
    id = "user123",
    scopes = c("read", "write")
  )

  pass <- auth$check_request(
    request = no_auth,
    response = no_auth$respond(),
    keys = list(),
    .session = session
  )
  expect_false(pass)

  # User with admin scope
  session$validate_test <- user_info(
    provider = "example",
    id = "admin123",
    scopes = c("read", "write", "admin")
  )

  pass <- auth$check_request(
    request = no_auth,
    response = no_auth$respond(),
    keys = list(),
    .session = session
  )
  expect_true(pass)
})

test_that("auth_oauth2 reject_response clears failed session", {
  auth <- auth_oauth2(
    token_url = "https://example.com/oauth/token",
    redirect_url = "https://myapp.com/auth/callback",
    client_id = "my_client_id",
    client_secret = "my_client_secret",
    auth_url = "https://example.com/oauth/authorize",
    grant_type = "authorization_code",
    name = "test"
  )

  session <- new.env()
  session$test <- user_info(provider = "example", id = "user123")

  no_auth <- reqres::Request$new(fiery::fake_request("http://example.com"))

  auth$reject_response(no_auth$respond(), scope = NULL, .session = session)
  expect_equal(no_auth$response$status, 403L)
  expect_null(session$test)
})

test_that("auth_oauth2 reject_response initiates authorization for authorization_code", {
  auth <- auth_oauth2(
    token_url = "https://example.com/oauth/token",
    redirect_url = "https://myapp.com/auth/callback",
    client_id = "my_client_id",
    client_secret = "my_client_secret",
    auth_url = "https://example.com/oauth/authorize",
    grant_type = "authorization_code",
    scopes = c("read", "write"),
    name = "test"
  )

  session <- new.env()
  no_auth <- reqres::Request$new(fiery::fake_request(
    "http://example.com/api/data"
  ))

  auth$reject_response(no_auth$respond(), scope = NULL, .session = session)
  expect_equal(no_auth$response$status, 303L)
  location <- no_auth$response$get_header("location")
  expect_true(grepl("^https://example.com/oauth/authorize", location))
  expect_true(grepl("client_id=my_client_id", location))
  expect_true(grepl(
    paste0("state=", session$oauth_state$state),
    location,
    fixed = TRUE
  ))
  expect_true(grepl("redirect_uri=", location))
  expect_true(grepl("code_challenge=", location))
  expect_true(grepl("code_challenge_method=S256", location))
})

test_that("auth_oauth2 custom redirect_path can be set", {
  auth <- auth_oauth2(
    token_url = "https://example.com/oauth/token",
    redirect_url = "https://myapp.com/auth/callback",
    client_id = "my_client_id",
    client_secret = "my_client_secret",
    auth_url = "https://example.com/oauth/authorize",
    grant_type = "authorization_code",
    redirect_path = "/custom/oauth/path",
    name = "test"
  )

  expect_equal("/custom/oauth/path", auth$.__enclos_env__$private$REDIRECT_PATH)
})

test_that("auth_oauth2 service_params are included in auth URL", {
  auth <- auth_oauth2(
    token_url = "https://example.com/oauth/token",
    redirect_url = "https://myapp.com/auth/callback",
    client_id = "my_client_id",
    client_secret = "my_client_secret",
    auth_url = "https://example.com/oauth/authorize",
    grant_type = "authorization_code",
    service_params = list(
      prompt = "consent",
      access_type = "offline"
    ),
    name = "test"
  )

  session <- new.env()
  no_auth <- reqres::Request$new(fiery::fake_request("http://example.com"))

  auth$reject_response(no_auth$respond(), scope = NULL, .session = session)
  location <- no_auth$response$get_header("location")
  expect_true(grepl("prompt=consent", location))
  expect_true(grepl("access_type=offline", location))
})

test_that("auth_oauth2 requires auth_url for authorization_code grant", {
  expect_error(
    auth_oauth2(
      token_url = "https://example.com/oauth/token",
      redirect_url = "https://myapp.com/auth/callback",
      client_id = "my_client_id",
      client_secret = "my_client_secret",
      grant_type = "authorization_code",
      name = "test"
    ),
    "auth_url"
  )
})

test_that("auth_oauth2 does not require auth_url for password grant", {
  expect_no_error(
    auth_oauth2(
      token_url = "https://example.com/oauth/token",
      redirect_url = "https://myapp.com/auth/callback",
      client_id = "my_client_id",
      client_secret = "my_client_secret",
      grant_type = "password",
      name = "test"
    )
  )
})

test_that("auth_oauth2 reject_response for password grant requests basic auth", {
  auth <- auth_oauth2(
    token_url = "https://example.com/oauth/token",
    redirect_url = "https://myapp.com/auth/callback",
    client_id = "my_client_id",
    client_secret = "my_client_secret",
    grant_type = "password",
    name = "test"
  )

  session <- new.env()
  no_auth <- reqres::Request$new(fiery::fake_request("http://example.com"))

  expect_snapshot(
    auth$reject_response(no_auth$respond(), scope = NULL, .session = session),
    error = TRUE
  )
})

test_that("auth_oauth2 respects existing response status on rejection", {
  auth <- auth_oauth2(
    token_url = "https://example.com/oauth/token",
    redirect_url = "https://myapp.com/auth/callback",
    client_id = "my_client_id",
    client_secret = "my_client_secret",
    auth_url = "https://example.com/oauth/authorize",
    grant_type = "authorization_code",
    name = "test"
  )

  session <- new.env()
  session$test <- user_info(provider = "example")

  no_auth <- reqres::Request$new(fiery::fake_request("http://example.com"))
  response <- no_auth$respond()
  response$status <- 500L

  auth$reject_response(response, scope = NULL, .session = session)
  # Should still process rejection even with non-default status
  expect_null(session$test)
})

test_that("auth_oauth2 register_handler adds redirect endpoint", {
  auth <- auth_oauth2(
    token_url = "https://example.com/oauth/token",
    redirect_url = "https://myapp.com/auth/callback",
    client_id = "my_client_id",
    client_secret = "my_client_secret",
    auth_url = "https://example.com/oauth/authorize",
    grant_type = "authorization_code",
    redirect_path = "/auth/callback",
    name = "test"
  )

  handlers_added <- list()
  mock_add_handler <- function(method, path, handler) {
    handlers_added[[length(handlers_added) + 1]] <<- list(
      method = method,
      path = path,
      handler = handler
    )
  }

  auth$register_handler(mock_add_handler)

  expect_equal(length(handlers_added), 1)
  expect_equal(handlers_added[[1]]$method, "get")
  expect_equal(handlers_added[[1]]$path, "/auth/callback")
  expect_type(handlers_added[[1]]$handler, "closure")
})

test_that("auth_oauth2 with NULL scopes works", {
  auth <- auth_oauth2(
    token_url = "https://example.com/oauth/token",
    redirect_url = "https://myapp.com/auth/callback",
    client_id = "my_client_id",
    client_secret = "my_client_secret",
    auth_url = "https://example.com/oauth/authorize",
    grant_type = "authorization_code",
    scopes = NULL,
    name = "test"
  )

  expect_equal(
    auth$open_api$flows$authorizationCode$scopes,
    structure(character(0), names = character(0))
  )
})

test_that("auth_oauth2 forbid_user clears session", {
  auth <- auth_oauth2(
    token_url = "https://example.com/oauth/token",
    redirect_url = "https://myapp.com/auth/callback",
    client_id = "my_client_id",
    client_secret = "my_client_secret",
    auth_url = "https://example.com/oauth/authorize",
    grant_type = "authorization_code",
    name = "test"
  )

  session <- new.env()
  session$test <- user_info(
    provider = "example",
    id = "user123",
    scopes = c("read")
  )

  good_auth <- reqres::Request$new(fiery::fake_request("http://example.com"))
  auth$forbid_user(good_auth$respond(), .session = session)
  expect_equal(good_auth$response$status, 403L)
  expect_null(session$test)
})

test_that("auth_oauth2 passes if session already has valid user info", {
  auth <- auth_oauth2(
    token_url = "https://example.com/oauth/token",
    redirect_url = "https://myapp.com/auth/callback",
    client_id = "my_client_id",
    client_secret = "my_client_secret",
    auth_url = "https://example.com/oauth/authorize",
    grant_type = "authorization_code",
    name = "session_test"
  )

  session <- new.env()
  # Pre-populate session with user info from previous OAuth authentication
  session$session_test <- user_info(
    provider = "github",
    id = "oauth_user789",
    name_given = "OAuth",
    name_family = "User",
    scopes = c("read:user", "repo"),
    token = list(
      access_token = "oauth_access_token_xyz",
      token_type = "bearer",
      expires_in = 3600,
      refresh_token = "refresh_token_abc",
      timestamp = Sys.time()
    )
  )

  # Request without any authentication (OAuth already happened)
  no_auth <- reqres::Request$new(fiery::fake_request("http://example.com"))

  pass <- auth$check_request(
    request = no_auth,
    response = no_auth$respond(),
    keys = list(),
    .session = session
  )
  # Should pass because session already has valid OAuth info
  expect_true(pass)
  # Session should remain unchanged
  expect_equal(session$session_test$provider, "github")
  expect_equal(
    session$session_test$token$access_token,
    "oauth_access_token_xyz"
  )
})

# Tests yet to be implemented

test_that("auth_oauth2 handles successful code exchange", {
  # Mock the callback with code and state
  # Verify token exchange happens
  # Verify session is populated with token info
})

test_that("auth_oauth2 validates state parameter", {
  # Test mismatched state rejection
  # Test expired state rejection
})

test_that("auth_oauth2 refresh_token updates expired tokens", {
  # Test automatic refresh when expired
  # Test refresh token is used correctly
})

test_that("auth_oauth2 handles OAuth error responses", {
  # Test access_denied, invalid_scope, etc.
})
