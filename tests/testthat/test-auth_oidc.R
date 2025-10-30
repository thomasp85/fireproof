test_that("auth_oidc gets constructed correctly", {
  auth <- auth_oidc(
    service_url = "https://accounts.google.com",
    redirect_url = "https://myapp.com/auth/callback",
    client_id = "my_client_id",
    client_secret = "my_client_secret",
    scopes = c("profile", "email"),
    name = "oidc_test"
  )

  # openid scope always gets added
  expect_equal(
    auth$.__enclos_env__$private$SCOPES,
    c("openid", "profile", "email")
  )

  auth <- auth_oidc(
    service_url = "https://accounts.google.com",
    redirect_url = "https://myapp.com/auth/callback",
    client_id = "my_client_id",
    client_secret = "my_client_secret",
    scopes = c("profile", "email", "openid"),
    name = "oidc_test"
  )

  expect_equal(
    auth$.__enclos_env__$private$SCOPES,
    c("openid", "profile", "email")
  )

  # Should normalize multiple slashes
  expect_false(grepl("//\\.well-known", auth$open_api$openIdConnectUrl))
  expect_true(grepl(
    "/.well-known/openid-configuration$",
    auth$open_api$openIdConnectUrl
  ))
})

test_that("auth_oidc constructs correct OpenAPI definition", {
  auth <- auth_oidc(
    service_url = "https://accounts.google.com",
    redirect_url = "https://myapp.com/auth/callback",
    client_id = "my_client_id",
    client_secret = "my_client_secret",
    scopes = c("profile", "email"),
    name = "oidc_test"
  )

  # OpenID scope should be automatically added
  open_api <- auth$open_api
  expect_equal(open_api$type, "openIdConnect")
  expect_equal(
    open_api$openIdConnectUrl,
    "https://accounts.google.com/.well-known/openid-configuration"
  )
})

test_that("auth_oidc inherits session-based authentication from OAuth2", {
  auth <- auth_oidc(
    service_url = "https://accounts.example.com",
    redirect_url = "https://myapp.com/auth/callback",
    client_id = "my_client_id",
    client_secret = "my_client_secret",
    name = "session_test"
  )

  session <- new.env()
  request <- reqres::Request$new(fiery::fake_request("http://example.com"))

  # No session - should fail
  pass <- auth$check_request(
    request = request,
    response = request$respond(),
    keys = list(),
    .session = session
  )
  expect_false(pass)

  # With valid session - should pass
  session$session_test <- user_info(
    provider = "example",
    id = "sub_123",
    name_display = "John Doe",
    scopes = c("openid", "profile", "email")
  )

  pass <- auth$check_request(
    request = request,
    response = request$respond(),
    keys = list(),
    .session = session
  )
  expect_true(pass)
})

test_that("auth_oidc validates with custom validate function", {
  auth <- auth_oidc(
    service_url = "https://accounts.example.com",
    redirect_url = "https://myapp.com/auth/callback",
    client_id = "my_client_id",
    client_secret = "my_client_secret",
    validate = function(info) {
      info$provider == "trusted_provider"
    },
    name = "validate_test"
  )

  session <- new.env()
  request <- reqres::Request$new(fiery::fake_request("http://example.com"))

  # Wrong provider
  session$validate_test <- user_info(
    provider = "untrusted",
    id = "sub_123"
  )

  pass <- auth$check_request(
    request = request,
    response = request$respond(),
    keys = list(),
    .session = session
  )
  expect_false(pass)

  # Correct provider
  session$validate_test <- user_info(
    provider = "trusted_provider",
    id = "sub_123"
  )

  pass <- auth$check_request(
    request = request,
    response = request$respond(),
    keys = list(),
    .session = session
  )
  expect_true(pass)
})

test_that("auth_oidc well-known URL handles multiple slashes correctly", {
  test_cases <- list(
    list(
      input = "https://example.com",
      expected = "https://example.com/.well-known/openid-configuration"
    ),
    list(
      input = "https://example.com/",
      expected = "https://example.com/.well-known/openid-configuration"
    ),
    list(
      input = "https://example.com//",
      expected = "https://example.com/.well-known/openid-configuration"
    ),
    list(
      input = "https://example.com/path",
      expected = "https://example.com/path/.well-known/openid-configuration"
    ),
    list(
      input = "https://example.com/path/",
      expected = "https://example.com/path/.well-known/openid-configuration"
    )
  )

  for (test_case in test_cases) {
    auth <- auth_oidc(
      service_url = test_case$input,
      redirect_url = "https://myapp.com/auth/callback",
      client_id = "my_client_id",
      client_secret = "my_client_secret",
      name = "url_test"
    )

    expect_equal(auth$open_api$openIdConnectUrl, test_case$expected)
  }
})
