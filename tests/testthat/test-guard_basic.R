test_that("guard_basic can be constructed and verify", {
  auth <- guard_basic(
    validate = function(username, password) {
      if (username == "thomas" && password == "pedersen") {
        return("scope1")
      }
      FALSE
    },
    user_info = function(user) {
      new_user_info(
        name_given = "Thomas"
      )
    },
    name = "test2"
  )

  expect_equal(auth$open_api, list(type = "http", scheme = "basic"))

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
  expect_equal(no_auth$response$status, 401L)
  expect_equal(
    no_auth$response$get_header("www-authenticate"),
    "Basic realm=\"private\", charset=UTF-8"
  )

  session <- new.env()
  wrong_auth <- reqres::Request$new(fiery::fake_request(
    "http://example.com",
    headers = list(
      authorization = "Bearer abcd1234"
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

  auth$reject_response(wrong_auth$respond(), .session = session)
  expect_equal(wrong_auth$response$status, 401L)
  expect_equal(
    wrong_auth$response$get_header("www-authenticate"),
    "Basic realm=\"private\", charset=UTF-8"
  )

  session <- new.env()
  bad_auth <- reqres::Request$new(fiery::fake_request(
    "http://example.com",
    headers = list(
      authorization = paste0(
        "Basic ",
        base64enc::base64encode(charToRaw("hadley:ggplot"))
      )
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
      authorization = paste0(
        "Basic ",
        base64enc::base64encode(charToRaw("thomas:pedersen"))
      )
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
      provider = "local",
      id = "thomas",
      name_given = "Thomas",
      scopes = "scope1"
    )
  )
  auth$forbid_user(good_auth$respond(), .session = session)
  expect_equal(good_auth$response$status, 403L)
  expect_null(session$test2)
})

test_that("guard_basic passes if session already has valid user info", {
  auth <- guard_basic(
    validate = function(username, password) {
      if (username == "thomas" && password == "pedersen") {
        return("scope1")
      }
      FALSE
    },
    name = "session_test"
  )

  session <- new.env()
  # Pre-populate session with user info from previous authentication
  session$session_test <- new_user_info(
    provider = "local",
    id = "thomas",
    name_given = "Thomas",
    name_family = "Pedersen",
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
  expect_equal(session$session_test$id, "thomas")
  expect_equal(
    session$session_test$name,
    c(given = "Thomas", family = "Pedersen")
  )
})
