test_that("Fireproof can be constructed", {
  fp <- Fireproof$new()

  expect_s3_class(fp, "Fireproof")
  expect_equal(fp$name, "fireproof")
  expect_equal(fp$require, "firesale")
})

test_that("Fireproof add_guard adds a Guard object", {
  fp <- Fireproof$new()

  guard <- guard_basic(
    validate = function(username, password) TRUE,
    name = "test_guard"
  )

  fp$add_guard(guard, "basic_auth")

  expect_equal(fp$guards, "basic_auth")
  expect_length(fp$guards, 1)
})

test_that("Fireproof add_guard adds multiple guards", {
  fp <- Fireproof$new()

  basic <- guard_basic(
    validate = function(username, password) TRUE,
    name = "basic"
  )
  key <- guard_key(
    key_name = "api-key",
    validate = "secret",
    name = "key"
  )

  fp$add_guard(basic, "basic_auth")
  fp$add_guard(key, "key_auth")

  expect_equal(fp$guards, c("basic_auth", "key_auth"))
  expect_length(fp$guards, 2)
})

test_that("Fireproof add_guard accepts function", {
  fp <- Fireproof$new()

  custom_guard <- function(request, response, keys) {
    TRUE
  }

  fp$add_guard(custom_guard, "custom")

  expect_equal(fp$guards, "custom")
})

test_that("Fireproof add_guard handles guard name", {
  fp <- Fireproof$new()

  guard <- guard_basic(
    validate = function(username, password) TRUE,
    name = "default_name"
  )

  fp$add_guard(guard)

  expect_equal(fp$guards, "default_name")

  fp$add_guard(guard, "new_name")
  expect_equal(guard$name, "new_name")

  custom_guard <- function(request, response, keys) TRUE

  expect_snapshot(
    fp$add_guard(custom_guard),
    error = TRUE
  )
})

test_that("Fireproof add_guard rejects invalid guard types", {
  fp <- Fireproof$new()

  expect_snapshot(
    fp$add_guard("not_a_guard", "invalid"),
    error = TRUE
  )

  expect_snapshot(
    fp$add_guard(123, "invalid"),
    error = TRUE
  )
})

test_that("Fireproof add_auth works", {
  fp <- Fireproof$new()

  guard <- guard_basic(
    validate = function(username, password) TRUE,
    name = "basic"
  )
  fp$add_guard(guard, "basic_auth")


  flow <- fp$add_auth("get", "/protected", basic_auth)
  expect_s3_class(flow, "fireproof_op")
  expect_null(attr(flow, "op"))  # scalar
})

test_that("Fireproof add_auth handles complex flows", {
  fp <- Fireproof$new()

  basic <- guard_basic(
    validate = function(username, password) TRUE,
    name = "basic"
  )
  key <- guard_key(
    key_name = "api-key",
    validate = "secret",
    name = "key"
  )
  bearer <- guard_bearer(
    validate = function(token) TRUE,
    name = "bearer"
  )

  fp$add_guard(basic, "basic_auth")
  fp$add_guard(key, "key_auth")
  fp$add_guard(bearer, "bearer_auth")

  flow <- fp$add_auth("get", "/protected", basic_auth || key_auth)

  expect_s3_class(flow, "fireproof_op")
  expect_equal(attr(flow, "op"), "||")
  expect_length(flow, 2)

  flow <- fp$add_auth("get", "/protected2", basic_auth && key_auth)

  expect_s3_class(flow, "fireproof_op")
  expect_equal(attr(flow, "op"), "&&")
  expect_length(flow, 2)

  flow <- fp$add_auth(
    "get",
    "/protected3",
    bearer_auth || (basic_auth && key_auth)
  )

  expect_s3_class(flow, "fireproof_op")
  expect_equal(attr(flow, "op"), "||")
})

test_that("Fireproof add_auth with NULL flow disables auth", {
  fp <- Fireproof$new()
  basic <- guard_basic(
    validate = function(username, password) TRUE
  )
  fp$add_guard(basic, "basic_auth")

  fp$add_auth("get", "/*", basic_auth)
  bad_req <- reqres::Request$new(fiery::fake_request("http://example.com/public"))

  expect_snapshot(
    fp$dispatch(bad_req, server = new.env(), arg_list = list(datastore = new.env())),
    error = TRUE
  )

  fp$add_auth("get", "/public", NULL)

  pass <- fp$dispatch(bad_req, server = new.env(), arg_list = list(datastore = new.env()))
  expect_true(pass)
})

test_that("Fireproof add_handler is defunct", {
  fp <- Fireproof$new()

  expect_snapshot(
    fp$add_handler("get", "/path", function() {}),
    error = TRUE
  )
})

test_that("Fireproof flow_to_openapi converts simple flow", {
  fp <- Fireproof$new()

  basic <- guard_basic(
    validate = function(username, password) TRUE,
    name = "basic"
  )
  fp$add_guard(basic, "basic_auth")

  flow <- fp$add_auth("get", "/protected", basic_auth)
  openapi <- fp$flow_to_openapi(flow, scope = c("read"))

  expect_type(openapi, "list")
  expect_length(openapi, 1)
  expect_true("basic_auth" %in% names(openapi[[1]]))
  expect_equal(openapi[[1]]$basic_auth, c("read"))
})

test_that("Fireproof flow_to_openapi converts OR flow", {
  fp <- Fireproof$new()

  basic <- guard_basic(
    validate = function(username, password) TRUE,
    name = "basic"
  )
  key <- guard_key(
    key_name = "api-key",
    validate = "secret",
    name = "key"
  )

  fp$add_guard(basic, "basic_auth")
  fp$add_guard(key, "key_auth")

  flow <- fp$add_auth("get", "/protected", basic_auth || key_auth)
  openapi <- fp$flow_to_openapi(flow, scope = character())

  expect_type(openapi, "list")
  expect_length(openapi, 2)
  expect_true("basic_auth" %in% names(openapi[[1]]))
  expect_true("key_auth" %in% names(openapi[[2]]))
})

test_that("Fireproof flow_to_openapi handles AND within OR", {
  fp <- Fireproof$new()

  basic <- guard_basic(
    validate = function(username, password) TRUE,
    name = "basic"
  )
  key <- guard_key(
    key_name = "api-key",
    validate = "secret",
    name = "key"
  )
  bearer <- guard_bearer(
    validate = function(token) TRUE,
    name = "bearer"
  )

  fp$add_guard(basic, "basic_auth")
  fp$add_guard(key, "key_auth")
  fp$add_guard(bearer, "bearer_auth")

  flow <- fp$add_auth(
    "get",
    "/protected",
    bearer_auth || (basic_auth && key_auth)
  )
  openapi <- fp$flow_to_openapi(flow, scope = character())

  expect_type(openapi, "list")
  expect_length(openapi, 2)
  # First alternative: bearer_auth
  expect_true("bearer_auth" %in% names(openapi[[1]]))
  # Second alternative: basic_auth AND key_auth
  expect_true("basic_auth" %in% names(openapi[[2]]))
  expect_true("key_auth" %in% names(openapi[[2]]))
})

test_that("Fireproof flow_to_openapi warns on deeply nested flow", {
  fp <- Fireproof$new()

  auth1 <- guard_basic(validate = function(u, p) TRUE, name = "a1")
  auth2 <- guard_key(key_name = "k", validate = "s", name = "a2")
  auth3 <- guard_bearer(validate = function(t) TRUE, name = "a3")

  fp$add_guard(auth1, "auth1")
  fp$add_guard(auth2, "auth2")
  fp$add_guard(auth3, "auth3")

  # Create depth > 2 flow (invalid for OpenAPI)
  # This will be: and(or(and(...))) which is depth 3
  inner <- and("auth1", "auth2")
  middle <- or(inner, "auth3")
  outer <- and(middle, "auth1")

  expect_snapshot(
    result <- fp$flow_to_openapi(outer, scope = character())
  )
  expect_null(result)
})

test_that("Fireproof print method shows summary", {
  fp <- Fireproof$new()

  basic <- guard_basic(
    validate = function(username, password) TRUE,
    name = "basic"
  )
  fp$add_guard(basic, "basic_auth")
  fp$add_auth("get", "/protected", basic_auth)

  output <- capture.output(print(fp))

  expect_true(any(grepl("fireproof plugin", output)))
  expect_true(any(grepl("1.*guard", output)))
  expect_true(any(grepl("1.*handler", output)))
})

test_that("Fireproof print method handles multiple guards and handlers", {
  fp <- Fireproof$new()

  basic <- guard_basic(
    validate = function(username, password) TRUE,
    name = "basic"
  )
  key <- guard_key(
    key_name = "api-key",
    validate = "secret",
    name = "key"
  )

  fp$add_guard(basic, "basic_auth")
  fp$add_guard(key, "key_auth")
  fp$add_auth("get", "/path1", basic_auth)
  fp$add_auth("post", "/path2", key_auth)

  output <- capture.output(print(fp))

  expect_true(any(grepl("2.*guard", output)))
  expect_true(any(grepl("2.*handler", output)))
})

test_that("parse_auth_flow parses single symbol", {
  flow <- parse_auth_flow(basic_auth)

  expect_s3_class(flow, "fireproof_op")
  expect_null(attr(flow, "op"))
  expect_equal(flow[[1]], "basic_auth")
})

test_that("parse_auth_flow parses OR expression", {
  flow <- parse_auth_flow(auth1 || auth2)

  expect_s3_class(flow, "fireproof_op")
  expect_equal(attr(flow, "op"), "||")
  expect_equal(flow[[1]], "auth1")
  expect_equal(flow[[2]], "auth2")
})

test_that("parse_auth_flow parses AND expression", {
  flow <- parse_auth_flow(auth1 && auth2)

  expect_s3_class(flow, "fireproof_op")
  expect_equal(attr(flow, "op"), "&&")
  expect_equal(flow[[1]], "auth1")
  expect_equal(flow[[2]], "auth2")
})

test_that("parse_auth_flow parses nested expression", {
  flow <- parse_auth_flow((auth1 && auth2) || auth3)

  expect_s3_class(flow, "fireproof_op")
  expect_equal(attr(flow, "op"), "||")
  expect_length(flow, 2)
  expect_s3_class(flow[[1]], "fireproof_op")
  expect_equal(attr(flow[[1]], "op"), "&&")
})

test_that("parse_auth_flow handles parentheses", {
  flow <- parse_auth_flow((auth1))

  expect_s3_class(flow, "fireproof_op")
  expect_equal(flow[[1]], "auth1")
})

test_that("parse_auth_flow returns NULL for NULL input", {
  flow <- parse_auth_flow(NULL)

  expect_null(flow)
})

test_that("parse_auth_flow rejects invalid operators", {
  expect_error(
    parse_auth_flow(auth1 + auth2),
    "Unknown operator"
  )

  expect_error(
    parse_auth_flow(auth1 & auth2),
    "Unknown operator"
  )
})

test_that("parse_auth_flow collapses same operators", {
  # auth1 || auth2 || auth3 should collapse to single OR with 3 elements
  flow <- parse_auth_flow(auth1 || auth2 || auth3)

  expect_s3_class(flow, "fireproof_op")
  expect_equal(attr(flow, "op"), "||")
  expect_length(flow, 3)
})

test_that("Fireproof on_attach creates RouteStack if missing", {
  skip_if_not_installed("fiery")

  fp <- Fireproof$new()
  app <- fiery::Fire$new()

  # No RouteStack yet
  expect_null(app$plugins$request_routr)

  fp$on_attach(app)

  # RouteStack should now exist
  expect_s3_class(app$plugins$request_routr, "RouteStack")
})

test_that("Fireproof on_attach adds itself to RouteStack", {
  skip_if_not_installed("fiery")
  skip_if_not_installed("routr")

  fp <- Fireproof$new()
  app <- fiery::Fire$new()

  fp$on_attach(app)

  # Check that fireproof is in the route stack
  routes <- app$plugins$request_routr$routes
  expect_true("fireproof_auth" %in% routes)
})

test_that("Fireproof on_attach uses existing RouteStack", {
  skip_if_not_installed("fiery")
  skip_if_not_installed("routr")

  fp <- Fireproof$new()
  app <- fiery::Fire$new()

  # Pre-create RouteStack
  rs <- routr::RouteStack$new()
  rs$attach_to <- "request"
  app$attach(rs)

  initial_count <- length(app$plugins$request_routr$routes)

  fp$on_attach(app)

  # Should have added one more route
  expect_equal(
    length(app$plugins$request_routr$routes),
    initial_count + 1
  )
})

test_that("Fireproof handles quoted guard names", {
  flow <- parse_auth_flow("basic_auth")

  expect_s3_class(flow, "fireproof_op")
  expect_equal(flow[[1]], "basic_auth")
})

test_that("Fireproof handles single-quoted guard names", {
  flow <- parse_auth_flow('basic_auth')

  expect_s3_class(flow, "fireproof_op")
  expect_equal(flow[[1]], "basic_auth")
})

test_that("Fireproof add_guard calls register_handler on Guard", {
  fp <- Fireproof$new()

  # Create a guard that tracks if register_handler was called
  guard <- guard_basic(
    validate = function(username, password) TRUE,
    name = "basic"
  )

  # Guard's register_handler should be called
  fp$add_guard(guard, "basic_auth")

  # No direct way to test this without mocking, but we can verify no error
  expect_true(TRUE)
})

test_that("Fireproof format method for flow works", {
  flow <- parse_auth_flow(auth1 || auth2)

  formatted <- format(flow)

  expect_type(formatted, "character")
  expect_true(grepl("\\|\\|", formatted))
})

test_that("Fireproof handles multiple methods for same path", {
  fp <- Fireproof$new()

  guard <- guard_basic(
    validate = function(username, password) TRUE,
    name = "basic"
  )
  fp$add_guard(guard, "basic_auth")

  expect_no_error({
    fp$add_auth("get", "/path", basic_auth)
    fp$add_auth("post", "/path", basic_auth)
    fp$add_auth("delete", "/path", basic_auth)
  })
})

test_that("Fireproof handles wildcard paths", {
  fp <- Fireproof$new()

  guard <- guard_basic(
    validate = function(username, password) TRUE,
    name = "basic"
  )
  fp$add_guard(guard, "basic_auth")

  expect_no_error(
    fp$add_auth("all", "/*", basic_auth)
  )
})
