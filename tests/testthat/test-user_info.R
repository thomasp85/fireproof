test_that("new_user_info creates basic user info structure", {
  info <- new_user_info(
    provider = "local",
    id = "user123"
  )

  expect_s3_class(info, "fireproof_user_info")
  expect_type(info, "list")
  expect_equal(info$provider, "local")
  expect_equal(info$id, "user123")
})

test_that("new_user_info combines name fields correctly", {
  info <- new_user_info(
    provider = "local",
    id = "user123",
    name_given = "Thomas",
    name_middle = "Lin",
    name_family = "Pedersen",
    name_display = "thomasp85",
    name_user = "tpedersen"
  )

  expect_equal(
    info$name,
    c(
      given = "Thomas",
      middle = "Lin",
      family = "Pedersen",
      display = "thomasp85",
      user = "tpedersen"
    )
  )
})

test_that("new_user_info handles partial name information", {
  info <- new_user_info(
    provider = "local",
    id = "user123",
    name_given = "Thomas",
    name_family = "Pedersen"
  )

  # Should only include provided name fields
  expect_equal(info$name["given"], c(given = "Thomas"))
  expect_equal(info$name["family"], c(family = "Pedersen"))
  expect_true(is.na(info$name["middle"]))
  expect_true(is.na(info$name["display"]))
  expect_true(is.na(info$name["user"]))
})

test_that("new_user_info handles additional fields via ...", {
  info <- new_user_info(
    provider = "local",
    id = "user123",
    scopes = c("read", "write"),
    token = list(access_token = "abc123"),
    custom_field = "custom_value"
  )

  expect_equal(info$scopes, c("read", "write"))
  expect_equal(info$token, list(access_token = "abc123"))
  expect_equal(info$custom_field, "custom_value")
})

test_that("new_user_info works with all NULL values", {
  info <- new_user_info()

  expect_s3_class(info, "fireproof_user_info")
  expect_null(info$provider)
  expect_null(info$id)
  expect_null(info$name)
  expect_null(info$emails)
  expect_null(info$photos)
})
