test_that("and() creates fireproof_op with && operator", {
  op <- and("auth1", "auth2")

  expect_s3_class(op, "fireproof_op")
  expect_equal(attr(op, "op"), "&&")
  expect_equal(length(op), 2)
  expect_equal(op[[1]], "auth1")
  expect_equal(op[[2]], "auth2")
})

test_that("or() creates fireproof_op with || operator", {
  op <- or("auth1", "auth2")

  expect_s3_class(op, "fireproof_op")
  expect_equal(attr(op, "op"), "||")
  expect_equal(length(op), 2)
  expect_equal(op[[1]], "auth1")
  expect_equal(op[[2]], "auth2")
})

test_that("scalar() creates fireproof_op with NULL operator", {
  op <- scalar("auth1")

  expect_s3_class(op, "fireproof_op")
  expect_null(attr(op, "op"))
  expect_equal(length(op), 1)
  expect_equal(op[[1]], "auth1")
})

test_that("may_collapse() checks operator compatibility", {
  and_op <- and("auth1", "auth2")
  or_op <- or("auth1", "auth2")
  scalar_op <- scalar("auth1")

  # and operation may collapse with && operator
  expect_true(may_collapse(and_op, "&&"))
  expect_false(may_collapse(and_op, "||"))

  # or operation may collapse with || operator
  expect_true(may_collapse(or_op, "||"))
  expect_false(may_collapse(or_op, "&&"))

  # scalar with NULL op uses the provided op as default
  expect_true(may_collapse(scalar_op, "&&"))
  expect_true(may_collapse(scalar_op, "||"))
})

test_that("eval_op evaluates single element", {
  op <- scalar("auth1")
  table <- list(auth1 = TRUE)

  result <- eval_op(op, table)
  expect_true(result)

  table <- list(auth1 = FALSE)
  result <- eval_op(op, table)
  expect_false(result)
})

test_that("eval_op evaluates and operation", {
  # all TRUE
  op <- and("auth1", "auth2")
  table <- list(auth1 = TRUE, auth2 = TRUE)

  result <- eval_op(op, table)
  expect_true(result)

  # one FALSE
  table <- list(auth1 = TRUE, auth2 = FALSE)

  result <- eval_op(op, table)
  expect_false(result)

  # all FALSE
  table <- list(auth1 = FALSE, auth2 = FALSE)

  result <- eval_op(op, table)
  expect_false(result)
})

test_that("eval_op evaluates or operation", {
  # All TRUE
  op <- or("auth1", "auth2")
  table <- list(auth1 = TRUE, auth2 = TRUE)

  result <- eval_op(op, table)
  expect_true(result)

  # one TRUE
  table <- list(auth1 = TRUE, auth2 = FALSE)

  result <- eval_op(op, table)
  expect_true(result)

  # all FALSE
  table <- list(auth1 = FALSE, auth2 = FALSE)

  result <- eval_op(op, table)
  expect_false(result)
})

test_that("eval_op evaluates nested operations", {
  # (auth1 && auth2) || auth3
  inner_and <- and("auth1", "auth2")
  outer_or <- or(inner_and, "auth3")

  # Case 1: inner_and is TRUE, auth3 is FALSE -> TRUE
  table <- list(auth1 = TRUE, auth2 = TRUE, auth3 = FALSE)
  expect_true(eval_op(outer_or, table))

  # Case 2: inner_and is FALSE, auth3 is TRUE -> TRUE
  table <- list(auth1 = FALSE, auth2 = TRUE, auth3 = TRUE)
  expect_true(eval_op(outer_or, table))

  # Case 3: inner_and is FALSE, auth3 is FALSE -> FALSE
  table <- list(auth1 = FALSE, auth2 = TRUE, auth3 = FALSE)
  expect_false(eval_op(outer_or, table))
})

test_that("eval_op evaluates complex nested operations", {
  # (auth1 || auth2) && (auth3 || auth4)
  or1 <- or("auth1", "auth2")
  or2 <- or("auth3", "auth4")
  and_op <- and(or1, or2)

  # Both OR conditions TRUE
  table <- list(auth1 = TRUE, auth2 = FALSE, auth3 = TRUE, auth4 = FALSE)
  expect_true(eval_op(and_op, table))

  # First OR TRUE, second OR FALSE
  table <- list(auth1 = TRUE, auth2 = FALSE, auth3 = FALSE, auth4 = FALSE)
  expect_false(eval_op(and_op, table))

  # First OR FALSE, second OR TRUE
  table <- list(auth1 = FALSE, auth2 = FALSE, auth3 = TRUE, auth4 = FALSE)
  expect_false(eval_op(and_op, table))
})

test_that("is_flow_valid_openapi validates top-level OR operations", {
  # Valid: top-level OR
  op <- or("auth1", "auth2")
  expect_true(is_flow_valid_openapi(op))

  # Invalid: top-level AND
  op <- and("auth1", "auth2")
  expect_false(is_flow_valid_openapi(op))

  # Invalid: scalar (no OR at top level)
  op <- scalar("auth1")
  expect_false(is_flow_valid_openapi(op))
})

test_that("is_flow_valid_openapi validates depth <= 2", {
  # Valid: depth 1
  op <- or("auth1", "auth2")
  expect_true(is_flow_valid_openapi(op))

  # Valid: depth 2
  inner <- and("auth1", "auth2")
  op <- or(inner, "auth3")
  expect_true(is_flow_valid_openapi(op))

  # Invalid: depth 3
  level3 <- and("auth1", "auth2")
  level2 <- or(level3, "auth3")
  level1 <- and(level2, "auth4")
  expect_false(is_flow_valid_openapi(level1))
})

test_that("flow_depth calculates depth correctly for single element", {
  op <- scalar("auth1")
  expect_equal(flow_depth(op), 1L)
})
