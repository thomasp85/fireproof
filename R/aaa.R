abort_auth <- function(internal_msg, call = caller_env(), ...) {
  reqres::abort_http_problem(
    503L,
    "Unable to complete authentication",
    title = "authentication_failed",
    message = internal_msg,
    call = call(),
    ...
  )
}
