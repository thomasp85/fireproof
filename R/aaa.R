#' Extract the path from a URL
#'
#' This function is a simple helper that extract the path part of a URL. It is
#' useful when constructing OAuth 2.0 derived authenticators for the
#' `redirect_path` argument.
#'
#' @param url The url to extract the path from
#' @param root An optional root to remove from the path as well
#'
#' @return The "path" part of the URL
#'
#' @export
#'
#' @keywords internal
#'
#' @examples
#' get_path("https://example.com/auth")
#'
#' get_path("https://example.com/api/auth", root = "/api")
#'
get_path <- function(url, root = NULL) {
  url <- sub("^https?://[^/]+", "", url)
  if (!is.null(root) && !root %in% c("/", "")) {
    root <- sub("^/?", "/", root)
    root <- sub("(?<!^)/$", "", root, perl = TRUE)
    root <- paste0("^", root)
    if (!grepl(root, url, ignore.case = TRUE)) {
      cli::cli_abort("{.arg root} not part of {.arg url}")
    }
    url <- sub(root, "", url, ignore.case = TRUE)
  }
  if (url == "") url <- "/"
  url
}

abort_auth <- function(internal_msg, call = caller_env(), ...) {
  reqres::abort_http_problem(
    503L,
    "Unable to complete authentication",
    title = "authentication_failed",
    message = internal_msg,
    call = call,
    ...
  )
}

abort_oauth_error <- function(error, detail, uri, call = caller_env()) {
  switch(
    error,
    invalid_request = reqres::abort_http_problem(
      400L,
      detail %||%
        "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed",
      title = error,
      type = uri,
      call = call
    ),
    unauthorized_client = reqres::abort_http_problem(
      400L,
      detail %||%
        "The client is not authorized to request an authorization code using this method",
      title = error,
      type = uri,
      call = call
    ),
    access_denied = reqres::abort_http_problem(
      403L,
      detail %||%
        "The resource owner or authorization server denied the request",
      title = error,
      type = uri,
      call = call
    ),
    unsupported_response_type = reqres::abort_http_problem(
      400L,
      detail %||%
        "The authorization server does not support obtaining an authorization code using this method",
      title = error,
      type = uri,
      call = call
    ),
    invalid_scope = reqres::abort_http_problem(
      400L,
      detail %||% "The requested scope is invalid, unknown, or malformed",
      title = error,
      type = uri,
      call = call
    ),
    server_error = reqres::abort_http_problem(
      503L,
      detail %||%
        "The authorization server encountered an unexpected condition that prevented it from fulfilling the request",
      title = error,
      type = uri,
      call = call
    ),
    temporarily_unavailable = reqres::abort_http_problem(
      503L,
      detail %||%
        "The authorization server is currently unable to handle the request due to a temporary overloading or maintenance of the server",
      title = error,
      type = uri,
      call = call
    ),
    reqres::abort_bad_request(
      detail %||% "Unknown error",
      title = error,
      type = uri,
      call = call
    )
  )
}

with_dots <- function(fun) {
  if (!"..." %in% fn_fmls_names(fun)) {
    fn_fmls(fun) <- c(fn_fmls(fun), "..." = missing_arg())
  }
  fun
}
