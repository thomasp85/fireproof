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

with_dots <- function(fun) {
  if (!"..." %in% fn_fmls_names(fun)) {
    fn_fmls(fun) <- c(fn_fmls(fun), "..." = missing_arg())
  }
  fun
}
