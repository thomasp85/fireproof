#' Authentication based on shared secret
#'
#' This authentication scheme is based on a mutually shared secret between the
#' server and the client. The client provides this secret either as a header or
#' in a cookie, and the server verifies the authenticity of the secret. Like
#' with [basic authentication][auth_basic], this scheme relies on additional
#' technology like HTTPS/SSL to make it secure since the secret can otherwise
#' easily be extracted from the request by man-in-the-middle attack.
#'
#' @details
#' This authentication is not a classic HTTP authentication scheme and thus
#' doesn't return a `401` response with a `WWW-Authenticate` header. Instead it
#' returns a `400` response unless another authenticator has already set the
#' response status to something else.
#'
#' @param key The name of the header or cookie to store the secret under
#' @param secret The secret to check for. Either a single string with the secret
#' or a function that takes a value and returns `TRUE` if its a valid secret
#' (useful if you have multiple or rotating secrets). Make sure never to store
#' secrets in plain text and avoid checking them into version control.
#' @param cookie Boolean. Should the secret be transmitted as a cookie. If
#' `FALSE` it is expected to be transmitted as a header.
#' @inheritParams auth_basic
#'
#' @return A `AuthBasic` object
#'
#' @export
#'
auth_key <- function(
  key,
  secret,
  cookie = TRUE,
  name = "KeyAuth"
) {
  AuthKey$new(
    key = key,
    secret = secret,
    cookie = cookie,
    name = name
  )
}

AuthKey <- R6::R6Class(
  "AuthKey",
  inherit = Auth,
  public = list(
    initialize = function(
      key,
      secret,
      cookie = TRUE,
      name
    ) {
      super$initialize(
        name = name
      )
      check_string(key)
      private$KEY <- key
      if (is_string(secret)) {
        secret_string <- secret
        secret <- function(x) identical(x, secret_string)
      }
      check_function(secret)
      private$SECRET <- secret
      check_bool(cookie)
      private$COOKIE <- cookie
    },
    check_request = function(request, response, keys, ...) {
      auth <- if (private$COOKIE) {
        request$headers[[private$KEY]]
      } else {
        request$cookies[[private$KEY]]
      }
      private$SECRET(auth)
    },
    reject_response = function(response) {
      # Don't overwrite more specific rejection from other auths
      if (response$status == 404L) {
        response$status <- 400L
      }
    }
  ),
  active = list(
    location = function() {
      if (private$COOKIE) "cookie" else "header"
    }
  ),
  private = list(
    KEY = "",
    SECRET = "",
    COOKIE = TRUE
  )
)
