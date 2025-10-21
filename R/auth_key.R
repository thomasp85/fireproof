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
#' or a function that takes the key, the request and the response and returns
#' `TRUE` if its a valid secret (useful if you have multiple or rotating
#' secrets). If a function, the function can also set the scope of the key in
#' the `auth_scope` field of the response data
#' (`response$set_data("auth_scope", ...)`) then it will be tested against the
#' scopes needed for the specific endpoint. Make sure never to store secrets in
#' plain text and avoid checking them into version control.
#' @param cookie Boolean. Should the secret be transmitted as a cookie. If
#' `FALSE` it is expected to be transmitted as a header.
#' @inheritParams auth_basic
#'
#' @return A [AuthKey] object
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

#' R6 class for the Key authentication scheme
#'
#' @description
#' This class encapsulates the logic of the key based authentication scheme. See
#' [auth_key()] for more information
#'
#' @export
#'
AuthKey <- R6::R6Class(
  "AuthKey",
  inherit = Auth,
  public = list(
    #' @description Constructor for the class
    #' @param key The name of the header or cookie to store the secret under
    #' @param secret The secret to check for. Either a single string with the secret
    #' or a function that takes the key, the request and the response and returns
    #' `TRUE` if its a valid secret (useful if you have multiple or rotating
    #' secrets). If a function, the function can also set the scope of the key in
    #' the `auth_scope` field of the response data
    #' (`response$set_data("auth_scope", ...)`) then it will be tested against the
    #' scopes needed for the specific endpoint. Make sure never to store secrets in
    #' plain text and avoid checking them into version control.
    #' @param cookie Boolean. Should the secret be transmitted as a cookie. If
    #' `FALSE` it is expected to be transmitted as a header.
    #' @param name The name of the scheme instance
    initialize = function(
      key,
      secret,
      cookie = TRUE,
      name = NULL
    ) {
      super$initialize(
        name = name
      )
      check_string(key)
      private$KEY <- key
      if (is_string(secret)) {
        secret_string <- secret
        secret <- function(key, request, response) identical(key, secret_string)
      }
      check_function(secret)
      if (length(fn_fmls(secret)) != 3 && !"..." %in% fn_fmls_names(authenticator)) {
        cli::cli_abort(
          "{.arg secret} must be a string or a function with three arguments: `key`, `request`, and `response`"
        )
      }
      private$SECRET <- secret
      check_bool(cookie)
      private$COOKIE <- cookie
    },
    #' @description A function that validates an incoming request, returning
    #' `TRUE` if it is valid and `FALSE` if not. It extracts the secret from
    #' either the cookie or header based on the provided `key` and test it
    #' against the provided `secret`.
    #' @param request The request to validate as a [Request][reqres::Request]
    #' object
    #' @param response The corresponding response to the request as a
    #' [Response][reqres::Response] object
    #' @param keys A named list of path parameters from the path matching
    #' @param ... Ignored
    #'
    check_request = function(request, response, keys, ...) {
      key <- if (private$COOKIE) {
        request$headers[[private$KEY]]
      } else {
        request$cookies[[private$KEY]]
      }
      private$SECRET(key, request, response)
    },
    #' @description Upon rejection this scheme sets the response status to `400`
    #' if it has not already been set by others. In contrast to the other
    #' schemes that are proper HTTP schemes, this one doesn't set a
    #' `WWW-Authenticate` header.
    #' @param response The response object
    #' @param scope The scope of the endpoint
    reject_response = function(response, scope) {
      # Don't overwrite more specific rejection from other auths
      if (response$status == 404L) {
        response$status <- 400L
      }
    }
  ),
  active = list(
    #' @field location The location of the secret in the request, either
    #' `"cookie"` or `"header"`
    location = function() {
      if (private$COOKIE) "cookie" else "header"
    },
    #' @field open_id An OpenID compliant security scheme description
    open_id = function() {
      list(
        type = "apiKey",
        "in" = self$location,
        name = private$KEY
      )
    }
  ),
  private = list(
    KEY = "",
    SECRET = "",
    COOKIE = TRUE
  )
)
