#' Shared secret guard
#'
#' This authentication scheme is based on a mutually shared secret between the
#' server and the client. The client provides this secret either as a header or
#' in a cookie, and the server verifies the authenticity of the secret. Like
#' with [basic authentication][guard_basic], this scheme relies on additional
#' technology like HTTPS/SSL to make it secure since the secret can otherwise
#' easily be extracted from the request by man-in-the-middle attack.
#'
#' @details
#' This authentication is not a classic HTTP authentication scheme and thus
#' doesn't return a `401` response with a `WWW-Authenticate` header. Instead it
#' returns a `400` response unless another guard has already set the
#' response status to something else.
#'
#' # User information
#' `guard_key()` automatically adds [user information][user_info] after
#' authentication. By default it will set the `provider` field to `"local"`.
#' Further, it will set the `scopes` field to any scopes returned by the
#' `validate` function (provided `validate` is passed a function).
#'
#' Since Key based authentication is seldom used with user specific keys it is
#' unlikely that it makes sense to populate the information any further.
#'
#' @param key_name The name of the header or cookie to store the secret under
#' @param validate Either a single string with the secret
#' or a function that will be called with the arguments `key`, `request`, and
#' `response` and returns `TRUE` if its a valid secret (useful if you have
#' multiple or rotating secrets). If the function returns a character vector it
#' is considered to be authenticated and the return value will be understood as
#' scopes the user is granted. Make sure never to store secrets in plain text
#' and avoid checking them into version control.
#' @param user_info A function to extract user information from the
#' key. It is called with a single argument: `key` which is the key
#' used for the successful authentication. The function should return a new
#' [user_info][new_user_info] list.
#' @param cookie Boolean. Should the secret be transmitted as a cookie. If
#' `FALSE` it is expected to be transmitted as a header.
#' @inheritParams guard_basic
#'
#' @return A [GuardKey] object
#'
#' @export
#'
#' @examples
#' # Create a guard of dubious quality
#' key <- guard_key(
#'   key_name = "my-key-location",
#'   validate = "SHHH!!DONT_TELL_ANYONE"
#' )
#'
#' # Add it to a fireproof plugin
#' fp <- Fireproof$new()
#' fp$add_guard(key, "key_auth")
#'
#' # Use it in an endpoint
#' fp$add_auth("get", "/*", key_auth)
#'
guard_key <- function(
  key_name,
  validate,
  user_info = NULL,
  cookie = TRUE,
  name = "KeyAuth"
) {
  GuardKey$new(
    key_name = key_name,
    validate = validate,
    user_info = user_info,
    cookie = cookie,
    name = name
  )
}

#' R6 class for the Key guard
#'
#' @description
#' This class encapsulates the logic of the key based authentication scheme. See
#' [guard_key()] for more information
#'
#' @export
#'
#' @examples
#' # Create a guard of dubious quality
#' key <- GuardKey$new(
#'   key = "my-key-location",
#'   validate = "SHHH!!DONT_TELL_ANYONE"
#' )
#'
GuardKey <- R6::R6Class(
  "GuardKey",
  inherit = Guard,
  public = list(
    #' @description Constructor for the class
    #' @param key_name The name of the header or cookie to store the secret under
    #' @param validate Either a single string with the secret
    #' or a function that will be called with the arguments `key`, `request`, and
    #' `response` and returns `TRUE` if its a valid secret (useful if you have
    #' multiple or rotating secrets). If the function returns a character vector it
    #' is considered to be authenticated and the return value will be understood as
    #' scopes the user is granted. Make sure never to store secrets in plain text
    #' and avoid checking them into version control.
    #' @param user_info A function to extract user information from the
    #' key. It is called with a single argument: `key` which is the key
    #' used for the successful authentication. The function should return a new
    #' [user_info][new_user_info] list.
    #' @param cookie Boolean. Should the secret be transmitted as a cookie. If
    #' `FALSE` it is expected to be transmitted as a header.
    #' @param name The name of the scheme instance
    initialize = function(
      key_name,
      validate,
      user_info = NULL,
      cookie = TRUE,
      name = NULL
    ) {
      super$initialize(
        name = name
      )
      check_string(key_name)
      private$KEY <- key_name
      if (is_string(validate)) {
        secret_string <- validate
        validate <- function(key, ...) identical(key, secret_string)
      }
      check_function(validate)
      private$VALIDATE <- with_dots(validate)
      check_bool(cookie)
      private$COOKIE <- cookie

      user_info <- user_info %||%
        function(key) {
          new_user_info()
        }
      check_function(user_info)
      private$USER_INFO <- with_dots(user_info)
    },
    #' @description A function that validates an incoming request, returning
    #' `TRUE` if it is valid and `FALSE` if not. It extracts the secret from
    #' either the cookie or header based on the provided `key` and test it
    #' based on `validate`.
    #' @param request The request to validate as a [Request][reqres::Request]
    #' object
    #' @param response The corresponding response to the request as a
    #' [Response][reqres::Response] object
    #' @param keys A named list of path parameters from the path matching
    #' @param server The fiery server handling the request
    #' @param arg_list A list of additional arguments extracted be the
    #' `before_request` handlers (will be used to access the session data store)
    #' @param ... Ignored
    #' @param .session The session storage for the current session
    #'
    check_request = function(request, response, keys, ..., .session) {
      info <- .session[[private$NAME]]
      authenticated <- is_user_info(info)
      if (!authenticated) {
        key <- if (private$COOKIE) {
          request$cookies[[private$KEY]]
        } else {
          request$get_header(private$KEY)
        }
        if (is.null(key)) {
          return(FALSE)
        }
        authenticated <- private$VALIDATE(
          key = key,
          request = request,
          response = response
        )
        scopes <- private$SCOPES %||% character()
        if (is.character(authenticated)) {
          scopes <- authenticated
          authenticated <- TRUE
        }
        if (authenticated) {
          .session[[private$NAME]] <- combine_info(
            new_user_info(provider = "local", scopes = scopes),
            private$USER_INFO(key)
          )
        } else {
          .session[[private$NAME]] <- list()
        }
      }
      authenticated
    },
    #' @description Upon rejection this scheme sets the response status to `400`
    #' if it has not already been set by others. In contrast to the other
    #' schemes that are proper HTTP schemes, this one doesn't set a
    #' `WWW-Authenticate` header.
    #' @param response The response object
    #' @param scope The scope of the endpoint
    #' @param ... Ignored
    #' @param .session The session storage for the current session
    reject_response = function(response, scope, ..., .session) {
      # Don't overwrite more specific rejection from other guards
      if (response$status == 404L) {
        if (!is.null(.session[[private$NAME]])) {
          .session[[private$NAME]] <- NULL
          response$status_with_text(403L)
        } else {
          response$status_with_text(400L)
        }
      }
    }
  ),
  active = list(
    #' @field location The location of the secret in the request, either
    #' `"cookie"` or `"header"`
    location = function() {
      if (private$COOKIE) "cookie" else "header"
    },
    #' @field open_api An OpenID compliant security scheme description
    open_api = function() {
      list(
        type = "apiKey",
        "in" = self$location,
        name = private$KEY
      )
    }
  ),
  private = list(
    KEY = "",
    VALIDATE = "",
    COOKIE = TRUE,
    USER_INFO = NULL
  )
)
