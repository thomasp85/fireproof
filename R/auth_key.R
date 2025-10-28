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
#' secrets). If the function returns a character vector it is considered to be
#' authenticated and the return value will be understood as scopes the user is
#' granted. Make sure never to store secrets in
#' plain text and avoid checking them into version control.
#' @param user_info A function to extract user information from the
#' username. It takes two arguments: `key` and `setter`,
#' the first being the key used for the successful authentication, the
#' second being a function that must be called in the end with the relevant
#' information. The `setter` function takes the following arguments:
#' `id` (the identifier of the user), `display_name` (the name the user has
#' chosen as public name), `name_given` (the users real given name),
#' `name_middle` (the users middle name), `name_family` (the users family
#' name), `emails` (a vector of emails, potentially named with type, e.g.
#' "work", "home" etc), `photos` (a vector of urls for profile photos),
#' and `...` with additional named fields to add.
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
  user_info = NULL,
  cookie = TRUE,
  name = "KeyAuth"
) {
  AuthKey$new(
    key = key,
    secret = secret,
    user_info = user_info,
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
    #' secrets). If the function returns a character vector it is considered to be
    #' authenticated and the return value will be understood as scopes the user is
    #' granted. Make sure never to store secrets in plain text and avoid
    #' checking them into version control.
    #' @param user_info A function to extract user information from the
    #' username. It takes two arguments: `key` and `setter`,
    #' the first being the key used for the successful authentication, the
    #' second being a function that must be called in the end with the relevant
    #' information. The `setter` function takes the following arguments:
    #' `id` (the identifier of the user), `display_name` (the name the user has
    #' chosen as public name), `name_given` (the users real given name),
    #' `name_middle` (the users middle name), `name_family` (the users family
    #' name), `emails` (a vector of emails, potentially named with type, e.g.
    #' "work", "home" etc), `photos` (a vector of urls for profile photos),
    #' and `...` with additional named fields to add.
    #' @param cookie Boolean. Should the secret be transmitted as a cookie. If
    #' `FALSE` it is expected to be transmitted as a header.
    #' @param name The name of the scheme instance
    initialize = function(
      key,
      secret,
      user_info = NULL,
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
      if (
        length(fn_fmls(secret)) != 3 && !"..." %in% fn_fmls_names(authenticator)
      ) {
        cli::cli_abort(
          "{.arg secret} must be a string or a function with three arguments: `key`, `request`, and `response`"
        )
      }
      private$SECRET <- secret
      check_bool(cookie)
      private$COOKIE <- cookie

      user_info <- user_info %||%
        function(key, setter) {
          setter()
        }
      check_function(user_info)
      if (
        !identical(
          fn_fmls_names(user_info),
          c("key", "setter")
        )
      ) {
        cli::cli_abort(
          "{.arg user_info} must be a function with two arguments: `key` and `setter`"
        )
      }
      private$USER_INFO <- user_info
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
    #' @param server The fiery server handling the request
    #' @param arg_list A list of additional arguments extracted be the
    #' `before_request` handlers (will be used to access the session data store)
    #' @param ... Ignored
    #' @param .session The session storage for the current session
    #'
    check_request = function(request, response, keys, ..., .session) {
      info <- .session[[private$NAME]]
      authenticated <- length(info) != 0
      if (!authenticated) {
        key <- if (private$COOKIE) {
          request$headers[[private$KEY]]
        } else {
          request$cookies[[private$KEY]]
        }
        authenticated <- private$SECRET(key, request, response)
        scopes <- private$SCOPES
        if (is.character(authenticated)) {
          scopes <- authenticated
          authenticated <- TRUE
        }
        if (authenticated) {
          private$USER_INFO(
            key = key,
            setter = key_user_info_setter(.session, private$NAME, scopes)
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
      # Don't overwrite more specific rejection from other auths
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
    SECRET = "",
    COOKIE = TRUE,
    USER_INFO = NULL
  )
)

key_user_info_setter <- function(session, name, scopes) {
  function(
    id = NULL,
    display_name = NULL,
    name_given = NULL,
    name_middle = NULL,
    name_family = NULL,
    emails = character(0),
    photos = character(0),
    ...
  ) {
    session[[name]] <- list2(
      id = id,
      display_name = display_name,
      name = c(given = name_given, middle = name_middle, family = name_family),
      emails = emails,
      photos = photos,
      scopes = scopes,
      ...
    )
  }
}
