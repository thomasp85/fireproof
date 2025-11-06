#' Basic authentication guard
#'
#' Basic authentication is a HTTP scheme that sends username and password as a
#' `:` separated, base64 encoded string in the authorization header. Because it
#' is effectively send in plain text (base64 encoding can easily be decoded)
#' this should only ever be used along with other security measures such as
#' https/ssl to avoid username and passwords being snooped from the request.
#'
#' @details
#' This guard will use a user provided function to test a
#' username/password pair. It is up to the user to handle the storage and
#' testing of the passwords in a sensible and responsible way. See
#' [sodium::password_store()] for a good first step towards responsible design.
#'
#' # User information
#' `guard_basic()` automatically adds [user information][user_info] after
#' authentication. By default it will set the `provider` field to `"local"` and
#' the `id` field to the username used for logging in. Further, it will set
#' the `scopes` field to any scopes returned by the `authenticator` function.
#'
#' @param validate A function that will be called with the arguments
#' `username`, `password`, `realm`, `request`, and `response` and returns `TRUE`
#' if the user is valid, and `FALSE` otherwise. If the function returns a
#' character vector it is considered to be authenticated and the return value
#' will be understood as scopes the user is granted.
#' @param name The name of the guard
#' @param user_info A function to extract user information from the
#' username. It is called with a single argument: `user` which is the username
#' used for the successful authentication. The function should return a new
#' [user_info][new_user_info] list.
#' @param realm The realm this authentication corresponds to. Will be returned
#' to the client on a failed authentication attempt to inform them of the
#' credentials required, though most often these days it is kept from the user.
#'
#' @return A [GuardBasic] R6 object
#'
#' @export
#' @importFrom base64enc base64decode
#'
#' @examples
#' # Create a guard of dubious quality
#' basic <- guard_basic(
#'   validate = function(user, password) {
#'     user == "thomas" && password == "pedersen"
#'   },
#'   user_info = function(user) {
#'     new_user_info(
#'       name_given = "Thomas",
#'       name_middle = "Lin",
#'       name_family = "Pedersen"
#'     )
#'   }
#' )
#'
#' # Add it to a fireproof plugin
#' fp <- Fireproof$new()
#' fp$add_guard(basic, "basic_auth")
#'
#' # Use it in an endpoint
#' fp$add_auth("get", "/*", basic_auth)
#'
guard_basic <- function(
  validate,
  user_info = NULL,
  realm = "private",
  name = "BasicAuth"
) {
  GuardBasic$new(
    validate = validate,
    user_info = user_info,
    realm = realm,
    name = name
  )
}

dplyr_authenticator <- function(
  table,
  user_col = "username",
  pwd_col = "password",
  scope_col = NULL,
  pwd_compare = sodium::password_verify
) {
  check_installed("dplyr")
  function(username, password, realm, request, response) {
    user <- dplyr::filter(table, .data[[user_col]] == username)
    pwd <- dplyr::pull(user, !!pwd_col)
    scope <- if (!is.null(scope_col)) dplyr::pull(user, !!scope_col)
    valid <- if (length(pwd) == 1) {
      pwd_compare(pwd, password)
    } else {
      FALSE
    }
    if (valid && !is.null(scope)) {
      response$set_data("auth_scope", c(response$get_data("auth_scope"), scope))
    }
    valid
  }
}

#' R6 class for the Basic authentication guard
#'
#' @description
#' This class encapsulates the logic of the
#' [Basic authentication scheme](https://datatracker.ietf.org/doc/html/rfc7617).
#' See [guard_basic()] for more information.
#'
#' @export
#'
#' @examples
#' # Create a guard of dubious quality
#' basic <- GuardBasic$new(
#'   validate = function(user, password) {
#'     user == "thomas" && password == "pedersen"
#'   },
#'   user_info = function(user) {
#'     new_user_info(
#'       name_given = "Thomas",
#'       name_middle = "Lin",
#'       name_family = "Pedersen"
#'     )
#'   }
#' )
#'
GuardBasic <- R6::R6Class(
  "GuardBasic",
  inherit = Guard,
  public = list(
    #' @description Constructor for the class
    #' @param validate A function that will be called with the arguments
    #' `username`, `password`, `realm`, `request`, and `response` and returns `TRUE`
    #' if the user is valid, and `FALSE` otherwise. If the function returns a
    #' character vector it is considered to be authenticated and the return value
    #' will be understood as scopes the user is granted.
    #' @param user_info A function to extract user information from the
    #' username. It is called with a single argument: `user` which is the username
    #' used for the successful authentication. The function should return a new
    #' [user_info][new_user_info] list.
    #' @param realm The realm this authentication corresponds to. Will be returned
    #' to the client on a failed authentication attempt to inform them of the
    #' credentials required, though most often these days it is kept from the user.
    #' @param name The name of the authentication
    initialize = function(
      validate,
      user_info = NULL,
      realm = "private",
      name = NULL
    ) {
      super$initialize(
        name = name
      )
      check_function(validate)
      private$VALIDATE <- with_dots(validate)
      check_string(realm)
      private$REALM <- realm

      user_info <- user_info %||%
        function(user) {
          new_user_info()
        }
      private$USER_INFO <- with_dots(user_info)
    },
    #' @description A function that validates an incoming request, returning
    #' `TRUE` if it is valid and `FALSE` if not. It decodes the credentials in
    #' the `Authorization` header, splits it into username and password and then
    #' calls the `validate` function provided at construction.
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

      auth <- request$headers$authorization
      if (!authenticated && !is.null(auth) && grepl("^Basic ", auth)) {
        auth <- sub("^Basic ", "", auth)
        auth <- base64decode(auth)
        auth <- strsplit(rawToChar(auth), ":", fixed = TRUE)[[1]]
        if (length(auth) != 2) {
          reqres::abort_bad_request("Malformed Authorization header")
        }
        response$set_data("auth_username", auth[1])
        authenticated <- private$VALIDATE(
          username = auth[1],
          password = auth[2],
          realm = private$REALM,
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
            new_user_info(provider = "local", id = auth[1], scopes = scopes),
            private$USER_INFO(auth[1])
          )
        } else {
          .session[[private$NAME]] <- list()
        }
      }
      authenticated
    },
    #' @description Upon rejection this scheme sets the response status to `401`
    #' and sets the `WWW-Authenticate` header to
    #' `Basic realm="<realm>", charset=UTF-8`
    #' @param response The response object
    #' @param scope The scope of the endpoint
    #' @param ... Ignored
    #' @param .session The session storage for the current session
    reject_response = function(response, scope, ..., .session) {
      if (response$status %in% c(400L, 404L)) {
        if (!is.null(.session[[private$NAME]])) {
          .session[[private$NAME]] <- NULL
          response$status_with_text(403L)
        } else {
          response$append_header(
            "WWW-Authenticate",
            paste0('Basic realm="', private$REALM, '", charset=UTF-8')
          )
          response$status_with_text(401L)
        }
      }
    }
  ),
  active = list(
    #' @field open_api An OpenID compliant security scheme description
    open_api = function() {
      list(
        type = "http",
        scheme = "basic"
      )
    }
  ),
  private = list(
    VALIDATE = NULL,
    REALM = "",
    USER_INFO = NULL
  )
)
