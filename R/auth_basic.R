#' Basic authentication plugin
#'
#' Basic authentication is a HTTP scheme that sends username and password as a
#' `:` separated, base64 encoded string in the authorization header. Because it
#' is effectively send in plain text (base64 encoding can easily be decoded)
#' this should only ever be used along with other security measures such as
#' https/ssl to avoid username and passwords being snooped from the request.
#'
#' @details
#' This authenticator will use a user provided function to test a
#' username/password pair. It is up to the user to handle the storage and
#' testing of the passwords in a sensible and responsible way. See
#' [sodium::password_store()] for a good first step towards responsible design.
#'
#' If the authentication passes, the username from the authorization header is
#' written to the `username` data slot in the request
#'
#' @param authenticator A function that takes a username, password, realm,
#' request, and response and returns `TRUE` if the pair is valid, and `FALSE`
#' otherwise. If the function sets a character vector of scopes for the user in
#' the `auth_scope` field of the response data
#' (`response$set_data("auth_scope", ...)`) then it will be tested against the
#' scopes needed for the specific endpoint
#' @param name The name of the authentication
#' @param realm The realm this authentication corresponds to. Will be returned
#' to the client on a failed authentication attempt to inform them of the
#' credentials required, though most often these days it is kept from the user.
#'
#' @return An [AuthBasic] R6 object
#'
#' @export
#' @importFrom base64enc base64decode
#'
auth_basic <- function(
  authenticator,
  name = "BasicAuth",
  realm = "private"
) {
  AuthBasic$new(
    authenticator = authenticator,
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

#' R6 class for the Basic authentication scheme
#'
#' @description
#' This class encapsulates the logic of the
#' [Basic authentication scheme](https://datatracker.ietf.org/doc/html/rfc7617).
#' See [auth_basic()] for more information.
#'
#' @export
#'
AuthBasic <- R6::R6Class(
  "AuthBasic",
  inherit = Auth,
  public = list(
    #' @description Constructor for the class
    #' @param authenticator A function that takes a username, password, realm,
    #' request, and response and returns `TRUE` if the pair is valid, and `FALSE`
    #' otherwise. If the function sets a character vector of scopes for the user in
    #' the `auth_scope` field of the response data
    #' (`response$set_data("auth_scope", ...)`) then it will be tested against the
    #' scopes needed for the specific endpoint
    #' @param realm The realm this authentication corresponds to. Will be returned
    #' to the client on a failed authentication attempt to inform them of the
    #' credentials required, though most often these days it is kept from the user.
    #' @param name The name of the authentication
    initialize = function(
      authenticator,
      realm = "private",
      name = NULL
    ) {
      super$initialize(
        name = name
      )
      check_function(authenticator)
      if (length(fn_fmls(authenticator)) != 5 && !"..." %in% fn_fmls_names(authenticator)) {
        cli::cli_abort(
          "{.arg authenticator} must be a function with five arguments: `username`, `password`, `realm`, `request`, and `response`"
        )
      }
      private$AUTHENTICATOR <- authenticator
      check_string(realm)
      private$REALM <- realm
    },
    #' @description A function that validates an incoming request, returning
    #' `TRUE` if it is valid and `FALSE` if not. It decodes the credentials in
    #' the `Authorization` header, splits it into username and password and then
    #' calls the authenticator function provided at construction.
    #' @param request The request to validate as a [Request][reqres::Request]
    #' object
    #' @param response The corresponding response to the request as a
    #' [Response][reqres::Response] object
    #' @param keys A named list of path parameters from the path matching
    #' @param ... Ignored
    #'
    check_request = function(request, response, keys, ...) {
      auth <- request$headers$authorization
      authenticated <- FALSE
      if (!is.null(auth) && grepl("^Basic ", auth)) {
        auth <- sub("^Basic ", "", auth)
        auth <- base64decode(auth)
        auth <- strsplit(auth, ":", fixed = TRUE)[[1]]
        if (length(auth) != 2) {
          reqres::abort_bad_request("Malformed Authorization header")
        }
        response$set_data("auth_username", auth[1])
        authenticated <- private$AUTHENTICATOR(
          auth[1],
          auth[2],
          private$REALM,
          request,
          response
        )
      }
      authenticated
    },
    #' @description Upon rejection this scheme sets the response status to `401`
    #' and sets the `WWW-Authenticate` header to
    #' `Basic realm="<realm>", charset=UTF-8`
    #' @param response The response object
    #' @param scope The scope of the endpoint
    reject_response = function(response, scope) {
      response$append_header(
        "WWW-Authenticate",
        paste0('Basic realm="', private$REALM, '", charset=UTF-8')
      )
      response$status <- 401L
    }
  ),
  private = list(
    AUTHENTICATOR = NULL,
    REALM = ""
  )
)
