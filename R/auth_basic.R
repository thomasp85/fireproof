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
#' @param authenticator A function that takes a username and password and
#' returns `TRUE` if the pair is valid, and `FALSE` otherwise
#' @param name The name of the authentication
#' @param realm The realm this authentication corresponds to. Will be returned
#' to the client on a failed authentication attempt to inform them of the
#' credentials required, though most often these days it is kept from the user.
#'
#' @return An `AuthBasic` R6 object
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
  pwd_compare = sodium::password_verify
) {
  check_installed("dplyr")
  function(username, password) {
    user <- dplyr::filter(table, .data[[user_col]] == username)
    pwd <- dplyr::pull(user, !!pwd_col)
    if (length(pwd) == 1) {
      pwd_compare(pwd, password)
    } else {
      FALSE
    }
  }
}

AuthBasic <- R6::R6Class(
  "AuthBasic",
  inherit = Auth,
  public = list(
    initialize = function(
      authenticator,
      realm = "private",
      name = NULL
    ) {
      super$initialize(
        name = name
      )
      check_function(authenticator)
      if (length(fn_fmls(authenticator)) != 2) {
        cli::cli_abort(
          "{.arg authenticator} must be a function with two arguments: `username` and `password`"
        )
      }
      private$AUTHENTICATOR <- authenticator
      check_string(realm)
      private$REALM <- realm
    },
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
        request$set_data("username", auth[1])
        authenticated <- private$AUTHENTICATOR(auth[1], auth[2])
      }
      authenticated
    },
    reject_response = function(response) {
      response$set_header(
        "WWW-Authenticate",
        paste0('Basic realm="', private$REALM, '"')
      )
      response$status <- 401L
    }
  ),
  private = list(
    AUTHENTICATOR = NULL,
    REALM = ""
  )
)
