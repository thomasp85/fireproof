#' Basic authentication plugin
#'
#' Basic authentication is a HTTP scheme that sends username and password as a
#' `:` separated, base64 encoded string in the authorization header. Because it
#' is effectively send in plain text (base64 encoding can easily be decoded)
#' this should only ever be used along with other security measures such as
#' https/ssl to avoid username and passwords being snooped from the request.
#'
#' @param authenticator A function that takes a username and password and
#' returns `TRUE` if the pair is valid, and `FALSE` otherwise
#' @param get,head,post,put,delete,connect,options,trace,patch,all Character
#' vectors with paths to add authentication to up front. Additional paths can be
#' added afterwards using the `add_handler()` method.
#' @param name The name of the plugin
#' @param realm The realm this authentication corresponds to. Will be returned
#' to the client on a failed authentication attempt to inform them of the
#' credentials required though most often these days it is kept from the user.
#' @param ignore_trailing_slash Logical. Should the trailing slash of a path
#' be ignored when determining if a request should be authenticated. Setting
#' this will not change the request or the path associated with it but just ensure that
#' both `path/to/resource` and `path/to/resource/` ends up being authenticated
#'
#' @return A `AuthBasicRoute` object
#'
#' @export
#'
auth_basic <- function(
  authenticator,
  get = NULL,
  head = NULL,
  post = NULL,
  put = NULL,
  delete = NULL,
  connect = NULL,
  options = NULL,
  trace = NULL,
  patch = NULL,
  all = NULL,
  name = "BasicAuth",
  realm = "private",
  ignore_trailing_slash = FALSE
) {
  route <- AuthBasicRoute$new(
    name = name,
    authenticator = authenticator,
    realm = realm,
    ignore_trailing_slash = ignore_trailing_slash
  )
  prefill_paths(
    route,
    get = get,
    head = head,
    post = post,
    put = put,
    delete = delete,
    connect = connect,
    options = options,
    trace = trace,
    patch = patch,
    all = all
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

AuthBasicRoute <- R6::R6Class(
  "AuthBasicRoute",
  inherit = AuthRoute,
  public = list(
    initialize = function(
      name,
      authenticator,
      realm = "private",
      ignore_trailing_slash = FALSE
    ) {
      super$initialize(
        name = name,
        ignore_trailing_slash = ignore_trailing_slash
      )
      check_function(authenticator)
      private$AUTHENTICATOR <- authenticator
      check_string(realm)
      private$REALM <- realm
      private$SCHEME <- "basic"
    }
  ),
  private = list(
    AUTHENTICATOR = NULL,
    REALM = "",

    validator = function(request, response) {
      auth <- request$headers$authorization
      authenticated <- FALSE
      if (!is.null(auth) && grepl("^Basic ", auth)) {
        auth <- sub("^Basic ", "", auth)
        auth <- base64enc::base64decode(auth)
        auth <- strsplit(auth, ":", fixed = TRUE)[[1]]
        if (length(auth) != 2) {
          reqres::abort_bad_request("Malformed Authorization header")
        }
        request$set_data("username", auth[1])
        authenticated <- private$AUTHENTICATOR(auth[1], auth[2])
      }
      if (!authenticated) {
        response$set_header(
          "WWW-Authenticate",
          paste0('Basic realm="', private$REALM, '"')
        )
        reqres::abort_unauthorized("Unauthorized")
      }
      authenticated
    }
  )
)
