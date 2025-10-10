#' Authentication based on shared secret
#'
#' This authentication scheme is based on a mutually shared secret between the
#' server and the client. The client provides this secret either as a header or
#' in a cookie, and the server verifies the authenticity of the secret. Like
#' with [basic authentication][auth_basic], this scheme relies on additional
#' technology like HTTPS/SSL to make it secure since the secret can otherwise
#' easily be extracted from the request by man-in-the-middle attack.
#'
#' @param key The name of the header or cookie to store the secret under
#' @param secret The secret to check for. Make sure never to store this in plain
#' text and check avoid checking it into version control.
#' @param cookie Boolean. Should the secret be transmitted as a cookie. If
#' `FALSE` it is expected to be transmitted as a header.
#' @inheritParams auth_basic
#'
#' @return A `AuthBasicRoute` object
#'
#' @export
#'
auth_key <- function(
  key,
  secret,
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
  cookie = TRUE,
  name = "KeyAuth",
  ignore_trailing_slash = FALSE
) {
  route <- AuthKeyRoute$new(
    name = name,
    key = key,
    secret = secret,
    cookie = cookie,
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

AuthKeyRoute <- R6::R6Class(
  "AuthKeyRoute",
  inherit = AuthRoute,
  public = list(
    initialize = function(
      name,
      key,
      secret,
      cookie = TRUE,
      ignore_trailing_slash = FALSE
    ) {
      super$initialize(
        name = name,
        ignore_trailing_slash = ignore_trailing_slash
      )
      check_string(key)
      private$KEY <- key
      check_string(secret)
      private$SECRET <- secret
      check_bool(cookie)
      private$COOKIE <- cookie
      private$SCHEME <- "apiKey"
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
    COOKIE = TRUE,

    validator = function(request, response) {
      auth <- if (private$COOKIE) {
        request$headers[[private$KEY]]
      } else {
        request$cookies[[private$KEY]]
      }
      if (auth != private$SECRET) {
        reqres::abort_status(400L)
      }
      TRUE
    }
  )
)
