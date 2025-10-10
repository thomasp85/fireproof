AuthRoute <- R6::R6Class(
  "AuthRoute",
  inherit = routr::Route,
  public = list(
    initialize = function(name, ignore_trailing_slash = FALSE) {
      super$initialize(ignore_trailing_slash = ignore_trailing_slash)
      check_string(name)
      private$NAME <- name
    },
    add_handler = function(method, path) {
      validator <- private$validator

      super$add_handler(
        method,
        path,
        handler = function(request, response, keys, ...) {
          validator(request, response)
        }
      )
    }
  ),
  active = list(
    name = function() {
      paste0("auth_", private$NAME)
    },
    scheme = function() {
      private$SCHEME
    },
    scope = function() {
      private$SCOPE
    }
  ),
  private = list(
    NAME = NULL,
    SCHEME = NULL,
    SCOPE = list(),

    validator = function(request, response) {
      TRUE
    }
  )
)
