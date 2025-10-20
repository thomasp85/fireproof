Auth <- R6::R6Class(
  "Auth",
  public = list(
    initialize = function(name) {
      check_string(name, allow_null = TRUE)
      private$NAME <- name
    },
    check_request = function(request, response, keys, ...) {
      TRUE
    },
    reject_response = function(response) {
      response$status <- 400L
    }
  ),
  active = list(
    name = function() {
      private$NAME
    }
  ),
  private = list(
    NAME = NULL
  )
)
