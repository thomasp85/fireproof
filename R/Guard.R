#' R6 base class for guards
#'
#' @description
#' All guards inherit from this base class and adapts it for the particular
#' scheme it implements. Additional schemes can be implemented as subclasses of
#' this and will work transparently with fireproof.
#'
#' @export
#'
#' @examples
#' # You'd never actually do this, rather you'd use the subclasses
#' guard <- Guard$new(name = "base_auth")
#'
Guard <- R6::R6Class(
  "Guard",
  public = list(
    #' @description Constructor for the class
    #' @param name The name of the scheme instance
    initialize = function(name = NULL) {
      check_string(name, allow_null = TRUE)
      private$NAME <- name
    },
    #' @description A function that validates an incoming request, returning
    #' `TRUE` if it is valid and `FALSE` if not. The base class simply returns
    #' `TRUE` for all requests
    #' @param request The request to validate as a [Request][reqres::Request]
    #' object
    #' @param response The corresponding response to the request as a
    #' [Response][reqres::Response] object
    #' @param keys A named list of path parameters from the path matching
    #' @param ... Ignored
    #' @param .session The session storage for the current session
    #'
    check_request = function(request, response, keys, ..., .session) {
      TRUE
    },
    #' @description Action to perform on the response in case the request fails
    #' to get validated by any instance in the flow. All failing instances will
    #' have this method called one by one so be mindful if you are overwriting
    #' information set by another instance
    #' @param response The response object
    #' @param scope The scope of the endpoint
    #' @param ... Ignored
    #' @param .session The session storage for the current session
    reject_response = function(response, scope, ..., .session) {
      .session[[private$NAME]] <- NULL
      response$status_with_text(400L)
    },
    #' @description Action to perform on the response in case the request does
    #' not have the necessary permissions for the endpoint. All succeeding
    #' instances will have this method called one by one if permissions are
    #' insufficient so be mindful if you are overwriting information set by
    #' another instance
    #' @param response The response object
    #' @param scope The scope of the endpoint
    #' @param ... Ignored
    #' @param .session The session storage for the current session
    forbid_user = function(response, scope, ..., .session) {
      .session[[private$NAME]] <- NULL
      response$status_with_text(403L)
    },
    #' @description Hook for registering endpoint handlers needed for this
    #' auth method
    #' @param add_handler The `add_handler` method from [Fireproof] to be called
    #' for adding additional handlers
    register_handler = function(add_handler) {
      invisible(NULL)
    }
  ),
  active = list(
    #' @field name The name of the instance
    name = function(value) {
      if (missing(value)) {
        return(private$NAME)
      }
      check_string(value)
      private$NAME <- value
      invisible()
    },
    #' @field open_api An OpenID compliant security scheme description
    open_api = function() {
      list()
    }
  ),
  private = list(
    NAME = NULL
  )
)

#' @rdname Guard
#' @param x An object
#' @export
is_guard <- function(x) inherits(x, "Guard")
