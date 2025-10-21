#' R6 base class for authentication schemes
#'
#' @description
#' All schemes inherit from this base class and adapts it for the particular
#' scheme it implements. Additional schemes can be implemented as subclasses of
#' this and will work transparently with fireproof.
#'
#' @export
Auth <- R6::R6Class(
  "Auth",
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
    #'
    check_request = function(request, response, keys, ...) {
      TRUE
    },
    #' @description Action to perform on the response in case the request fails
    #' to get validated by any instance in the flow. All failing instances will
    #' have this method called one by one so be mindful if you are overwriting
    #' information set by another instance
    #' @param response The response object
    #' @param scope The scope of the endpoint
    reject_response = function(response, scope) {
      response$status <- 400L
    },
    #' @description Action to perform on the response in case the request does
    #' not have the necessary permissions for the endpoint. All succeeding
    #' instances will have this method called one by one if permissions are
    #' insufficient so be mindful if you are overwriting information set by
    #' another instance
    #' @param response The response object
    #' @param scope The scope of the endpoint
    forbid_user = function(response, scope) {
      response$status <- 403L
    }
  ),
  active = list(
    #' @field name The name of the instance
    name = function() {
      private$NAME
    }
  ),
  private = list(
    NAME = NULL
  )
)

#' @rdname Auth
#' @param x An object
is_auth <- function(x) inherits(x, "Auth")
