#' Bearer authentication plugin
#'
#' Bearer authentication is a HTTP scheme powers most of the modern web
#' authentication as it is the foundation for OAuth 2.0 and OpenID. It is a
#' quite simple scheme that is based on the concept of tome and scope limited
#' bearer tokens. Whoever has a valid token gains access to the resources the
#' token unlocks. This prevents the leaking of passwords s well as make it easy
#' to rotate tokens etc. While the time-limited aspect of tokens means that an
#' attacker may only gain temporary access to a resource if they intercept a
#' token during transmission, it is still highly recommended to only transmit
#' tokens over HTTPS
#'
#' @details
#' This authenticator will use a user provided function to test a token. The
#' complexity of the test fully depends on the issuer of the token. At it's
#' simplest the token is opaque and the function test it against a database.
#' However, it is more common to use a JSON web token to encode various
#' information into the token itself that can help in determining scoped access
#' etc.
#'
#' The authenticator should in general not test the scope of the token, but
#' rather write the scope of the token to the `auth_scope` field of the response
#' data store (`response$set_data("auth_scope", ...)`). The scope requirement of
#' the exact endpoint will then be tested automatically. Further, the
#' authenticator should write any additional user information that gets fetched
#' during the validation to relevant fields in the response data
#'
#' @param authenticator A function that takes a token, realm, request, and
#' response and returns `TRUE` if the token is valid, and `FALSE`
#' otherwise. If the function sets a character vector of scopes for the token in
#' the `auth_scope` field of the response data
#' (`response$set_data("auth_scope", ...)`) then it will be tested against the
#' scopes needed for the specific endpoint
#' @param name The name of the authentication
#' @param realm The realm this authentication corresponds to. Will be returned
#' to the client on a failed authentication attempt to inform them of the
#' credentials required, though most often these days it is kept from the user.
#' @param allow_body_token Should it be allowed to pass the token in the request
#' body as a query form type with the `access_token` name. Defaults to `TRUE`
#' but you can turn it off to force the client to use the `Authorization`
#' header.
#' @param allow_query_token Should it be allowed to pass the token in the query
#' string of the url with the `access_token` name. Default to `FALSE` due to
#' severe security implications but can be turned on if you have very
#' well-thought-out reasons to do so.
#'
#' @return An [AuthBearer] R6 object
#'
#' @export
#'
auth_bearer <- function(
  authenticator,
  name = "BearerAuth",
  realm = "private",
  allow_body_token = TRUE,
  allow_query_token = FALSE
) {
  AuthBasic$new(
    authenticator = authenticator,
    realm = realm,
    allow_body_token = allow_body_token,
    allow_query_token = allow_query_token,
    name = name
  )
}

#' R6 class for the Bearer authentication scheme
#'
#' @description
#' This class encapsulates the logic of the
#' [Bearer authentication scheme](https://datatracker.ietf.org/doc/html/rfc6750).
#' See [auth_bearer()] for more information.
#'
#' @export
#'
AuthBearer <- R6::R6Class(
  "AuthBearer",
  inherit = Auth,
  public = list(
    #' @description Constructor for the class
    #' @param authenticator A function that takes a token, realm, request, and
    #' response and returns `TRUE` if the token is valid, and `FALSE`
    #' otherwise. If the function sets a character vector of scopes for the token in
    #' the `auth_scope` field of the response data
    #' (`response$set_data("auth_scope", ...)`) then it will be tested against the
    #' scopes needed for the specific endpoint
    #' @param realm The realm this authentication corresponds to. Will be returned
    #' to the client on a failed authentication attempt to inform them of the
    #' credentials required, though most often these days it is kept from the user.
    #' @param allow_body_token Should it be allowed to pass the token in the request
    #' body as a query form type with the `access_token` name. Defaults to `TRUE`
    #' but you can turn it off to force the client to use the `Authorization`
    #' header.
    #' @param allow_query_token Should it be allowed to pass the token in the query
    #' string of the url with the `access_token` name. Default to `FALSE` due to
    #' severe security implications but can be turned on if you have very
    #' well-thought-out reasons to do so.
    #' @param name The name of the authentication
    initialize = function(
      authenticator,
      realm = "private",
      allow_body_token = TRUE,
      allow_query_token = FALSE,
      name = NULL
    ) {
      super$initialize(
        name = name
      )
      check_function(authenticator)
      if (length(fn_fmls(authenticator)) != 4 && !"..." %in% fn_fmls_names(authenticator)) {
        cli::cli_abort(
          "{.arg authenticator} must be a function with four arguments: `token`, `realm`, `request`, and `response`"
        )
      }
      private$AUTHENTICATOR <- authenticator
      check_string(realm)
      private$REALM <- realm
    },
    #' @description A function that validates an incoming request, returning
    #' `TRUE` if it is valid and `FALSE` if not. It fetches the token from the
    #' request according to the `allow_body_token` and `allow_query_token`
    #' settings and validates it according to the provided authenticator. If the
    #' token is present multiple times it will fail with `400` is this is not
    #' allowed. It will store the token in the `auth_token` field of the
    #' response data.
    #' @param request The request to validate as a [Request][reqres::Request]
    #' object
    #' @param response The corresponding response to the request as a
    #' [Response][reqres::Response] object
    #' @param keys A named list of path parameters from the path matching
    #' @param ... Ignored
    #'
    check_request = function(request, response, keys, ...) {
      token <- list()
      auth_header <- request$headers$authorization
      if (
        !is.null(auth_header) &&
          grepl("^Bearer ", auth_header)
      ) {
        token$header <- sub("^Bearer ", "", auth_header)
      }
      if (
        allow_body_token &&
          request$method %in% c("post", "put", "patch") &&
          request$is("application/x-www-form-urlencoded")
      ) {
        success <- request$parse(
          "application/x-www-form-urlencoded" = reqres::parse_queryform(),
          autofail = FALSE
        )
        if (success) token$body <- request$body$access_token
      }
      if (
        allow_query_token && grepl("no-store", request$headers$cache_control)
      ) {
        token$query <- request$query$access_token
        if (!is.null(token$query)) {
          response$set_header("Cache-Control", "private")
        }
      }
      token <- unlist(token)
      if (length(token) > 1) {
        response$append_header(
          "WWW-Authenticate",
          paste0(
            'Bearer realm="',
            private$REALM,
            '", error="invalid_request"'
          )
        )
        reqres::abort_http_problem(
          400L,
          "Clients MUST NOT use more than one method to transmit a bearer token",
          type = "https://datatracker.ietf.org/doc/html/rfc6750#section-2"
        )
      }
      response$set_data("auth_token", token)
      authenticated <- length(token) == 1 &&
        private$AUTHENTICATOR(token, private$REALM, request, response)
      authenticated
    },
    #' @description Upon rejection this scheme sets the response status to `401`
    #' and sets the `WWW-Authenticate` header to `Bearer realm="<realm>"`. If
    #' any scope is provided by the endpoint it will be appended as
    #' `, scope="<scope>"` and if the token is present but invalid, it will
    #' append `, error="invalid_token"`
    #' @param response The response object
    #' @param scope The scope of the endpoint
    reject_response = function(response, scope) {
      response$append_header(
        "WWW-Authenticate",
        paste0(
          'Bearer realm="',
          private$REALM,
          '"',
          if (!is.null(scope)) paste0(', scope="', paste0(scope, collapse = " "), '"'),
          if (!is.null(response$get_data("token"))) paste0(', error="invalid_token"')
        )
      )
      response$status <- 401L
    },
    #' @description Upon rejection due to insufficient permission this scheme
    #' sets the response to `403` and sets the `WWW-Authenticate` header to
    #' `Bearer realm="<realm>", scope="<scope>", error="insufficient_scope"`
    #' @param response The response object
    #' @param scope The scope of the endpoint
    forbid_user = function(response, scope) {
      response$append_header(
        "WWW-Authenticate",
        paste0(
          'Bearer realm="',
          private$REALM,
          '", scope="',
          paste0(scope, collapse = " "),
          '", error="insufficient_scope"'
        )
      )
      response$status <- 403L
    }
  ),
  private = list(
    AUTHENTICATOR = NULL,
    REALM = ""
  )
)
