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
#' # User information
#' `auth_bearer()` automatically adds [user information][user_info] after
#' authentication. By default it will set the `provider` field to `"local"`.
#' Further, it will set the `scopes` field to any scopes returned by the
#' `authenticator` function and the `token` field to a list with the following
#' elements:
#'
#' - `access_token`: The provided token
#' - `token_type`: `"bearer"`
#' - `scope` The scopes concatenated into a space separated string
#'
#' This structure mimics the structure of the token information returned by
#' OAuth 2.0 and OpenID Connect services.
#'
#' @param authenticator A function that will be called with the arguments
#' `token`, `realm`, `request`, and `response` and returns `TRUE` if the token
#' is valid, and `FALSE` otherwise. If the function returns a character vector
#' it is considered to be authenticated and the return value will be understood
#' as scopes the user is granted.
#' @param name The name of the authentication
#' @param user_info A function to extract user information from the
#' username. It is called with two arguments: `token` and `setter`,
#' the first being the token used for the successful authentication, the
#' second being a function that must be called in the end with the relevant
#' information (see [user_info()]).
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
#' to the `authenticator` function.
#'
#' @return An [AuthBearer] R6 object
#'
#' @export
#'
#' @examples
#' # Create an authenticator of dubious quality
#' bearer <- auth_bearer(
#'   authenticator = function(token) {
#'     token == "abcd1234"
#'   },
#'   user_info = function(user, setter) {
#'     setter(
#'       name_given = "Thomas",
#'       name_middle = "Lin",
#'       name_family = "Pedersen"
#'     )
#'   },
#'   allow_body_token = FALSE
#' )
#'
#' # Add it to a fireproof plugin
#' fp <- Fireproof$new()
#' fp$add_auth(bearer, "bearer_auth")
#'
#' # Use it in an endpoint
#' fp$add_auth_handler("get", "/*", bearer_auth)
#'
auth_bearer <- function(
  authenticator,
  user_info = NULL,
  realm = "private",
  allow_body_token = TRUE,
  allow_query_token = FALSE,
  name = "BearerAuth"
) {
  AuthBearer$new(
    authenticator = authenticator,
    user_info = user_info,
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
#' @examples
#' # Create an authenticator of dubious quality
#' bearer <- AuthBearer$new(
#'   authenticator = function(token) {
#'     token == "abcd1234"
#'   },
#'   user_info = function(user, setter) {
#'     setter(
#'       name_given = "Thomas",
#'       name_middle = "Lin",
#'       name_family = "Pedersen"
#'     )
#'   }
#' )
#'
AuthBearer <- R6::R6Class(
  "AuthBearer",
  inherit = Auth,
  public = list(
    #' @description Constructor for the class
    #' @param authenticator A function that will be called with the arguments
    #' `token`, `realm`, `request`, and `response` and returns `TRUE` if the token
    #' is valid, and `FALSE` otherwise. If the function returns a character vector
    #' it is considered to be authenticated and the return value will be understood
    #' as scopes the user is granted.
    #' @param user_info A function to extract user information from the
    #' username. It is called with two arguments: `token` and `setter`,
    #' the first being the token used for the successful authentication, the
    #' second being a function that must be called in the end with the relevant
    #' information (see [user_info()]).
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
      user_info = NULL,
      realm = "private",
      allow_body_token = TRUE,
      allow_query_token = FALSE,
      name = NULL
    ) {
      super$initialize(
        name = name
      )
      check_function(authenticator)
      private$AUTHENTICATOR <- with_dots(authenticator)
      check_string(realm)
      private$REALM <- realm

      user_info <- user_info %||%
        function(token, setter) {
          setter()
        }
      check_function(user_info)
      private$USER_INFO <- with_dots(user_info)

      check_bool(allow_body_token)
      private$ALLOW_BODY <- allow_body_token
      check_bool(allow_query_token)
      private$ALLOW_QUERY <- allow_query_token
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
    #' @param .session The session storage for the current session
    #'
    check_request = function(request, response, keys, ..., .session) {
      info <- .session[[private$NAME]]

      if (length(info) == 0) {
        token <- list()
        auth_header <- request$headers$authorization
        if (
          !is.null(auth_header) &&
            grepl("^Bearer ", auth_header)
        ) {
          token$header <- sub("^Bearer ", "", auth_header)
        }
        if (
          private$ALLOW_BODY &&
            request$method %in% c("post", "put", "patch") &&
            request$is("application/x-www-form-urlencoded")
        ) {
          success <- request$parse(
            "application/x-www-form-urlencoded" = reqres::parse_queryform(),
            autofail = FALSE
          )
          if (success) token$body <- trimws(request$body$access_token)
        }
        if (
          private$ALLOW_QUERY &&
            grepl("no-store", request$headers$cache_control %||% "")
        ) {
          token$query <- request$query$access_token
          if (!is.null(token$query)) {
            response$set_header("Cache-Control", "private")
          }
        }
        token <- unlist(token)
        if (length(token) > 1) {
          reqres::abort_http_problem(
            400L,
            "Clients MUST NOT use more than one method to transmit a bearer token",
            type = "https://datatracker.ietf.org/doc/html/rfc6750#section-2"
          )
        }
        scopes <- private$SCOPES %||% character()
        if (length(token) == 1) {
          authenticated <- private$AUTHENTICATOR(
            token = token,
            realm = private$REALM,
            request = request,
            response = response
          )
          if (is.character(authenticated)) {
            scopes <- authenticated
            authenticated <- TRUE
          }
        } else {
          authenticated <- FALSE
        }
        if (authenticated) {
          private$USER_INFO(
            token = token,
            setter = bearer_user_info_setter(
              .session,
              private$NAME,
              token,
              scopes
            )
          )
        } else {
          .session[[private$NAME]] <- list()
        }
        authenticated
      } else {
        TRUE
      }
    },
    #' @description Upon rejection this scheme sets the response status to `401`
    #' and sets the `WWW-Authenticate` header to `Bearer realm="<realm>"`. If
    #' any scope is provided by the endpoint it will be appended as
    #' `, scope="<scope>"` and if the token is present but invalid, it will
    #' append `, error="invalid_token"`
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
            paste0(
              'Bearer realm="',
              private$REALM,
              '"',
              if (!is.null(scope)) {
                paste0(', scope="', paste0(scope, collapse = " "), '"')
              },
              if (!is.null(response$get_data("token"))) {
                paste0(', error="invalid_token"')
              }
            )
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
        scheme = "bearer"
      )
    }
  ),
  private = list(
    AUTHENTICATOR = NULL,
    REALM = "",
    USER_INFO = NULL,
    ALLOW_BODY = TRUE,
    ALLOW_QUERY = FALSE
  )
)

bearer_user_info_setter <- function(session, name, token, scopes) {
  function(
    provider = "local",
    id = NULL,
    name_display = NULL,
    name_given = NULL,
    name_middle = NULL,
    name_family = NULL,
    emails = NULL,
    photos = NULL,
    ...
  ) {
    session[[name]] <- user_info(
      provider = provider,
      id = id,
      name_display = name_display,
      name_given = name_given,
      name_middle = name_middle,
      name_family = name_family,
      emails = emails,
      photos = photos,
      scopes = scopes,
      token = list(
        access_token = token,
        token_type = "bearer",
        scope = paste0(scopes, collapse = " ")
      ),
      ...
    )
  }
}
