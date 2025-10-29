#' Authentication based on OAuth 2.0
#'
#' OAuth 2.0 is an authorization scheme that is powering much of the modern
#' internet and is behind things like "log in with GitHub" etc. It separates the
#' responsibility of authentication away from the server, and allows a user to
#' grant limited access to a service on the users behalf. While OAuth also
#' allows a server to make request on the users behalf the main purpose in the
#' context of `fireproof` is to validate that the user can perform a successful
#' login and potentially extract basic information about the user. The
#' `auth_oauth2()` function is the base constructor which can be used to create
#' authenticators with any provider. For ease of use `fireproof` comes with a
#' range of predefined constructors for popular services such as GitHub, Google
#' etc. Central for all of these is the need for your server to register itself
#' with the provider and get a client id and a client secret which must be used
#' when logging users in.
#'
#' @param token_url The URL to the authorization servers token endpoint
#' @param redirect_url The URL the authorization server should redirect to
#' following a successful authorization. Must be equivalent to one provided
#' when registering your application
#' @param client_id The ID issued by the authorization server when
#' registering your application
#' @param client_secret The secret issued by the authorization server when
#' registering your application. Do NOT store this in plain text
#' @param auth_url The URL to redirect the user to when requesting
#' authorization (only needed for `grant_type = "authorization_code"`)
#' @param grant_type The type of authorization scheme to use, either
#' `"authorization_code"` or `"password"`
#' @param scopes Optional character vector of scopes to request the user to
#' grant you during authorization
#' @param validate Function to validate the user once logged in. It will be
#' called with a single argument `info`, which gets the information of the user
#' as provided by the `user_info` function in the. By default it returns `TRUE`
#' on everything meaning that anyone who can log in with the provider will
#' be accepted, but you can provide a different function to e.g. restrict
#' access to certain user names etc.
#' @param redirect_path The path that should capture redirects after
#' successful authorization. By default this is derived from `redirect_url`
#' by removing the domain part of the url, but if for some reason this
#' doesn't yields the correct result for your server setup you can overwrite
#' it here.
#' @param on_auth A function which will handle the result of a successful
#' authorization. It will be called with four arguments: `request`, `response`,
#' `session_state`, and `server`. The first contains the current request
#' being responded to, the second is the response being send back, the third
#' is a list recording the state of the original request which initiated the
#' authorization (containing `method`, `url`, `headers`, and `body` fields
#' with information from the original request). By default it will use
#' [replay_request] to internally replay the original request and send back
#' the response.
#' @param user_info A function to extract user information from the
#' authorization provider. It will be called with two arguments: `token_info`
#' and `setter`, the first being the token information returned from the
#' provider as a list (notably with a `token` field for the actual token), the
#' second being a function that must be called in the end with the relevant
#' information. The `setter` function takes the following arguments:
#' `provider` (the name of the oauth2 provider), `id` (the identifier of the
#' user), `display_name` (the name the user has chosen as public name),
#' `name_given` (the users real given name), `name_middle` (the users middle
#' name), `name_family` (the users family name), `emails` (a vector of
#' emails, potentially named with type, e.g. "work", "home" etc), `photos`
#' (a vector of urls for profile photos), and `...` with additional named
#' fields to add
#' @param service_params A named list of additional query params to add to
#' the url when constructing the authorization url in the
#' `"authorization_code"` grant type
#' @param name The name of the scheme instance. This will also be the name
#' under which token info and user info is saved in the session store
#'
#' @return An [AuthOAuth2] object
#'
#' @export
#' @importFrom urltools url_encode
#'
#' @examples
#' # Example using GitHub endpoints (use `auth_github()` in real code)
#' github <- auth_oauth2(
#'   token_url = "https://github.com/login/oauth/access_token",
#'   redirect_url = "https://example.com/auth",
#'   client_id = "MY_APP_ID",
#'   client_secret = "SUCHASECRET",
#'   auth_url = "https://github.com/login/oauth/authorize",
#'   grant_type = "authorization_code"
#' )
#'
#' # Add it to a fireproof plugin
#' fp <- Fireproof$new()
#' fp$add_auth(github, "github_auth")
#'
#' # Use it in an endpoint
#' fp$add_auth_handler("get", "/*", github_auth)
#'
auth_oauth2 <- function(
  token_url,
  redirect_url,
  client_id,
  client_secret,
  auth_url = NULL,
  grant_type = c("authorization_code", "password"),
  scopes = NULL,
  validate = function(info) TRUE,
  redirect_path = sub("^.*?(?=(?<!:/?)/)", "", redirect_url, perl = TRUE),
  on_auth = replay_request,
  user_info = NULL,
  service_params = list(),
  name = "OAuth2Auth"
) {
  AuthOAuth2$new(
    token_url = token_url,
    redirect_url = redirect_url,
    client_id = client_id,
    client_secret = client_secret,
    auth_url = auth_url,
    grant_type = grant_type,
    scopes = scopes,
    validate = validate,
    redirect_path = redirect_path,
    on_auth = on_auth,
    user_info = user_info,
    service_params = service_params,
    name = name
  )
}

#' R6 class for the OAuth 2.0 authentication scheme
#'
#' @description
#' This class encapsulates the logic of the oauth 2.0 based authentication
#' scheme. See [auth_oauth2()] for more information
#'
#' @export
#'
#' @examples
#' # Example using GitHub endpoints (use `auth_github()` in real code)
#' github <- AuthOAuth2$new(
#'   token_url = "https://github.com/login/oauth/access_token",
#'   redirect_url = "https://example.com/auth",
#'   client_id = "MY_APP_ID",
#'   client_secret = "SUCHASECRET",
#'   auth_url = "https://github.com/login/oauth/authorize",
#'   grant_type = "authorization_code"
#' )
#'
AuthOAuth2 <- R6::R6Class(
  "AuthOAuth2",
  inherit = Auth,
  public = list(
    #' @description Constructor for the class
    #' @param token_url The URL to the authorization servers token endpoint
    #' @param redirect_url The URL the authorization server should redirect to
    #' following a successful authorization. Must be equivalent to one provided
    #' when registering your application
    #' @param client_id The ID issued by the authorization server when
    #' registering your application
    #' @param client_secret The secret issued by the authorization server when
    #' registering your application. Do NOT store this in plain text
    #' @param auth_url The URL to redirect the user to when requesting
    #' authorization (only needed for `grant_type = "authorization_code"`)
    #' @param grant_type The type of authorization scheme to use, either
    #' `"authorization_code"` or `"password"`
    #' @param scopes Optional character vector of scopes to request the user to
    #' grant you during authorization
    #' @param validate Function to validate the user once logged in. It will be
    #' called with a single argument `info`, which gets the information of the user
    #' as provided by the `user_info` function in the. By default it returns `TRUE`
    #' on everything meaning that anyone who can log in with the provider will
    #' be accepted, but you can provide a different function to e.g. restrict
    #' access to certain user names etc.
    #' @param redirect_path The path that should capture redirects after
    #' successful authorization. By default this is derived from `redirect_url`
    #' by removing the domain part of the url, but if for some reason this
    #' doesn't yields the correct result for your server setup you can overwrite
    #' it here.
    #' @param on_auth A function which will handle the result of a successful
    #' authorization. It will be called with four arguments: `request`, `response`,
    #' `session_state`, and `server`. The first contains the current request
    #' being responded to, the second is the response being send back, the third
    #' is a list recording the state of the original request which initiated the
    #' authorization (containing `method`, `url`, `headers`, and `body` fields
    #' with information from the original request). By default it will use
    #' [replay_request] to internally replay the original request and send back
    #' the response.
    #' @param user_info A function to extract user information from the
    #' authorization provider. It will be called with two arguments: `token_info`
    #' and `setter`, the first being the token information returned from the
    #' provider as a list (notably with a `token` field for the actual token), the
    #' second being a function that must be called in the end with the relevant
    #' information. The `setter` function takes the following arguments:
    #' `provider` (the name of the oauth2 provider), `id` (the identifier of the
    #' user), `display_name` (the name the user has chosen as public name),
    #' `name_given` (the users real given name), `name_middle` (the users middle
    #' name), `name_family` (the users family name), `emails` (a vector of
    #' emails, potentially named with type, e.g. "work", "home" etc), `photos`
    #' (a vector of urls for profile photos), and `...` with additional named
    #' fields to add
    #' @param service_params A named list of additional query params to add to
    #' the url when constructing the authorization url in the
    #' `"authorization_code"` grant type
    #' @param name The name of the scheme instance. This will also be the name
    #' under which token info and user info is saved in the session store
    initialize = function(
      token_url,
      redirect_url,
      client_id,
      client_secret,
      auth_url = NULL,
      grant_type = c("authorization_code", "password"),
      scopes = NULL,
      validate = function(info) TRUE,
      redirect_path = sub(
        "^.*?(?=(?<!:/?)/)",
        "",
        redirect_url,
        perl = TRUE
      ),
      on_auth = replay_request,
      user_info = NULL,
      service_params = list(),
      name = NULL
    ) {
      super$initialize(
        name = name
      )
      private$GRANT_TYPE <- arg_match(grant_type)
      if (private$GRANT_TYPE == "authorization_code") {
        check_string(auth_url)
      }
      private$AUTH_URL <- auth_url
      check_string(token_url)
      private$TOKEN_URL <- token_url
      check_string(client_id)
      private$CLIENT_ID <- client_id
      check_string(client_secret)
      private$CLIENT_SECRET <- client_secret
      check_string(redirect_url)
      private$REDIRECT_URL <- redirect_url
      check_string(redirect_path)
      private$REDIRECT_PATH <- redirect_path
      check_character(scopes, allow_null = TRUE)
      private$SCOPES <- scopes

      check_function(validate)
      private$VALIDATE <- with_dots(validate)
      check_function(on_auth)
      private$ON_AUTH <- with_dots(on_auth)

      user_info <- user_info %||%
        function(token_info, setter) {
          setter()
        }
      check_function(user_info)
      private$USER_INFO <- with_dots(user_info)
      if (!is.list(service_params) || !is_named2(service_params)) {
        stop_input_type(service_params, "a named list")
      }
      private$SERVICE_PARAMS <- service_params
    },
    #' @description A function that validates an incoming request, returning
    #' `TRUE` if it is valid and `FALSE` if not. It extracts the secret from
    #' either the cookie or header based on the provided `key` and test it
    #' against the provided `secret`.
    #' @param request The request to validate as a [Request][reqres::Request]
    #' object
    #' @param response The corresponding response to the request as a
    #' [Response][reqres::Response] object
    #' @param keys A named list of path parameters from the path matching
    #' @param server The fiery server handling the request
    #' @param arg_list A list of additional arguments extracted be the
    #' `before_request` handlers (will be used to access the session data store)
    #' @param ... Ignored
    #' @param .session The session storage for the current session
    #'
    check_request = function(request, response, keys, ..., .session) {
      info <- .session[[private$NAME]]
      !is.null(info) && private$VALIDATE(info = info)
    },
    #' @description Upon rejection this scheme sets the response status to `400`
    #' if it has not already been set by others. In contrast to the other
    #' schemes that are proper HTTP schemes, this one doesn't set a
    #' `WWW-Authenticate` header.
    #' @param response The response object
    #' @param scope The scope of the endpoint
    #' @param ... Ignored
    #' @param .session The session storage for the current session
    reject_response = function(response, scope, ..., .session) {
      if (!is.null(.session[[private$NAME]])) {
        .session[[private$NAME]] <- NULL
        response$status_with_text(403L)
      } else {
        private$request_authorization(response$request, response, .session)
      }
    },
    #' @description Hook for registering endpoint handlers needed for this
    #' authentication method
    #' @param add_handler The `add_handler` method from [Fireproof] to be called
    #' for adding additional handlers
    register_handler = function(add_handler) {
      add_handler(
        "get",
        private$REDIRECT_PATH,
        function(request, response, keys, server, arg_list, ...) {
          session <- arg_list[[server$plugins$firesale$arg_name]]$session
          private$exchange_code_to_token(request, response, session)
        }
      )
    }
  ),
  active = list(
    #' @field location The location of the secret in the request, either
    #' `"cookie"` or `"header"`
    location = function() {
      if (private$COOKIE) "cookie" else "header"
    },
    #' @field open_api An OpenID compliant security scheme description
    open_api = function() {
      list(
        type = "oauth2",
        flows = if (private$GRANT_TYPE == "authorization_code") {
          list(
            authorizationCode = list(
              authorizationUrl = private$AUTH_URL,
              tokenUrl = private$TOKEN_URL,
              refreshUrl = private$TOKEN_URL,
              scopes = set_names(rep_along(private$SCOPES, ""), private$SCOPES)
            )
          )
        } else {
          list(
            password = list(
              tokenUrl = private$TOKEN_URL,
              refreshUrl = private$TOKEN_URL,
              scopes = set_names(rep_along(private$SCOPES, ""), private$SCOPES)
            )
          )
        }
      )
    }
  ),
  private = list(
    CLIENT_ID = "",
    CLIENT_SECRET = "",
    COOKIE = TRUE,
    AUTH_URL = "",
    TOKEN_URL = "",
    REDIRECT_URL = "",
    REDIRECT_PATH = "",
    GRANT_TYPE = "",
    SCOPES = NULL,
    VALIDATE = NULL,
    ON_AUTH = NULL,
    USER_INFO = NULL,
    SERVICE_PARAMS = list(),

    construct_auth_url = function(request, state) {
      paste0(
        private$AUTH_URL,
        "?response_type=code&client_id=",
        private$CLIENT_ID,
        "&state=",
        state,
        "&redirect_uri=",
        urltools::url_encode(private$REDIRECT_URL),
        "&code_challenge=",
        url_safe_raw(sodium::sha256(state$verifier)),
        "&code_challenge_method=S256",
        if (!is.null(private$SCOPES)) {
          paste0(
            "&scope=",
            urltools::url_encode(paste0(private$SCOPES, collapse = "%20"))
          )
        },
        paste0(
          paste(
            names(private$SERVICE_PARAMS),
            urltools::url_encode(
              unlist(private$SERVICE_PARAMS) %||% character(0)
            ),
            sep = "="
          ),
          collapse = "&"
        )
      )
    },
    request_authorization = function(request, response, session) {
      if (private$GRANT_TYPE == "authorization_code") {
        # Logic for authorization code type
        state <- create_session_state(request, session)
        auth_url <- private$construct_auth_url(request, state)
        response$status <- 303L # Force client to use GET
        response$set_header("location", auth_url)
      } else if (private$GRANT_TYPE == "password") {
        # Logic for password type
        auth <- request$headers$authorization
        if (!is.null(auth) && grepl("^Basic ", auth)) {
          auth <- sub("^Basic ", "", auth)
          auth <- base64decode(auth)
          auth <- strsplit(auth, ":", fixed = TRUE)[[1]]
          if (length(auth) != 2) {
            reqres::abort_bad_request("Malformed Authorization header")
          }
        } else {
          response$append_header(
            "WWW-Authenticate",
            paste0('Basic realm="oauth2", charset=UTF-8')
          )
          reqres::abort_status(401L)
        }
        token_par <- list(
          grant_type = "password",
          username = auth[[1]],
          password = auth[[2]],
          scope = paste0(private$SCOPES, collapse = " "),
          client_id = private$CLIENT_ID,
          client_secret = private$CLIENT_SECRET
        )
        private$request_token(token_par, session)
        if (!private$VALIDATE(info = session[[private$NAME]])) {
          self$reject_response(response, .session = session)
        } else {
          response$status <- 200L
        }
      }
    },
    exchange_code_to_token = function(request, response, session) {
      session_state <- session$oauth_state
      session$oauth_state <- NULL
      state <- request$query$state
      if (
        state != session_state$state ||
          Sys.time() > session_state$time + 3600
      ) {
        reqres::abort_bad_request("Invalid state parameter")
      }
      error <- request$query$error
      if (!is.null(error)) {
        abort_authorization_error(
          error,
          request$query$error_description,
          request$query$error_uri
        )
      }
      token_par <- list(
        grant_type = private$GRANT_TYPE,
        code = request$query$code,
        client_id = private$CLIENT_ID,
        client_secret = private$CLIENT_SECRET,
        code_verifier = session_state$verifier
      )
      if (!is.null(private$REDIRECT_URL)) {
        token_par$redirect_uri <- private$REDIRECT_URL
      }
      private$request_token(token_par, session, session_state)
      if (!private$VALIDATE(info = session[[private$NAME]])) {
        self$reject_response(response, .session = session)
      } else {
        private$ON_AUTH(
          request = request,
          response = response,
          session_state = session_state,
          server = server
        )
      }
    },
    request_token = function(token_par, session, session_state = NULL) {
      ch <- curl::new_handle()
      curl::handle_setopt(ch, post = 1)
      curl::handle_setform(ch, .list = token_par)
      res <- curl_fetch_memory(private$TOKEN_URL, ch)
      content <- jsonlite::parse_json(rawToChar(res$content))
      if (res$status_code != 200L) {
        abort_auth(paste0(
          c(content$error, content$error_description, content$error_uri),
          collapse = ": "
        ))
      }
      if (!is.null(content$scope)) {
        content$scope <- strsplit(content$scope, " ", fixed = TRUE)[[1]]
      }
      private$USER_INFO(
        token_info = content,
        setter = oauth_user_info_setter(
          session,
          private$NAME,
          content,
          content$scope %||% private$SCOPES
        )
      )
    }
  )
)

create_session_state = function(request, session) {
  request_state <- list(
    state = url_safe_raw(sodium::random(32)),
    verifier = url_safe_raw(sodium::random(32)),
    nonce = url_safe_raw(sodium::random(32)),
    time = Sys.time(),
    method = request$method,
    url = request$url,
    headers = request$headers,
    body = request$body_raw,
    from = request$ip
  )
  session$oauth_state <- request_state
  request_state$state
}

url_safe_raw <- function(x) {
  x <- base64enc::base64encode(x)
  gsub("=+$", "", x, perl = TRUE)
  gsub("+", "-", x, fixed = TRUE)
  gsub("/", "_", x, fixed = TRUE)
}

oauth_user_info_setter <- function(session, name, token, scopes) {
  function(
    provider = NULL,
    id = NULL,
    display_name = NULL,
    name_given = NULL,
    name_middle = NULL,
    name_family = NULL,
    emails = character(0),
    photos = character(0),
    ...
  ) {
    session[[name]] <- list2(
      provider = provider,
      id = id,
      display_name = display_name,
      name = c(given = name_given, middle = name_middle, family = name_family),
      emails = emails,
      photos = photos,
      scopes = scopes,
      token = token,
      ...
    )
  }
}

abort_authorization_error <- function(error, detail, uri, call = caller_env()) {
  switch(
    error,
    invalid_request = reqres::abort_http_problem(
      400L,
      detail %||%
        "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed",
      title = error,
      type = uri,
      call = call
    ),
    unauthorized_client = reqres::abort_http_problem(
      400L,
      detail %||%
        "The client is not authorized to request an authorization code using this method",
      title = error,
      type = uri,
      call = call
    ),
    access_denied = reqres::abort_http_problem(
      403L,
      detail %||%
        "The resource owner or authorization server denied the request",
      title = error,
      type = uri,
      call = call
    ),
    unsupported_response_type = reqres::abort_http_problem(
      400L,
      detail %||%
        "The authorization server does not support obtaining an authorization code using this method",
      title = error,
      type = uri,
      call = call
    ),
    invalid_scope = reqres::abort_http_problem(
      400L,
      detail %||% "The requested scope is invalid, unknown, or malformed",
      title = error,
      type = uri,
      call = call
    ),
    server_error = reqres::abort_http_problem(
      503L,
      detail %||%
        "The authorization server encountered an unexpected condition that prevented it from fulfilling the request",
      title = error,
      type = uri,
      call = call
    ),
    temporarily_unavailable = reqres::abort_http_problem(
      503L,
      detail %||%
        "The authorization server is currently unable to handle the request due to a temporary overloading or maintenance of the server",
      title = error,
      type = uri,
      call = call
    ),
    reqres::abort_bad_request(
      detail %||% "Unknown error",
      title = error,
      type = uri,
      call = call
    )
  )
}
