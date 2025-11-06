#' Guard based on OAuth 2.0
#'
#' OAuth 2.0 is an authorization scheme that is powering much of the modern
#' internet and is behind things like "log in with GitHub" etc. It separates the
#' responsibility of authentication away from the server, and allows a user to
#' grant limited access to a service on the users behalf. While OAuth also
#' allows a server to make request on the users behalf the main purpose in the
#' context of `fireproof` is to validate that the user can perform a successful
#' login and potentially extract basic information about the user. The
#' `guard_oauth2()` function is the base constructor which can be used to create
#' guards with any provider. For ease of use `fireproof` comes with a
#' range of predefined constructors for popular services such as GitHub etc.
#' Central for all of these is the need for your server to register itself
#' with the provider and get a client id and a client secret which must be used
#' when logging users in.
#'
#' # User information
#' `guard_oauth2()` automatically adds some [user information][user_info] after
#' authentication, but it is advised to consult the service provider for more
#' information (this is done automatically for the provider specific
#' constructors. See their documentation for details about what information is
#' assigned to which field). The base constructor will set the `scopes` field to
#' any scopes returned by the provider during authorization. It will also set
#' the `token` field to a list with the token data provided by the service
#' during authorization. Some standard fields in the list are:
#'
#' - `access_token`: The actual token value
#' - `token_type`: The type of token (usually `"bearer"`)
#' - `expires_in`: The lifetime of the token in seconds
#' - `refresh_token`: A long-lived token that can be used to issue a new
#'   access token if the current becomes stale
#' - `timestamp`: The time the token was received
#'
#' But OAuth 2.0 providers may choose to supply more. Consult the documentation
#' for the provider to learn of additional fields it may provide.
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
#' grant you during authorization. If named, the names are taken as scopes and
#' the elements as descriptions of the scopes, e.g. given a scope, `read`, it
#' can either be provided as `c("read")` or `c(read = "Grant read access")`
#' @param validate Function to validate the user once logged in. It will be
#' called with a single argument `info`, which gets the information of the user
#' as provided by the `user_info` function in the. By default it returns `TRUE`
#' on everything meaning that anyone who can log in with the provider will
#' be accepted, but you can provide a different function to e.g. restrict
#' access to certain user names etc. If the function returns a
#' character vector it is considered to be authenticated and the return value
#' will be understood as scopes the user is granted.
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
#' access token. It is called with a single argument: `token_info` which is the
#' access token information returned by the OAuth 2 server after a successful
#' authentication. The function should return a new [user_info][new_user_info]
#' list.
#' @param service_params A named list of additional query params to add to
#' the url when constructing the authorization url in the
#' `"authorization_code"` grant type
#' @param name The name of the scheme instance. This will also be the name
#' under which token info and user info is saved in the session store
#'
#' @return An [GuardOAuth2] object
#'
#' @export
#' @importFrom urltools url_encode
#'
#' @examples
#' # Example using GitHub endpoints (use `guard_github()` in real code)
#' github <- guard_oauth2(
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
#' fp$add_guard(github, "github_auth")
#'
#' # Use it in an endpoint
#' fp$add_auth("get", "/*", github_auth)
#'
guard_oauth2 <- function(
  token_url,
  redirect_url,
  client_id,
  client_secret,
  auth_url = NULL,
  grant_type = c("authorization_code", "password"),
  scopes = NULL,
  validate = function(info) TRUE,
  redirect_path = get_path(redirect_url),
  on_auth = replay_request,
  user_info = NULL,
  service_params = list(),
  name = "OAuth2Auth"
) {
  GuardOAuth2$new(
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

#' R6 class for the OAuth 2.0 Guard
#'
#' @description
#' This class encapsulates the logic of the oauth 2.0 based authentication
#' scheme. See [guard_oauth2()] for more information
#'
#' @export
#'
#' @examples
#' # Example using GitHub endpoints (use `guard_github()` in real code)
#' github <- GuardOAuth2$new(
#'   token_url = "https://github.com/login/oauth/access_token",
#'   redirect_url = "https://example.com/auth",
#'   client_id = "MY_APP_ID",
#'   client_secret = "SUCHASECRET",
#'   auth_url = "https://github.com/login/oauth/authorize",
#'   grant_type = "authorization_code"
#' )
#'
GuardOAuth2 <- R6::R6Class(
  "GuardOAuth2",
  inherit = Guard,
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
    #' as provided by the `user_info` function. By default it returns `TRUE`
    #' on everything meaning that anyone who can log in with the provider will
    #' be accepted, but you can provide a different function to e.g. restrict
    #' access to certain user names etc. If the function returns a
    #' character vector it is considered to be authenticated and the return value
    #' will be understood as scopes the user is granted.
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
    #' access token. It is called with a single argument: `token_info` which is the
    #' access token information returned by the OAuth 2 server after a successful
    #' authentication. The function should return a new [user_info][new_user_info]
    #' list.
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
      redirect_path = get_path(redirect_url),
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
      if (is_named(scopes)) {
        private$SCOPES <- names(scopes)
        private$SCOPE_DESC <- unname(scopes)
      } else {
        private$SCOPES <- scopes
        private$SCOPE_DESC <- rep_along(scopes, "")
      }

      check_function(validate)
      private$VALIDATE <- with_dots(validate)
      check_function(on_auth)
      private$ON_AUTH <- with_dots(on_auth)

      user_info <- user_info %||%
        function(token_info) {
          new_user_info()
        }
      check_function(user_info)
      private$USER_INFO <- with_dots(user_info)
      if (!is.list(service_params) || !is_named2(service_params)) {
        stop_input_type(service_params, "a named list")
      }
      private$SERVICE_PARAMS <- service_params
    },
    #' @description A function that validates an incoming request, returning
    #' `TRUE` if it is valid and `FALSE` if not.
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
      is_user_info(.session[[private$NAME]])
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
          private$exchange_code_to_token(request, response, session, server)
        }
      )
      # Redirect *may* arrive as a POST even though most browsers convert 302/303
      # to GET
      add_handler(
        "post",
        private$REDIRECT_PATH,
        function(request, response, keys, server, arg_list, ...) {
          session <- arg_list[[server$plugins$firesale$arg_name]]$session
          private$exchange_code_to_token(request, response, session, server)
        }
      )
    },
    #' @description Refresh the access token of the session. Will return `TRUE`
    #' upon success and `FALSE` upon failure. Failure can either be issues with
    #' the token provider, but also lack of a refresh token.
    #' @param session The session data store
    #' @param force Boolean. Should the token be refreshed even if it hasn't
    #' expired yet
    refresh_token = function(session, force = FALSE) {
      token <- session[[private$NAME]]$token
      if (is.null(token$refresh_token)) {
        return(
          !force &&
            !is.null(token$expires_in) &&
            Sys.time() < token$timestamp + as.integer(token$expires_in)
        )
      }
      if (
        force ||
          is.null(token$expires_in) ||
          Sys.time() > token$timestamp + as.integer(token$expires_in)
      ) {
        token_par <- list(
          grant_type = "refresh_token",
          refresh_token = token$refresh_token,
          client_id = private$CLIENT_ID,
          client_secret = private$CLIENT_SECRET
        )
        ch <- curl::new_handle()
        curl::handle_setopt(ch, post = 1)
        curl::handle_setform(ch, .list = token_par)
        res <- curl::curl_fetch_memory(private$TOKEN_URL, ch)
        if (res$status_code != 200L) {
          return(FALSE)
        }
        content <- jsonlite::parse_json(rawToChar(res$content))
        content$timestamp <- Sys.time()
        session[[private$NAME]]$token <- modifyList(
          session[[private$NAME]]$token,
          content
        )
        TRUE
      } else {
        TRUE
      }
    }
  ),
  active = list(
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
              scopes = set_names(
                private$SCOPE_DESC,
                private$SCOPES %||% character()
              )
            )
          )
        } else {
          list(
            password = list(
              tokenUrl = private$TOKEN_URL,
              refreshUrl = private$TOKEN_URL,
              scopes = set_names(
                private$SCOPE_DESC,
                private$SCOPES %||% character()
              )
            )
          )
        }
      )
    }
  ),
  private = list(
    CLIENT_ID = "",
    CLIENT_SECRET = "",
    AUTH_URL = "",
    TOKEN_URL = "",
    REDIRECT_URL = "",
    REDIRECT_PATH = "",
    GRANT_TYPE = "",
    SCOPES = NULL,
    SCOPE_DESC = NULL,
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
        state$state,
        "&redirect_uri=",
        urltools::url_encode(private$REDIRECT_URL),
        "&code_challenge=",
        url_safe_raw(sodium::sha256(charToRaw(state$verifier))),
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
        authorized <- private$VALIDATE(info = session[[private$NAME]])
        scopes <- private$SCOPES %||% character()
        if (is.character(authorized)) {
          scopes <- authorized
          authorized <- TRUE
        }
        if (!authorized) {
          session[[private$NAME]] <- list()
          self$reject_response(response, .session = session)
        } else {
          session[[private$NAME]]$scopes <- unique(
            scopes,
            session[[private$NAME]]$scopes
          )
          response$status <- 200L
        }
      }
    },
    exchange_code_to_token = function(request, response, session, server) {
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
        abort_oauth_error(
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
      authorized <- private$VALIDATE(info = session[[private$NAME]])
      scopes <- private$SCOPES %||% character()
      if (is.character(authorized)) {
        scopes <- authorized
        authorized <- TRUE
      }
      if (!authorized) {
        session[[private$NAME]] <- list()
        self$reject_response(response, .session = session)
      } else {
        session[[private$NAME]]$scopes <- unique(
          scopes,
          session[[private$NAME]]$scopes
        )
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
      token_par <- format_queryform(token_par)
      curl::handle_setopt(
        ch,
        post = 1,
        postfields = token_par,
        postfieldsize = length(token_par)
      )
      curl::handle_setheaders(
        ch,
        "content-type" = "application/x-www-form-urlencoded"
      )
      res <- curl::curl_fetch_memory(private$TOKEN_URL, ch)
      if (res$status_code != 200L) {
        content <- rawToChar(res$content)
        content <- try_fetch(
          jsonlite::parse_json(content),
          error = function(...) {
            list(error_description = content)
          }
        )
        abort_auth(paste0(
          c(content$error, content$error_description, content$error_uri),
          collapse = ": "
        ))
      }
      content <- jsonlite::parse_json(rawToChar(res$content))
      content$timestamp <- Sys.time()
      if (!is.null(content$scope)) {
        content$scope <- strsplit(content$scope, " ", fixed = TRUE)[[1]]
      }
      session[[private$NAME]] <- combine_info(
        new_user_info(
          provider = private$TOKEN_URL,
          scopes = content$scope %||% private$SCOPES %||% character(),
          token = content
        ),
        private$USER_INFO(content)
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
  request_state
}

url_safe_raw <- function(x) {
  x <- base64enc::base64encode(x)
  x <- gsub("=*$", "", x, perl = TRUE)
  x <- gsub("+", "-", x, fixed = TRUE)
  gsub("/", "_", x, fixed = TRUE)
}

format_queryform <- function(data) {
  charToRaw(paste0(names(data), "=", data, collapse = "&"))
}

# List of providers to consider
# Amazon: http://login.amazon.com/ auth: 'https://www.amazon.com/ap/oa' token: https://api.amazon.com/auth/o2/token' user: 'https://api.amazon.com/user/profile'
# Okta
# Auth0
