#' Guard based on OpenID Connect
#'
#' OpenID Connect is an authentication standard build on top of
#' [OAuth 2.0][guard_oauth2]. OAuth 2.0 at its core is only about authorization
#' and doesn't provide a standardized approach to extracting user information
#' that can be used for authentication. OpenID Connect fills this gap in a
#' number of ways. First, the token returned is a JSON Web Token (JWT) that
#' contains claims about the user, signed by the issuer. Second, the
#' authentication service provides means for discovery of all relevant end
#' points making rotation of credentials etc easier. Third, the claims about
#' users are standardized so authentication services are easily interchangable.
#' Not all OAuth 2.0 authorization services provide an OpenID Connect layer, but
#' if they do, it is generally preferable to use that. The `guard_oidc()`
#' function is the base constructor which can be used to create authenticators
#' with any provider. For ease of use `fireproof` comes with a range of
#' predefined constructors for popular services such as Google etc. Central for
#' all of these is the need for your server to register itself with the
#' provider and get a client id and a client secret which must be used when
#' logging users in.
#'
#' # User information
#' `guard_oidc()` automatically adds [user information][new_user_info] after
#' authentication, based on the standardized user claims provided in the
#' `id_token` as well as any additional user information provided at the
#' `userinfo_endpoint` of the service if `request_user_info = TRUE`. You can see
#' a list of standard user information defined by OpenID Connect at the
#' [OpenID website](https://openid.net/specs/openid-connect-core-1_0.html#StandardClaims).
#' The mapping of these to [new_user_info()] is as follows:
#'
#' - `sub` -> `id`
#' - `name` -> `name_display`
#' - `given_name` -> `name_given`
#' - `middle_name` -> `name_middle`
#' - `family_name` -> `name_family`
#' - `email` -> `emails`
#' - `picture` -> `photos`
#'
#' Further, it will set the `scopes` field to any scopes returned by the
#' `validate` function, the `provider` field to `service_name`, the `token`
#' field to the token information as described in [guard_oauth2()], and `.raw` to
#' the full list of user information as provided unaltered by the service. Be
#' aware that the information reported by the service depends on the `oauth_scopes`
#' requested by fireproof and granted by the user. You can therefore never
#' assume the existence of any information besides `id`, `provider` and `token`.
#'
#' @param service_url The url to the authentication service
#' @inheritParams guard_oauth2
#' @param request_user_info Logical. Should the userinfo endpoint be followed to
#' add information about the user not present in the JWT token. Setting this to
#' `TRUE` will add an additional API call to your authentication flow but
#' potentially provide richer information about the user.
#' @param service_name The name of the service provider. Will be passed on to
#' the `provider` slot in the user info list
#'
#' @return An [GuardOIDC] object
#'
#' @export
#' @importFrom jose jwt_split
#'
#' @examples
#' # Example using Google endpoint (use `guard_google()` in real code)
#' google <- guard_oidc(
#'   service_url = "https://accounts.google.com/",
#'   redirect_url = "https://example.com/auth",
#'   client_id = "MY_APP_ID",
#'   client_secret = "SUCHASECRET"
#' )
#'
#' # Add it to a fireproof plugin
#' fp <- Fireproof$new()
#' fp$add_guard(google, "google_auth")
#'
#' # Use it in an endpoint
#' fp$add_auth("get", "/*", google_auth)
#'
guard_oidc <- function(
  service_url,
  redirect_url,
  client_id,
  client_secret,
  grant_type = c("authorization_code", "password"),
  oauth_scopes = c("profile"),
  request_user_info = FALSE,
  validate = function(info) TRUE,
  redirect_path = get_path(redirect_url),
  on_auth = replay_request,
  service_name = service_url,
  service_params = list(),
  name = "OIDCAuth"
) {
  GuardOIDC$new(
    service_url = service_url,
    redirect_url = redirect_url,
    client_id = client_id,
    client_secret = client_secret,
    grant_type = grant_type,
    oauth_scopes = oauth_scopes,
    request_user_info = request_user_info,
    validate = validate,
    redirect_path = redirect_path,
    on_auth = on_auth,
    service_name = service_name,
    service_params = service_params,
    name = name
  )
}

#' R6 class for the OpenID Connect guard
#'
#' @description
#' This class encapsulates the logic of the OpenID Connect based authentication
#' scheme. See [guard_oidc()] for more information
#'
#' @export
#'
#' @examples
#' # Example using Google endpoint (use `guard_google()` in real code)
#' google <- GuardOIDC$new(
#'   service_url = "https://accounts.google.com/",
#'   redirect_url = "https://example.com/auth",
#'   client_id = "MY_APP_ID",
#'   client_secret = "SUCHASECRET"
#' )
#'
GuardOIDC <- R6::R6Class(
  "GuardOIDC",
  inherit = GuardOAuth2,
  public = list(
    #' @description Constructor for the class
    #' @param service_url The url to the authentication service
    #' @param redirect_url The URL the authorization server should redirect to
    #' following a successful authorization. Must be equivalent to one provided
    #' when registering your application
    #' @param client_id The ID issued by the authorization server when
    #' registering your application
    #' @param client_secret The secret issued by the authorization server when
    #' registering your application. Do NOT store this in plain text
    #' @param grant_type The type of authorization scheme to use, either
    #' `"authorization_code"` or `"password"`
    #' @param oauth_scopes Optional character vector of scopes to request the
    #' user to grant you during authorization. These will *not* influence the
    #' scopes granted by the `validate` function and fireproof scoping. If named,
    #' the names are taken as scopes and the elements as descriptions of the scopes,
    #' e.g. given a scope, `read`, it can either be provided as `c("read")` or
    #' `c(read = "Grant read access")`
    #' @param request_user_info Logical. Should the userinfo endpoint be followed to
    #' add information about the user not present in the JWT token. Setting this to
    #' `TRUE` will add an additional API call to your authentication flow but
    #' potentially provide richer information about the user.
    #' @param validate Function to validate the user once logged in. It must
    #' have a single argument `info`, which gets the information of the user as
    #' provided by the `user_info` function in the. By default it returns `TRUE`
    #' on everything meaning that anyone who can log in with the provider will
    #' be accepted, but you can provide a different function to e.g. restrict
    #' access to certain user names etc.
    #' @param redirect_path The path that should capture redirects after
    #' successful authorization. By default this is derived from `redirect_url`
    #' by removing the domain part of the url, but if for some reason this
    #' doesn't yields the correct result for your server setup you can overwrite
    #' it here.
    #' @param on_auth A function which will handle the result of a successful
    #' authorization. It must have four arguments: `request`, `response`,
    #' `session_state`, and `server`. The first contains the current request
    #' being responded to, the second is the response being send back, the third
    #' is a list recording the state of the original request which initiated the
    #' authorization (containing `method`, `url`, `headers`, and `body` fields
    #' with information from the original request). By default it will use
    #' [replay_request] to internally replay the original request and send back
    #' the response.
    #' @param service_name The name of the service provider. Will be passed on to
    #' the `provider` slot in the user info list
    #' @param service_params A named list of additional query params to add to
    #' the url when constructing the authorization url in the
    #' `"authorization_code"` grant type
    #' @param name The name of the scheme instance. This will also be the name
    #' under which token info and user info is saved in the session store
    initialize = function(
      service_url,
      redirect_url,
      client_id,
      client_secret,
      grant_type = c("authorization_code", "password"),
      oauth_scopes = c("profile"),
      request_user_info = FALSE,
      validate = function(info) TRUE,
      redirect_path = get_path(redirect_url),
      on_auth = replay_request,
      service_name = service_url,
      service_params = list(),
      name = NULL
    ) {
      super$initialize(
        token_url = "",
        redirect_url = redirect_url,
        client_id = client_id,
        client_secret = client_secret,
        auth_url = "",
        grant_type = grant_type,
        oauth_scopes = unique(c("openid", oauth_scopes)),
        validate = validate,
        redirect_path = redirect_path,
        on_auth = on_auth,
        user_info = NULL,
        service_params = service_params,
        name = name
      )
      check_string(service_url)
      private$SERVICE_URL = service_url

      check_bool(request_user_info)
      private$REQ_USER_INFO <- request_user_info

      check_string(service_name)
      private$SERVICE_NAME = service_name
    }
  ),
  active = list(
    #' @field open_api An OpenID compliant security scheme description
    open_api = function() {
      list(
        type = "openIdConnect",
        openIdConnectUrl = gsub(
          "(?<!:)/+",
          "/",
          paste0(private$SERVICE_URL, "/.well-known/openid-configuration"),
          perl = TRUE
        )
      )
    }
  ),
  private = list(
    GRANT_TYPE = "authorization_code",
    SERVICE = list(),
    SERVICE_URL = "",
    SERVICE_EXPIRES = as.POSIXct(0, origin = "1970-01-01"),
    SERVICE_NAME = "",
    KEYS = list(),
    KEYS_EXPIRES = as.POSIXct(0, origin = "1970-01-01"),
    REQ_USER_INFO = FALSE,

    service_discovery = function() {
      if (Sys.time() > private$SERVICE_EXPIRES) {
        service <- curl::curl_fetch_memory(
          gsub(
            "(?<!:)/+",
            "/",
            paste0(private$SERVICE_URL, "/.well-known/openid-configuration"),
            perl = TRUE
          )
        )
        headers <- curl::parse_headers(service$headers)
        service <- jsonlite::parse_json(rawToChar(service$content))
        cache_control <- grepl(
          "^cache-control:.*max-age=.*$",
          headers,
          ignore.case = TRUE,
          perl = TRUE
        )
        if (any(cache_control)) {
          max_age <- as.integer(sub(
            "^.*max-age=(\\d+).*$",
            "\\1",
            headers[cache_control],
            perl = TRUE
          ))
        } else {
          max_age <- 3600
        }
        private$SERVICE_EXPIRES <- Sys.time() + max_age
        private$AUTH_URL <- service$authorization_endpoint
        private$TOKEN_URL <- service$token_endpoint
        private$SERVICE <- service
      }
    },
    key_discovery = function(force = FALSE) {
      private$service_discovery()
      if (force || Sys.time() > private$KEYS_EXPIRES) {
        keys <- curl::curl_fetch_memory(private$SERVICE$jwks_uri)
        headers <- curl::parse_headers(keys$headers)
        keys <- jsonlite::parse_json(rawToChar(service$content))$keys
        keys <- lapply(keys, function(x) {
          x$ssh_key <- try_fetch(jose::read_jwk(x), error = function(...) NULL)
          x
        })
        kid <- lapply(keys, `[[`, "kid")
        if (all(lengths(kid) == 1)) {
          names(keys) <- unlist(kid)
        }

        cache_control <- grepl(
          "^cache-control:.*max-age=.*$",
          headers,
          ignore.case = TRUE,
          perl = TRUE
        )
        if (any(cache_control)) {
          max_age <- as.integer(sub(
            "^.*max-age=(\\d+).*$",
            "\\1",
            headers[cache_control],
            perl = TRUE
          ))
        } else {
          max_age <- 3600
        }
        private$KEYS_EXPIRES <- Sys.time() + max_age
        private$KEYS <- keys
      }
    },

    request_token = function(token_par, session) {
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
      jwt <- private$validate_id_token(content$id_token)
      if (
        private$REQ_USER_INFO && !is.null(private$SERVICE$userinfo_endpoint)
      ) {
        ch <- curl::new_handle()
        curl::handle_setheaders(
          ch,
          authorization = paste("bearer ", content$token)
        )
        info <- curl::curl_fetch_memory(private$SERVICE$userinfo_endpoint, ch)
        info <- jsonlite::parse_json(rawToChar(info$content))
        if (info$sub == jwt$sub) {
          extra_info <- setdiff(names(info), names(jwt))
          jwt[extra_info] <- info[extra_info]
        }
      }
      scope <- if (!is.null(content$scope)) {
        strsplit(content$scope, " ", fixed = TRUE)[[1]]
      }
      session$fireproof[[private$NAME]] <- new_user_info(
        provider = private$SERVICE_NAME,
        id = jwt$sub,
        name_display = jwt$name,
        name_given = jwt$given_name,
        name_middle = jwt$middle_name,
        name_family = jwt$family_name,
        emails = jwt$email,
        photos = jwt$picture,
        token = content,
        scopes = scope %||% private$SCOPES %||% character(),
        .raw = jwt
      )
    },
    construct_auth_url = function(request, state) {
      private$service_discovery()
      url <- super$construct_auth_url(request, state)
      paste0(url, "&nonce=", state$nonce)
    },
    validate_id_token = function(token, session_state) {
      private$key_discovery()
      token_parts <- try_fetch(
        jose::jwt_split(token),
        error = function(e) {
          abort_auth("invalid id_token returned from service", parent = e)
        }
      )
      kid <- token_parts$header$kid
      pubkey <- private$KEYS[[kid]]$ssh_key
      if (is.null(pubkey)) {
        private$key_discovery(force = TRUE)
        pubkey <- private$KEYS[[kid]]$ssh_key
        if (is.null(pubkey)) {
          abort_auth("can't retrieve public key matching kid from service")
        }
      }
      claims <- try_fetch(
        jose::jwt_decode_sig(token, pubkey),
        error = function(e) {
          abort_auth(
            "can't retrieve public key matching kid from service",
            parent = e
          )
        }
      )
      if (!identical(claims$iss, private$SERVICE$issuer)) {
        abort_auth("wrong issuer in claim")
      }
      if (!identical(claims$aud, private$CLIENT_ID)) {
        abort_auth("wrong issuer in claim")
      }
      now <- Sys.time()
      if (is.null(claims$exp) || claims$exp < now) {
        abort_auth("expired JWT token")
      }
      if (is.null(claims$iat) || claims$iat > now + 60) {
        abort_auth("JWT token issued in the future")
      }
      if (!identical(claims$nonce, session_state$nonce)) {
        abort_auth("JWT nonce not matching session nonce")
      }
      claims
    }
  )
)
