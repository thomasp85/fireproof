# For OAuth2: https://developers.google.com/identity/protocols/oauth2/web-server
# For OIDC: https://developers.google.com/identity/openid-connect/openid-connect
#' Authenticate with Google using OpenID Connect
#'
#' This authentication requests you to log in with google and authenticates you
#' through their service. Your server must be registered and have a valid client
#' ID and client secret for this to work. Read more about registering an
#' application at <https://developers.google.com/identity/protocols/oauth2>. If
#' you want to limit access to only select users you should make sure to provide
#' a `validation` function that checks the userinfo against a whitelist.
#'
#' @inheritParams auth_oidc
#' @inheritDotParams auth_oidc -service_url -service_name
#'
#' @return An [AuthOIDC] object
#'
#' @export
#'
#' @examples
#' google <- auth_google(
#'   redirect_url = "https://example.com/auth",
#'   client_id = "MY_APP_ID",
#'   client_secret = "SUCHASECRET",
#' )
#'
#' # Add it to a fireproof plugin
#' fp <- Fireproof$new()
#' fp$add_auth(google, "google_auth")
#'
#' # Use it in an endpoint
#' fp$add_auth_handler("get", "/*", google_auth)
#'
auth_google <- function(
  redirect_url,
  client_id,
  client_secret,
  scopes = "profile",
  service_params = list(
    access_type = "offline",
    include_granted_scopes = "true"
  ),
  ...,
  name = "google"
) {
  auth_oidc(
    service_url = "https://accounts.google.com/",
    redirect_url = redirect_url,
    client_id = client_id,
    client_secret = client_secret,
    service_name = "google",
    service_params = service_params,
    ...,
    name = name
  )
}
