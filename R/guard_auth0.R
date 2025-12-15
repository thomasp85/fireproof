#' Guard for Authenticating with Okta
#'
#' Okta is a single sign-on provider that organizations can use to collect
#' authentication to various services under one roof. This guard gives you
#' access to the OpenID Connect sign on provided by Okta, assuming you are a
#' registered user/organization
#'
#' # User information
#' `guard_okta()` automatically adds user information according to the
#' description in [guard_oidc()]. It sets the `provider` field to `"okta"`.
#'
#' @param domain The URL you have been provided for your organization, e.g.
#' `https://company.auth0.com`
#' @param identity_provider An optional identity provider which will handle the
#' user info. Will be passed to the connection parameter of the authentication
#' request. If a connection is already given in `service_params` then that will
#' take precedence. Auth0 needs to be configured with the identity provider
#' prior to using this.
#'
#' @inheritParams guard_oidc
#' @inheritDotParams guard_oidc -service_url -service_name
#'
#' @return A [GuardOIDC] object
#'
#' @export
#'
#' @examples
#' auth0 <- guard_auth0(
#'   domain = "https://company.auth0.com",
#'   redirect_url = "https://example.com/auth",
#'   client_id = "MY_APP_ID",
#'   client_secret = "SUCHASECRET"
#' )
#'
#' # Add it to a fireproof plugin
#' fp <- Fireproof$new()
#' fp$add_guard(auth0, "auth0_auth")
#'
#' # Use it in an endpoint
#' fp$add_auth("get", "/*", auth0_auth)
#'
guard_auth0 <- function(
  domain,
  redirect_url,
  client_id,
  client_secret,
  identity_provider = NULL,
  oauth_scopes = "profile",
  service_params = list(),
  ...,
  name = "auth0"
) {
  service_params <- modify_list(
    list(connection = identity_provider),
    service_params
  )
  service_params <- service_params[lengths(service_params) != 0]
  guard_oidc(
    service_url = domain,
    redirect_url = redirect_url,
    client_id = client_id,
    client_secret = client_secret,
    oauth_scopes = oauth_scopes,
    service_name = "auth0",
    service_params = service_params,
    ...,
    name = name
  )
}
