# Some docs: https://docs.github.com/en/apps/creating-github-apps/writing-code-for-a-github-app/building-a-login-with-github-button-with-a-github-app#introduction
#' Authenticate with GitHub using OAuth 2.0
#'
#' This authentication requests you to log in with GitHub and authenticates you
#' through their service. Your server must be registered and have a valid client
#' ID and client secret for this to work. Register an application at
#' <https://github.com/settings/applications/new>. If you want to limit access
#' to only select users you should make sure to provide a `validation` function
#' that checks the userinfo against a whitelist.
#'
#' @inheritParams auth_oauth2
#' @inheritDotParams auth_oauth2 -token_url -auth_url -user_info
#'
#' @return An [AuthOAuth2] object
#'
#' @export
#'
auth_github <- function(
  redirect_url,
  client_id,
  client_secret,
  ...,
  name = "github"
) {
  auth_oauth2(
    token_url = "https://github.com/login/oauth/access_token",
    redirect_url = redirect_url,
    client_id = client_id,
    client_secret = client_secret,
    auth_url = "https://github.com/login/oauth/authorize",
    user_info = function(token_info, setter) {
      ch <- curl::new_handle()
      curl::handle_setheaders(ch, authorization = paste("bearer ", token_info$token))
      info <- curl::curl_fetch_memory(
        url = "https://api.github.com/user",
      )
      info <- jsonlite::parse_json(rawToChar(info$content))
      setter(
        provider = "github",
        id = info$id,
        display_name = info$name,
        username = info$login,
        emails = info$email,
        photos = info$avatar_url,
        .raw = info
      )
    },
    service_params = service_params,
    ...,
    name = name
  )
}
