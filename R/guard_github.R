#' Guard for authenticating with the GitHub OAuth 2.0 server
#'
#' This guard requests you to log in with GitHub and authenticates yourself
#' through their service. Your server must be registered and have a valid client
#' ID and client secret for this to work. Register an application at
#' <https://github.com/settings/applications/new>. If you want to limit access
#' to only select users you should make sure to provide a `validate` function
#' that checks the userinfo against a whitelist.
#'
#' # User information
#' `guard_github()` automatically adds user information according to the
#' description in [guard_oauth2()]. It sets the `provider` field to `"github"`.
#' Further, extracts information from the `https://api.github.com/user` endpoint
#' and maps the information accordingly:
#'
#' - `id` -> `id`
#' - `name` -> `name_display`
#' - `login` -> `name_user`
#' - `email` -> `emails`
#' - `avatar_url` -> `photos`
#'
#' It also sets the `.raw` field to the full list of information returned from
#' github.
#'
#' @inheritParams guard_oauth2
#' @inheritDotParams guard_oauth2 -token_url -auth_url -user_info
#'
#' @return A [GuardOAuth2] object
#'
#' @references [Documentation for GitHub's OAuth 2 flow](https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/generating-a-user-access-token-for-a-github-app)
#'
#' @export
#'
#' @examples
#' github <- guard_github(
#'   redirect_url = "https://example.com/auth",
#'   client_id = "MY_APP_ID",
#'   client_secret = "SUCHASECRET"
#' )
#'
#' # Add it to a fireproof plugin
#' fp <- Fireproof$new()
#' fp$add_guard(github, "github_auth")
#'
#' # Use it in an endpoint
#' fp$add_auth("get", "/*", github_auth)
#'
guard_github <- function(
  redirect_url,
  client_id,
  client_secret,
  ...,
  name = "github"
) {
  guard_oauth2(
    token_url = "https://github.com/login/oauth/access_token",
    redirect_url = redirect_url,
    client_id = client_id,
    client_secret = client_secret,
    auth_url = "https://github.com/login/oauth/authorize",
    user_info = function(token_info) {
      ch <- curl::new_handle()
      curl::handle_setheaders(
        ch,
        authorization = paste0("bearer ", token_info$access_token)
      )
      info <- curl::curl_fetch_memory(
        url = "https://api.github.com/user", ch
      )
      info <- jsonlite::parse_json(rawToChar(info$content))
      new_user_info(
        provider = "github",
        id = info$id,
        name_display = info$name,
        name_user = info$login,
        emails = info$email,
        photos = info$avatar_url,
        .raw = info
      )
    },
    ...,
    scopes_delim = ",",
    name = name
  )
}
