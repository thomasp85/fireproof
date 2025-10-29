#' Authenticate using the mock OAuth servers provided by Beeceptor
#'
#' These two functions sets up mock OAuth 2.0 authentication based on tools
#' provided by
#' [Beeceptor](https://app.beeceptor.com/mock-server/oauth-mock). These should
#' obviously not be used for production because they allow anyone to be
#' authenticated, but they can be used while testing your authentication setup.
#'
#' @inheritParams auth_oauth2
#' @inheritDotParams auth_oauth2
#'
#' @export
#'
#' @return An [AuthOAuth2] object
#'
#' @rdname auth_beeceptor
#' @name auth_beeceptor
#'
#' @examples
#' beeceptor <- auth_beeceptor_github(
#'   redirect_url = "https://example.com/auth"
#' )
#'
#' # Add it to a fireproof plugin
#' fp <- Fireproof$new()
#' fp$add_auth(beeceptor, "beeceptor_auth")
#'
#' # Use it in an endpoint
#' fp$add_auth_handler("get", "/*", beeceptor_auth)
#'
auth_beeceptor_github <- function(
  redirect_url,
  client_id = "MOCK_CLIENT",
  ...,
  name = "beeceptor_github"
) {
  auth_oauth2(
    token_url = "https://oauth-mock.mock.beeceptor.com/oauth/token/github",
    redirect_url = redirect_url,
    client_id = client_id,
    client_secret = "ABCD",
    auth_url = "https://oauth-mock.mock.beeceptor.com/oauth/authorize",
    grant_type = "authorization_code",
    user_info = function(token_info, setter) {
      info <- curl::curl_fetch_memory(
        url = "https://oauth-mock.mock.beeceptor.com/userinfo/github",
      )
      info <- jsonlite::parse_json(rawToChar(info$content))
      setter(
        provider = "beeceptor",
        id = info$id,
        name_display = info$name,
        emails = info$email,
        photos = info$avatar_url,
        login = info$login
      )
    },
    ...,
    name = name
  )
}

#' @rdname auth_beeceptor
#' @export
auth_beeceptor_google <- function(
  redirect_url,
  client_id = "MOCK_CLIENT",
  ...,
  name = "beeceptor_google"
) {
  auth_oauth2(
    token_url = "https://oauth-mock.mock.beeceptor.com/oauth/token/google",
    redirect_url = redirect_url,
    client_id = client_id,
    client_secret = "ABCD",
    auth_url = "https://oauth-mock.mock.beeceptor.com/oauth/authorize",
    grant_type = "authorization_code",
    user_info = function(token_info, setter) {
      info <- curl::curl_fetch_memory(
        url = "https://oauth-mock.mock.beeceptor.com/userinfo/google",
      )
      info <- jsonlite::parse_json(rawToChar(info$content))
      setter(
        provider = "beeceptor",
        id = info$sub,
        name_display = info$name,
        name_given = info$given_name,
        name_family = info$family_name,
        emails = info$email,
        photos = info$picture
      )
    },
    ...,
    name = name
  )
}
