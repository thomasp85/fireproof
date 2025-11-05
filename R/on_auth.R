#' Predefined functions for handling successful OAuth 2.0 authentication
#'
#' When using the `"authorization code"` grant type in an OAuth 2.0
#' authorization flow, you have to decide what to do after an access token has
#' been successfully retrieved. Since the flow goes through multiple redirection
#' the original request is no longer available once the access token has been
#' retrieved. The `replay_request()` function will use the saved session_state
#' from the original request to construct a "fake" request and replay that on
#' the server to obtain the response it would have given had the user already
#' been authorized. The `redirect_back()` function will try to redirect the user
#' back to the location they where at when they send the request that prompted
#' authorization. You can also create your own function that e.g. presents a
#' "Successfully logged on" webpage. See *Details* for information on the
#' requirements for such a function.
#'
#' @details
#' Creating your own success handler is easy and just requires that you conform
#' to the input arguments of the functions described here. The main purpose of
#' the function is to modify the response object that is being send back to the
#' user to fit your needs. As with any routr handler it should return a boolean
#' indicating if further processing should happen. For this situation it is
#' usually sensible to return `FALSE`.
#'
#' @param request The current request being handled, as a [reqres::Request]
#' object. The result of a redirection from the authorization server.
#' @param response The response being returned to the user as a
#' [reqres::Response] object.
#' @param session_state A list of stored information from the original request.
#' Contains the following fields: `state` (a random string identifying the
#' authorization attempt), `time` (the timestamp of the original request),
#' `method` (the http method of the original request), `url` (the full url of
#' the original request, including any query string), `headers` (A named list of
#' all the headers of the original request), `body` (a raw vector of the body of
#' the original request), and `from` (The url the original request was sent
#' from)
#' @param server The fiery server handling the request
#'
#' @return `TRUE` if the request should continue processing in the server or
#' `FALSE` if the response should be send straight away
#'
#' @rdname on_auth
#' @name on_auth
#' @export
#'
#' @examples
#' # These functions are never called directly but passed on to the `on_auth`
#' # argument in OAuth 2.0 and OpenID Connect authentication flows
#'
#' # Default
#' google <- auth_google(
#'   redirect_url = "https://example.com/auth",
#'   client_id = "MY_APP_ID",
#'   client_secret = "SUCHASECRET",
#'   on_auth = replay_request
#' )
#'
#' # Alternative
#' google <- auth_google(
#'   redirect_url = "https://example.com/auth",
#'   client_id = "MY_APP_ID",
#'   client_secret = "SUCHASECRET",
#'   on_auth = redirect_back
#' )
#'
replay_request = function(request, response, session_state, server) {
  old_req <- fiery::fake_request(
    url = session_state$url,
    method = session_state$method,
    headers = lapply(session_state$headers, paste0, collapse = ","),
    content = session_state$body
  )
  true_res <- server$test_request(old_req)
  response$status <- true_res$status
  response$body <- true_res$body
  response$format(
    "text/plain" = function(body, ...) body,
    default = "text/plain"
  )
  for (header in names(true_res$headers)) {
    response$set_header(gsub("_", "-", header), true_res$headers[[header]])
  }
  FALSE
}

#' @rdname on_auth
#' @export
#'
redirect_back = function(request, response, session_state, server) {
  response$status <- 307L
  response$set_header("location", session_state$from)
  FALSE
}
