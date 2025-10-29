#' Well structured user information
#'
#' Different services and authentication schemes may present user information in
#' different ways. To ensure ease of interoperability, fireproof will attempt to
#' standardize the information as it gets extracted by the service. This
#' function will generally not be called directly but serves to document the
#' different input that may be available in the `setter()` function that is
#' passed to the `user_info` arguments function. See the *Value* section for a
#' description on the structure of the stored information.
#'
#' # Setting user information
#' Each authentication scheme will write to a field in the session data store
#' named after its own name. What gets written can sometimes be influenced by
#' the user by passing in a function to the `user_info` argument of the
#' constructor. This function will, among other information be provided with a
#' `setter()` function which takes the same arguments as described above and
#' automatically assigns the result to the correct part of the session data
#' store. In some cases one or more of the arguments will have a default value
#' assigned (e.g. for [auth_basic()], the `setter()` will have `id` default to
#' the username). Further, the setter will also set the `scopes` field to the
#' `scopes` reported for the user, the `token` field with information about the
#' token (for [auth_bearer()], [auth_oauth2()] and [auth_oidc()]), and the
#' `.raw` field with the raw user info value returned by the service (for
#' [auth_oidc()] and some predefined OAuth2 providers such as [auth_github()])
#'
#' @param provider A string naming the provider of the user information
#' @param id A unique identifier of this user
#' @param name_display,name_given,name_middle,name_family,name_user The legal
#' name of the user. Will be combined to a single `name` field in the output
#' with the structure
#' `c(given = name_given, middle = name_middle, family = name_family, display = name_display, user = name_user)`
#' @param emails A character vector of emails to the user. The vector can be
#' named in which case the names correspond to the category of email, e.g.
#' "work", "home" etc.
#' @param photos A character vector of urls pointing to profile pictures of the
#' user.
#' @param ... Additional named arguments to be added to the user information
#'
#' @return A list of class `fireproof_user_info`. The fields of the list are as
#' provided in the arguments except for the `name_*` arguments which will be
#' combined to a single field. See the description of these arguments for more
#' information.
#'
#' @export
#'
#' @examples
#' user_info(
#'   provider = "local",
#'   id = 1234,
#'   name_display = "thomasp85",
#'   name_given = "Thomas",
#'   name_middle = "Lin",
#'   name_family = "Pedersen"
#' )
#'
#'
user_info <- function(
  provider = NULL,
  id = NULL,
  name_display = NULL,
  name_given = NULL,
  name_middle = NULL,
  name_family = NULL,
  name_user = NULL,
  emails = NULL,
  photos = NULL,
  ...
) {
  structure(
    list(
      provider = provider,
      id = id,
      name = c(
        given = name_given,
        middle = name_middle,
        family = name_family,
        display = name_display,
        user = name_user
      ),
      emails = emails,
      photos = photos,
      ...
    ),
    class = "firesale_user_info"
  )
}

#' @export
print.firesale_user_info <- function(x, ...) {
  for (name in names(x)) {
    cat(name, ": ", format(x[name]), "\n", sep = "")
  }
}
