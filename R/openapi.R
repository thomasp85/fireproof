#' Ensure consistency of OpenAPI auth description
#'
#' Prune an OpenAPI doc so that security descriptions only contains references
#' to the schemes defined in `securitySchemes` and only contains scopes for the
#' schemes that are OAuth2.0 and OpenID. For OAuth2.0 specifically, scopes are
#' removed if they are not explicitly named in `securitySchemes`.
#'
#' @param doc A list describing a full OpenAPI documentation
#'
#' @return The `doc` modified so the auth descriptions are internally consistent
#'
#' @export
#'
#' @examples
#' # OpenAPI stub only containing relevant info for example
#' openapi <- list(
#'   components = list(
#'     securitySchemes = list(
#'       auth1 = list(
#'         type = "http",
#'         scheme = "basic"
#'       ),
#'       auth2 = list(
#'         type = "oauth2",
#'         flows = list(
#'           authorizationCode = list(
#'             scopes = list(
#'               read = "read data",
#'               write = "change data"
#'             )
#'           )
#'         )
#'       )
#'     )
#'   ),
#'   # Global auth settings
#'   security = list(
#'     list(auth1 = c("read", "write"))
#'   ),
#'   # Path specific auth settings
#'   paths = list(
#'     "/user/{username}" = list(
#'       get = list(
#'         security = list(
#'           list(auth2 = c("read", "write", "commit")),
#'           list(auth3 = c("read"))
#'         )
#'       )
#'     )
#'   )
#' )
#'
#' prune_openapi(openapi)
#'
prune_openapi <- function(doc) {
  uses_scopes <- vapply(
    doc$components$securitySchemes,
    function(x) {
      x$type %in% c("oauth2", "openIdConnect")
    },
    logical(1)
  )
  scopes <- lapply(doc$components$securitySchemes, function(x) {
    if (x$type == "oauth2") {
      unique(unlist(lapply(x$flows, function(xx) names(xx$scopes))))
    }
  })
  if (!is.null(doc$security)) {
    doc$security <- prune_security(
      doc$security,
      names(uses_scopes),
      uses_scopes,
      scopes
    )
  }
  doc$paths <- lapply(doc$paths, function(path) {
    lapply(path, function(method) {
      if (!is.null(method$security)) {
        method$security <- prune_security(
          method$security,
          names(uses_scopes),
          uses_scopes,
          scopes
        )
      }
      method
    })
  })
  doc
}

prune_security <- function(security, schemes, uses_scopes, scopes) {
  security <- lapply(security, function(sec) {
    sec <- sec[names(sec) %in% schemes]
    sec[!uses_scopes[names(sec)]] <- list(character())
    sec[] <- lapply(names(sec), function(sec_n) {
      intersect(sec[[sec_n]], scopes[[sec_n]] %||% sec[[sec_n]])
    })
    sec
  })
  security[lengths(security) != 0]
}
