#' A plugin that handles authentication
#'
#' @description
#' This plugin orchestrates all authentication for your fiery app. It is a
#' special [Route][routr::Route] that manages all the different authentication
#' scheme instances you have defined as well as testing all the endpoints that
#' have authentication requirements.
#'
#' @details
#' An authentication scheme instance is an object deriving from the [Auth] class
#' which is usually created with one of the `auth_*()` constructors. You can
#' provide it with a name as you register it and can thus have multiple
#' instances of the same scheme (e.g. two `auth_basic()` with different user
#' lists)
#'
#' An authentication handler is a handler that consists of a method, path, and
#' flow. The flow is a logical expression of the various instances the request
#' must pass to get access to that endpoint. For example, if you have two
#' instances named `auth1` and `auth2`, a flow could be `auth1 || auth2` to allow
#' a request if it passes either of the instances. Given an additional instance,
#' `auth3`, it could also be something like `auth1 || (auth2 && auth3)`. The
#' flow is given as a bare expression, not as a string. In addition to the three
#' required arguments you can also supply a character vector of scopes that are
#' required to be had to access the endpoint. If your scheme has scope support
#' then the request will be tested against these to see if the (otherwise valid)
#' user has permission to the resource.
#'
#' @export
#'
#' @importFrom routr Route
#' @importFrom reqres abort_status
Fireproof <- R6::R6Class(
  "Fireproof",
  inherit = Route,
  public = list(
    #' @description Add a new authentication handler
    #' @param method The http method to match the handler to
    #' @param path The URL path to match to
    #' @param flow The authentication flow the request must pass to be valid.
    #' See *Details*
    #' @param scope An optional character vector of scopes that the request must
    #' have permission for to access the resource
    #'
    add_auth_handler = function(
      method,
      path,
      flow,
      scope = NULL
    ) {
      flow <- parse_auth_flow({{ flow }})
      authenticators <- unique(unlist(flow))
      check_character(scope, allow_na = FALSE, allow_null = TRUE)

      super$add_handler(
        method,
        path,
        handler = function(request, response, keys, ...) {
          pass <- private$eval_auths(
            authenticators,
            request = request,
            response = response,
            keys = keys,
            ...
          )
          success <- eval_op(flow, pass)
          if (!success) {
            failed <- names(pass)[!vapply(pass, isTRUE, logical(1))]
            lapply(private$REJECTION[failed], function(fun) fun(response, scope))
            abort_status(response$status)
          }
          if (!is.null(scope) && !all(scope %in% response$get_data("auth_scope"))) {
            succeeded <- names(pass)[vapply(pass, isTRUE, logical(1))]
            lapply(private$FORBID[succeeded], function(fun) fun(response, scope))
            abort_status(response$status)
          }
          TRUE
        },
        reject_missing_methods = FALSE
      )
    },
    #' @description Add an authentication scheme instance to the plugin
    #' @param auth Either an [Auth] object defining the scheme instance
    #' (preferred) or a function taking the standard route handler arguments
    #' (`request`, `response`, `keys`, and `...`) and returns `TRUE` if the
    #' request is valid and `FALSE` if not.
    #' @param name The name of the scheme instance to be used when defining flow
    #' for endpoint authentication.
    #'
    add_auth = function(auth, name = NULL) {
      if (is.function(auth)) {
        if (!"..." %in% fn_fmls_names(auth)) {
          fn_fmls(auth) <- c(fn_fmls(auth), "..." = missing_arg())
        }
        reject <- function(response) {
          if (response$status == 404L) {
            response$status <- 400L
          }
        }
        forbid <- function(response, scope) {
          response$status <- 403L
        }
      } else {
        if (!is_auth(auth)) {
          cli::cli_abort(
            "{.arg auth} must be a function or an {.cls Auth} object"
          )
        }
        reject <- auth$reject_response
        forbid <- auth$forbid_user
        auth <- auth$check_request
        name <- name %||% auth$name
      }
      check_string(name)
      private$AUTHS[[name]] <- auth
      private$REJECTION[[name]] <- reject
      private$FORBID[[name]] <- forbid
    },
    #' @description Defunct overwrite of the `add_handler()` method to prevent
    #' this route to be used for anything other than authentication. Will throw
    #' an error if called.
    #' @param method ignored
    #' @param path ignored
    #' @param handler ignored
    #' @param reject_missing_methods ignored
    add_handler = function(
      method,
      path,
      handler,
      reject_missing_methods = FALSE
    ) {
      cli::cli_abort(c(
        "{.cls AuthRoute} does not support adding handlers directly",
        i = "Use the {.fun add_auth_handler} method to add an authentication/authorization handler"
      ))
    },
    #' @description Method for use by fiery when attached as a plugin. Should
    #' not be called directly. This method looks for a header route stack in the
    #' app and if it doesn't exist it creates one. It then attaches the plugin
    #' as the first route to it.
    #' @param app The Fire object to attach the router to
    #' @param ... Ignored
    #'
    on_attach = function(app, ...) {
      if (is.null(app$plugins$header_routr)) {
        rs <- routr::RouteStack$new()
        rs$attach_to <- "header"
        app$attach(rs)
      }
      app$plugins$header_routr$add_route(
        self,
        "fireproof_auth",
        after = 0
      )
    }
  ),
  active = list(
    #' @field name The name of the plugin: `"fireproof"`
    name = function() {
      "fireproof"
    },
    #' @field auths The name of all the authentication schemes currently added
    #' to the plugin
    auths = function() {
      names(private$AUTHS)
    }
  ),
  private = list(
    AUTHS = list(),
    REJECTION = list(),
    FORBID = list(),

    eval_auths = function(.authenticators, request, response, keys, ...) {
      auths <- private$AUTHS[.authenticators]
      missing <- lengths(auths) == 0
      if (any(missing)) {
        cli::cli_warn(
          "Ignoring unknown authenticator{?s} {.authenticators[missing]}"
        )
        auths[missing] <- true_fun
      }
      lapply(auths, function(x) {
        x(request = request, response = response, keys = keys, ...)
      })
    }
  )
)

true_fun <- function(...) TRUE
parse_auth_flow <- function(expr) {
  flow <- quo_squash(enexpr(expr))
  collapse <- TRUE
  if (is_call(flow) && is_symbol(flow[[1]], "(")) {
    flow <- flow[[2]]
    collapse <- FALSE
  }
  if (length(flow) == 1) {
    scalar(gsub('"|\'', "", expr_text(flow)))
  } else {
    op <- expr_name(flow[[1]])
    if (!op %in% c("||", "&&")) {
      cli::cli_abort(
        "Unknown operator for authentication flow. Only `||` and `&&` allowed"
      )
    }
    lhs <- parse_auth_flow(!!flow[[2]])
    rhs <- parse_auth_flow(!!flow[[3]])
    elems <- list2(
      !!!if (may_collapse(lhs, op)) lhs else list(lhs),
      !!!if (may_collapse(rhs, op)) rhs else list(rhs)
    )
    if (op == "||") {
      or(!!!elems, .collapsible = collapse)
    } else {
      and(!!!elems, .collapsible = collapse)
    }
  }
}

and <- function(..., .collapsible = TRUE) {
  structure(
    list2(...),
    class = "fireproof_op",
    can_collapse = .collapsible,
    op = "&&"
  )
}
or <- function(..., .collapsible = TRUE) {
  structure(
    list2(...),
    class = "fireproof_op",
    can_collapse = .collapsible,
    op = "||"
  )
}
scalar <- function(x) {
  structure(list(x), class = "fireproof_op", can_collapse = TRUE, op = NULL)
}
may_collapse <- function(x, op) {
  attr(x, "can_collapse") && (attr(x, "op") %||% op) == op
}
#' @export
format.fireproof_op <- function(x, ...) {
  paste0(
    if (length(x) > 1) "(" else "",
    paste0(lapply(x, format, ...), collapse = paste0(" ", attr(x, "op"), " ")),
    if (length(x) > 1) ")" else ""
  )
}
#' @export
print.fireproof_op <- function(x, ...) {
  cat(format(x, ...))
}
eval_op <- function(op, table) {
  if (length(op) == 1) {
    return(table[[op[[1]]]])
  }
  res <- vapply(op, eval_op, logical(1), table = table)
  if (attr(op, "op") == "||") any(res) else all(res)
}
