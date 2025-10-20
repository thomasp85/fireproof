#' @importFrom routr Route
#' @importFrom reqres abort_status
AuthRoute <- R6::R6Class(
  "AuthRoute",
  inherit = Route,
  public = list(
    add_auth_handler = function(
      method,
      path,
      flow,
      reject_missing_methods = FALSE
    ) {
      flow <- parse_auth_flow({{ flow }})
      authenticators <- unique(unlist(flow))

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
            lapply(private$REJECTIONS[failed], function(fun) fun(response))
            abort_status(response$status)
          }
          TRUE
        },
        reject_missing_methods = reject_missing_methods
      )
    },
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
      } else {
        if (!is_auth(auth)) {
          cli::cli_abort(
            "{.arg auth} must be a function or an {.cls Auth} object"
          )
        }
        reject <- auth$reject_response
        auth <- auth$check_request
        name <- name %||% auth$name
      }
      check_string(name)
      private$AUTHS[[name]] <- auth
      private$REJECTIONS[[name]] <- reject
    }
  ),
  active = list(
    auths = function() {
      names(private$AUTHS)
    }
  ),
  private = list(
    AUTHS = list(),
    REJECTIONS = list(),

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
