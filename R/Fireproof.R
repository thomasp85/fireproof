#' A plugin that handles authentication and/or authorization
#'
#' @description
#' This plugin orchestrates all guards for your fiery app. It is a
#' special [Route][routr::Route] that manages all the different guards you have
#' defined as well as testing all the endpoints that have auth requirements.
#'
#' @details
#' A guard is an object deriving from the [Guard] class which is usually created
#' with one of the `guard_*()` constructors. You can provide it with a name as
#' you register it and can thus have multiple instances of the same scheme (e.g.
#' two `guard_basic()` with different user lists)
#'
#' An auth handler is a handler that consists of a method, path, and
#' flow. The flow is a logical expression of the various guards the request
#' must pass to get access to that endpoint. For example, if you have two
#' guards named `auth1` and `auth2`, a flow could be `auth1 || auth2` to allow
#' a request if it passes either of the guards. Given an additional guard,
#' `auth3`, it could also be something like `auth1 || (auth2 && auth3)`. The
#' flow is given as a bare expression, not as a string. In addition to the three
#' required arguments you can also supply a character vector of scopes that are
#' required to have access to the endpoint. If your guard has scope support
#' then the request will be tested against these to see if the (otherwise valid)
#' user has permission to the resource.
#'
#' @export
#'
#' @importFrom routr Route
#' @importFrom reqres abort_status
#'
#' @examples
#' # Create a fireproof plugin
#' fp <- Fireproof$new()
#'
#' # Create some authentication schemes and add them
#' basic <- guard_basic(
#'   validate = function(user, password) {
#'     user == "thomas" && password == "pedersen"
#'   },
#'   user_info = function(user) {
#'     new_user_info(
#'       name_given = "Thomas",
#'       name_middle = "Lin",
#'       name_family = "Pedersen"
#'     )
#'   }
#' )
#' fp$add_guard(basic, "basic_auth")
#'
#' key <- guard_key(
#'   key_name = "my-key-location",
#'   validate = "SHHH!!DONT_TELL_ANYONE"
#' )
#' fp$add_guard(key, "key_auth")
#'
#' google <- guard_google(
#'   redirect_url = "https://example.com/auth",
#'   client_id = "MY_APP_ID",
#'   client_secret = "SUCHASECRET",
#' )
#' fp$add_guard(google, "google_auth")
#'
#' # Add authentication to different paths
#' fp$add_auth("get", "/require_basic", basic_auth)
#'
#' fp$add_auth("get", "/require_basic_and_key", basic_auth && key_auth)
#'
#' fp$add_auth(
#'   "get",
#'   "/require_google_or_the_others",
#'   google_auth || (basic_auth && key_auth)
#' )
#'
#' @examplesIf requireNamespace("fiery", quietly = TRUE) && requireNamespace("firesale", quietly = TRUE)
#' # Add plugin to fiery app
#' app <- fiery::Fire$new()
#'
#' # First add the firesale plugin as it is required
#' fs <- firesale::FireSale$new(storr::driver_environment(new.env()))
#' app$attach(fs)
#'
#' # Then add the fireproof plugin
#' app$attach(fp)
#'
Fireproof <- R6::R6Class(
  "Fireproof",
  inherit = Route,
  public = list(
    #' @description Print method for the class
    #' @param ... Ignored
    print = function(...) {
      cat(
        "A fireproof plugin with ",
        length(private$GUARDS),
        " guards and ",
        sum(lengths(private$handlerMap)),
        " handlers",
        sep = ""
      )
    },
    #' @description Add a new authentication handler. It invisibly returns the
    #' parsed flow so it can be used for generating OpenAPI specs with.
    #' @param method The http method to match the handler to
    #' @param path The URL path to match to
    #' @param flow The authentication flow the request must pass to be valid.
    #' See *Details*. If `NULL` then authentication is turned off for the
    #' endpoint.
    #' @param scope An optional character vector of scopes that the request must
    #' have permission for to access the resource
    #'
    add_auth = function(
      method,
      path,
      flow,
      scope = NULL
    ) {
      flow <- parse_auth_flow({{ flow }})

      # If flow is NULL, turn off auth for the endpoint
      if (is.null(flow)) {
        super$add_handler(method, path, function(...) TRUE)
        return(invisible(NULL))
      }

      guards <- unique(unlist(flow))
      check_character(scope, allow_na = FALSE, allow_null = TRUE)

      super$add_handler(
        method,
        path,
        handler = function(request, response, keys, server, arg_list, ...) {
          private$STORE_NAME <- private$STORE_NAME %||%
            server$plugins$firesale$arg_name %||% "datastore"
          datastore <- arg_list[[private$STORE_NAME]]

          pass <- private$eval_guards(
            guards,
            request = request,
            response = response,
            keys = keys,
            ...,
            .datastore = datastore
          )
          success <- eval_op(flow, pass)
          if (!success) {
            failed <- names(pass)[!vapply(pass, isTRUE, logical(1))]
            lapply(private$REJECTION[failed], function(fun) {
              fun(response, scope, ..., .datastore = datastore)
            })
            if (response$status >= 400) {
              abort_status(response$status)
            }
            return(response$status < 300)
          }
          if (!is.null(scope)) {
            provided_scopes <- unique(unlist(lapply(guards, function(auth) {
              datastore$session[[auth]]$scopes
            })))
            success <- all(scope %in% provided_scopes)
            if (!success) {
              succeeded <- names(pass)[vapply(pass, isTRUE, logical(1))]
              lapply(private$FORBID[succeeded], function(fun) {
                fun(response, scope, ...)
              })
              if (response$status >= 400) {
                abort_status(response$status)
              }
              return(response$status < 300)
            }
          }
          TRUE
        },
        reject_missing_methods = FALSE
      )
      invisible(flow)
    },
    #' @description Add a guard to the plugin
    #' @param guard Either a [Guard] object defining the guard (preferred) or a
    #' function taking the standard route handler arguments (`request`,
    #' `response`, `keys`, and `...`) and returns `TRUE` if the request is valid
    #' and `FALSE` if not.
    #' @param name The name of the guard to be used when defining flow
    #' for endpoint auth.
    #'
    add_guard = function(guard, name = NULL) {
      if (is.function(guard)) {
        guard <- with_dots(guard)
        reject <- function(response) {
          if (response$status == 404L) {
            response$status <- 400L
          }
        }
        forbid <- function(response, scope) {
          response$status <- 403L
        }
      } else {
        if (!is_guard(guard)) {
          cli::cli_abort(
            "{.arg guard} must be a function or a {.cls Guard} object"
          )
        }
        reject <- guard$reject_response
        forbid <- guard$forbid_user
        name <- name %||% guard$name
        guard$name <- name
        guard$register_handler(super$add_handler)
        guard <- guard$check_request
      }
      check_string(name)
      private$GUARDS[[name]] <- guard
      private$REJECTION[[name]] <- reject
      private$FORBID[[name]] <- forbid
    },
    #' @description Defunct overwrite of the `add_handler()` method to prevent
    #' this route to be used for anything other than auth. Will throw
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
        "{.cls Fireproof} does not support adding handlers directly",
        i = "Use the {.fun add_auth} method to add an authentication/authorization handler"
      ))
    },
    #' @description Turns a parsed flow (as returned by `add_auth()`)
    #' into an OpenAPI Security Requirement compliant list. Not all flows can be
    #' represented by the OpenAPI spec and the method will return `NULL` with a
    #' warning if so. Scope is added to all schemes, even if not applicable, so
    #' the final OpenAPI doc should be run through [prune_openapi()] before
    #' serving it.
    #' @param flow A parsed flow as returned by `add_auth()`
    #' @param scope A character vector of scopes required for this particular
    #' flow
    #'
    flow_to_openapi = function(flow, scope) {
      if (!identical(attr(flow, "op"), "||")) {
        flow <- or(flow)
      } # Force outmost to be ||
      if (!is_flow_valid_openapi(flow)) {
        cli::cli_warn(
          "Auth flow `{format(flow)}` cannot be represented by the OpenAPI syntax"
        )
        return(NULL)
      }
      lapply(flow, function(sf) {
        res <- set_names(
          rep(list(scope), length(sf)),
          unlist(sf)
        )
        res
      })
    },
    #' @description Method for use by fiery when attached as a plugin. Should
    #' not be called directly. This method looks for a header route stack in the
    #' app and if it doesn't exist it creates one. It then attaches the plugin
    #' as the first route to it.
    #' @param app The Fire object to attach the router to
    #' @param ... Ignored
    #'
    on_attach = function(app, ...) {
      if (is.null(app$plugins$request_routr)) {
        rs <- routr::RouteStack$new()
        rs$attach_to <- "request"
        app$attach(rs)
      }
      app$plugins$request_routr$add_route(
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
    #' @field require Required plugins for Fireproof
    require = function() {
      "firesale"
    },
    #' @field guards The name of all the guards currently added to the plugin
    guards = function() {
      names(private$GUARDS)
    }
  ),
  private = list(
    GUARDS = list(),
    REJECTION = list(),
    FORBID = list(),
    STORE_NAME = NULL,

    eval_guards = function(
      .guards,
      request,
      response,
      keys,
      ...,
      .datastore = datastore
    ) {
      guards <- private$GUARDS[.guards]
      missing_guards <- lengths(guards) == 0
      if (any(missing_guards)) {
        cli::cli_warn(
          "Ignoring unknown guard{?s} { .guards[missing_guards]}"
        )
        guards[missing_guards] <- list(true_fun)
        names(guards)[missing_guards] <- .guards[missing_guards]
      }
      lapply(guards, function(x) {
        x(
          request = request,
          response = response,
          keys = keys,
          ...,
          .datastore = .datastore
        )
      })
    }
  )
)

true_fun <- function(...) TRUE
parse_auth_flow <- function(expr) {
  flow <- quo_squash(enexpr(expr))
  if (is.null(flow)) {
    return(NULL)
  }
  if (is_call(flow) && is_symbol(flow[[1]], "(")) {
    flow <- flow[[2]]
  }
  if (length(flow) == 1) {
    scalar(gsub('"|\'', "", expr_text(flow)))
  } else {
    op <- expr_name(flow[[1]])
    if (!op %in% c("||", "&&")) {
      cli::cli_abort(
        "Unknown operator for auth flow. Only `||` and `&&` allowed"
      )
    }
    lhs <- parse_auth_flow(!!flow[[2]])
    rhs <- parse_auth_flow(!!flow[[3]])
    elems <- list2(
      !!!if (may_collapse(lhs, op)) lhs else list(lhs),
      !!!if (may_collapse(rhs, op)) rhs else list(rhs)
    )
    if (op == "||") {
      or(!!!elems)
    } else {
      and(!!!elems)
    }
  }
}
