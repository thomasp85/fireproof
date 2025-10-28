and <- function(...) {
  structure(
    list2(...),
    class = "fireproof_op",
    op = "&&"
  )
}
or <- function(...) {
  structure(
    list2(...),
    class = "fireproof_op",
    op = "||"
  )
}
scalar <- function(x) {
  structure(list(x), class = "fireproof_op", op = NULL)
}
may_collapse <- function(x, op) {
  (attr(x, "op") %||% op) == op
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

is_flow_valid_openapi <- function(flow) {
  attr(flow, "op") == "||" && flow_depth(flow) <= 3
}
flow_depth <- function(flow) {
  if (length(flow) == 1) {
    return(1L)
  }
  max(vapply(flow, flow_depth, integer(1))) + 1L
}
