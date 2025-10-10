prefill_paths <- function(
  route,
  get = NULL,
  head = NULL,
  post = NULL,
  put = NULL,
  delete = NULL,
  connect = NULL,
  options = NULL,
  trace = NULL,
  patch = NULL,
  all = NULL
) {
  paths <- list(
    get = get,
    head = head,
    post = post,
    put = put,
    delete = delete,
    connect = connect,
    options = options,
    trace = trace,
    patch = patch,
    all = all
  )
  lapply(names(paths), function(method) {
    lapply(paths[[method]], function(path) {
      route$add_handler(method, path)
    })
  })
  route
}
