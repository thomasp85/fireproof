parse_url <- function(url) {
  re_url <- paste0(
    "^([a-zA-Z0-9]+)://",
    "(?:([^@/:]+)(?::([^@/]+))?@)?",
    "([^/]+)",
    "(.*)$"
  )
  list(
    protocol = sub(re_url, "\\1", url),
    username = sub(re_url, "\\2", url),
    password = sub(re_url, "\\3", url),
    host = sub(re_url, "\\4", url),
    path = sub(re_url, "\\5", url)
  )
}

## Modified from webfakes::oauth2_login to keep cookies around
## Orchestrates token exchange
oauth2_login <- function(login_url) {
  handle <- curl::new_handle()
  login_resp <- curl::curl_fetch_memory(login_url, handle)
  html <- rawToChar(login_resp$content)
  xml <- xml2::read_html(html)
  form <- xml2::xml_find_first(xml, "//form")
  input <- xml2::xml_find_first(form, "//input")
  actn <- xml2::xml_attr(form, "action")
  stnm <- xml2::xml_attr(input, "name")
  stvl <- xml2::xml_attr(input, "value")
  data <- charToRaw(paste0(stnm, "=", stvl, "&", "action=yes"))
  curl::handle_reset(handle)
  curl::handle_setheaders(
    handle,
    `content-type` = "application/x-www-form-urlencoded"
  )
  curl::handle_setopt(
    handle,
    customrequest = "POST",
    postfieldsize = length(data),
    postfields = data
  )
  psurl <- parse_url(login_resp$url)
  actn_url <- paste0(psurl$protocol, "://", psurl$host, actn)
  token_resp <- curl::curl_fetch_memory(actn_url, handle = handle)
  list(login_response = login_resp, token_response = token_resp)
}
