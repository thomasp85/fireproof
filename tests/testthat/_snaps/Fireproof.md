# Fireproof add_guard handles guard name

    Code
      fp$add_guard(custom_guard)
    Condition
      Error in `fp$add_guard()`:
      ! `name` must be a single string, not `NULL`.

# Fireproof add_guard rejects invalid guard types

    Code
      fp$add_guard("not_a_guard", "invalid")
    Condition
      Error in `fp$add_guard()`:
      ! `guard` must be a function or a <Guard> object

---

    Code
      fp$add_guard(123, "invalid")
    Condition
      Error in `fp$add_guard()`:
      ! `guard` must be a function or a <Guard> object

# Fireproof add_auth with NULL flow disables auth

    Code
      fp$dispatch(bad_req, server = new.env(), arg_list = list(datastore = new.env()))
    Condition
      Error in `handler()`:
      ! Unauthorized

# Fireproof add_handler is defunct

    Code
      fp$add_handler("get", "/path", function() { })
    Condition
      Error in `fp$add_handler()`:
      ! <Fireproof> does not support adding handlers directly
      i Use the `add_auth()` method to add an authentication/authorization handler

# Fireproof flow_to_openapi warns on deeply nested flow

    Code
      result <- fp$flow_to_openapi(outer, scope = character())
    Condition
      Warning:
      Auth flow `(((auth1 && auth2) || auth3) && auth1)` cannot be represented by the OpenAPI syntax

# parse_auth_flow rejects invalid operators

    Code
      parse_auth_flow(auth1 + auth2)
    Condition
      Error in `parse_auth_flow()`:
      ! Unknown operator for auth flow. Only `||` and `&&` allowed

---

    Code
      parse_auth_flow(auth1 & auth2)
    Condition
      Error in `parse_auth_flow()`:
      ! Unknown operator for auth flow. Only `||` and `&&` allowed

