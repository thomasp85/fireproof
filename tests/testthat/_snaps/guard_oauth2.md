# guard_oauth2 requires auth_url for authorization_code grant

    Code
      guard_oauth2(token_url = "https://example.com/oauth/token", redirect_url = "https://myapp.com/auth/callback",
        client_id = "my_client_id", client_secret = "my_client_secret", grant_type = "authorization_code",
        name = "test")
    Condition
      Error in `initialize()`:
      ! `auth_url` must be a single string, not `NULL`.

# guard_oauth2 reject_response for password grant requests basic auth

    Code
      auth$reject_response(no_auth$respond(), scope = NULL, .datastore = datastore)
    Condition
      Error in `private$request_password_authorization()`:
      ! Unauthorized

