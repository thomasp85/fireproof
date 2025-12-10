# guard_bearer rejects multiple token transmission methods

    Code
      auth$check_request(request = multi_auth, response = multi_auth$respond(), keys = list(),
      .datastore = datastore)
    Condition
      Error in `auth$check_request()`:
      ! Clients MUST NOT use more than one method to transmit a bearer token

