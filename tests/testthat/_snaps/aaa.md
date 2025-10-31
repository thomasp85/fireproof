# get_path handles root that doesn't match

    Code
      get_path("https://example.com/auth", root = "/api")
    Condition
      Error in `get_path()`:
      ! `root` not part of `url`

---

    Code
      get_path("https://example.com/v1/auth", root = "/v2")
    Condition
      Error in `get_path()`:
      ! `root` not part of `url`

