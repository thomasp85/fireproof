# Guard name must be a string

    Code
      auth$name <- 123
    Condition
      Error:
      ! `value` must be a single string, not the number 123.

---

    Code
      auth$name <- c("a", "b")
    Condition
      Error:
      ! `value` must be a single string, not a character vector.

---

    Code
      Guard$new(name = TRUE)
    Condition
      Error in `initialize()`:
      ! `name` must be a single string or `NULL`, not `TRUE`.

