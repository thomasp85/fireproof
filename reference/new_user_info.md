# Well structured user information

Different services and authentication schemes may present user
information in different ways. To ensure ease of interoperability,
fireproof will attempt to standardize the information as it gets
extracted by the service. This function is intended to be called to
construct the output of `user_info` function.

## Usage

``` r
new_user_info(
  provider = NULL,
  id = NULL,
  name_display = NULL,
  name_given = NULL,
  name_middle = NULL,
  name_family = NULL,
  name_user = NULL,
  emails = NULL,
  photos = NULL,
  ...
)
```

## Arguments

- provider:

  A string naming the provider of the user information

- id:

  A unique identifier of this user

- name_display, name_given, name_middle, name_family, name_user:

  The legal name of the user. Will be combined to a single `name` field
  in the output with the structure
  `c(given = name_given, middle = name_middle, family = name_family, display = name_display, user = name_user)`

- emails:

  A character vector of emails to the user. The vector can be named in
  which case the names correspond to the category of email, e.g. "work",
  "home" etc.

- photos:

  A character vector of urls pointing to profile pictures of the user.

- ...:

  Additional named arguments to be added to the user information

## Value

A list of class `fireproof_user_info`. The fields of the list are as
provided in the arguments except for the `name_*` arguments which will
be combined to a single field. See the description of these arguments
for more information.

## Setting user information

Each authentication scheme will write to a field in the session data
store named after its own name. What gets written can sometimes be
influenced by the user by passing in a function to the `user_info`
argument of the constructor. This output of this function will be
combined with default information from the guard before being saved in
the session storage (e.g. the `scopes` field is always created
automatically).

## Examples

``` r
new_user_info(
  provider = "local",
  id = 1234,
  name_display = "thomasp85",
  name_given = "Thomas",
  name_middle = "Lin",
  name_family = "Pedersen"
)
#> $provider
#> [1] "local"
#> 
#> $id
#> [1] 1234
#> 
#> $name
#>       given      middle      family     display 
#>    "Thomas"       "Lin"  "Pedersen" "thomasp85" 
#> 
#> $emails
#> NULL
#> 
#> $photos
#> NULL
#> 
#> attr(,"class")
#> [1] "fireproof_user_info"

```
