
# JWT Token
## Module Configuration
```ini
auth.jwt.realm.name = "REVEL-JWT-AUTH"                  // default is REVEL-JWT-AUTH
auth.jwt.issuer = "REVEL-JWT-AUTH" 				        // use appropriate values (string, URL), default is REVEL-JWT-AUTH
auth.jwt.expiration = 30						        // In minutes, default is 60 minutes
auth.jwt.key.private = "/Users/youruser/private.rsa"
auth.jwt.key.public = "/Users/youruser/public.rsa.pub"
auth.jwt.anonymous = "/token, /freepass/.*"  				// Valid regexp allowed for path
```

## Enabling Auth Module

Add `module.jwtauth = gitlab.com/goevexx/jwtauth` into `conf/app.conf`

## Registering Auth Routes

Add `module:jwtauth` into `conf/routes`. Auth modules enables following routes
```sh
# JWT Auth Routes
POST	/token									JwtAuth.Token
GET		/refresh-token					JwtAuth.RefreshToken
GET		/logout									JwtAuth.Logout
```

## Registering Auth Filter

Revel Filter for JWT Auth Token verification. Register it in the `revel.Filters` in `<APP_PATH>/app/init.go`

```go
// Add jwt.AuthFilter anywhere deemed appropriate, it must be register after revel.PanicFilter
revel.Filters = []revel.Filter{
  revel.PanicFilter,
	...
	jwt.AuthFilter,		// JWT Auth Token verification for Request Paths
	...
}
// Note: If everything looks good then Claims map made available via c.Args
// and can be accessed using c.Args[jwt.TOKEN_CLAIMS_KEY]
```

## Register Auth Handler

Auth handler is responsible for validate user and returning `Subject (aka sub)` value and success/failure boolean. It should comply [AuthHandler](https://github.com/goevexx/jwtauth/blob/master/app/jwt/jwt.go#L31) interface or use raw func via [jwt.AuthHandlerFunc](https://github.com/goevexx/jwtauth/blob/master/app/jwt/jwt.go#L37).
```go
revel.OnAppStart(func() {
	jwt.Init(&MyAuth{})
	//          OR
	jwt.Init(jwt.AuthHandlerFunc(func(username, password string) (string, bool) {
		revel.AppLog.Infof("Username: %v, Password: %v", username, password)
		return "This is my subject value from function", true
	}))
})
```

## Configuration

```ini
# Configure jwtauth
# defaults: 
# realm.name
#   "REVEL-JWT-AUTH"
# issuer (use appropriate values (string, URL))
#   "REVEL-JWT-AUTH"
# expiration (in minutes)
#   60
# anonymous (valid regexp allowed for path)
```
