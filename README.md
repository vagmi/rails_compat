# Rails Compat Mode

This is is a simple Go package that enables you to read Rails cookies set by
Devise and Warden in Go. 

## Why do you need it?

When you want to port over a rails app to a go codebase but you still want to
access the user id from Go, then you use this package to get the user key.

## Usage


```go
// keyBase is from environment variable SECRET_KEY_BASE
var sess = map[string]interface{}
decrypted = rails_compat.DecodeRailsSession(cookie, keyBase)
buffer := bytes.NewBuffer([]byte(decrypted))
decoder = json.NewDecoder(buffer)
err := decoder.Decode(&sess)

// The user id is present in the `warden.user.user.key` as the first item of the first item in the array
// I have a utility method to extract it.
uid, err = rails_compat.ExtractUserId(decrypted)
```
