package models

// User is the jwt authentication model
type User struct {
	Username string `json:"username"`
	Password string `json:"password"`
}
