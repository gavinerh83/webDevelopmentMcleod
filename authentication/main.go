package main

import (
	"crypto/hmac"
	"fmt"
	"time"

	"crypto/sha512"

	"github.com/dgrijalva/jwt-go"
	"golang.org/x/crypto/bcrypt"
)

var key = []byte{}

type UserClaims struct { //create claims object, custom claim object
	jwt.StandardClaims
	SessionID int64
}

func (u *UserClaims) Valid() error {
	if !u.VerifyExpiresAt(time.Now().Unix(), true) {
		return fmt.Errorf("Token has expired")
	}
	if u.SessionID == 0 {
		return fmt.Errorf("Invalid session")
	}
	return nil
}

//creating tokens based on the claims
func createToken(c *UserClaims) (string, error) {
	//start with function newWithClaims
	token := jwt.NewWithClaims(jwt.SigningMethodHS512, c)
	signedToken, err := token.SignedString(key)
	if err != nil {
		return "", fmt.Errorf("Error in createToken when signing token")
	}
	return signedToken, nil
}

func main() {
	for i := 1; i <= 64; i++ {
		key = append(key, byte(i))
	}
	pass := "123456789"

	//generating a hashed version of password
	hash, err := hashPassword(pass)
	if err != nil {
		panic(err)
	}
	err = comparePassword(pass, hash)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println("Correct password entered")
}

//Generating a hashing password from incoming password string
func hashPassword(password string) ([]byte, error) {
	bs, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("Error while generating bcrypt hash from password")
	}
	return bs, nil
}

func comparePassword(password string, hashedPassword []byte) error {
	err := bcrypt.CompareHashAndPassword(hashedPassword, []byte(password))
	if err != nil {
		return fmt.Errorf("invalid password")
	}
	return nil
}

//takes a password and creates a hash version of it
func signMessage(msg []byte) ([]byte, error) {
	//hmac requires a hashing algorithm
	hash := hmac.New(sha512.New, key)

	//after getting the hash above, the hash is also a io.writer
	//msg is written to the hash
	_, err := hash.Write(msg)
	if err != nil {
		return nil, fmt.Errorf("Error in signMessage while hashing message")
	}
	//use the hash sum function, if you use the write method for the hash, the parameters for Sum is nil
	signature := hash.Sum(nil)

	return signature, nil
}

//compare the signed message and the new input
func checkSig(msg, sig []byte) (bool, error) {
	newSig, err := signMessage(msg)
	if err != nil {
		return false, fmt.Errorf("Error in checkSig while getting signature if message")
	}
	//comparing the newSig and the original signature
	same := hmac.Equal(newSig, sig)
	return same, nil
}
