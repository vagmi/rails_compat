package rails_compat

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"errors"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/pbkdf2"
	"strings"
)

const salt = "encrypted cookie"
const WARDEN_FORMAT_ERROR = "warden user key format invalid"

var keyCache = make(map[string][]byte)

type encrypted struct {
	data []byte
	iv   []byte
}

func decrypt(key []byte, cipherData encrypted) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		log.Panic(err)
	}
	if len(cipherData.data) < aes.BlockSize {
		log.Panic("cipher text is too short")
	}
	if len(cipherData.data)%aes.BlockSize != 0 {
		log.Panic("cipher text is not a multiple of block size")
	}
	mode := cipher.NewCBCDecrypter(block, cipherData.iv)
	plainBytes := make([]byte, len(cipherData.data))
	mode.CryptBlocks(plainBytes, cipherData.data)
	return plainBytes
}

func keyFromBase(keyBase, salt string) []byte {
	if fromCache, ok := keyCache[keyBase]; ok {
		return fromCache
	}
	iterations := 1000
	keySize := 64
	key := pbkdf2.Key([]byte(keyBase), []byte(salt), iterations, keySize, sha1.New)[:32]
	keyCache[keyBase] = key
	return key
}

func decodeCookie(cookie string) encrypted {
	// weird corner case when Rails5 decides to add other information to the encrypted cookie
	if strings.Contains(cookie, "--") {
		cookie = strings.Split(cookie, "--")[0]
	}
	cookieBytes, err := base64.StdEncoding.DecodeString(cookie)
	if err != nil {
		log.Panic(err)
	}
	split := strings.Split(string(cookieBytes), "--")
	strEnc := split[0]
	strIv := split[1]
	data, err := base64.StdEncoding.DecodeString(strEnc)
	if err != nil {
		log.Panic(err)
	}
	iv, err := base64.StdEncoding.DecodeString(strIv)
	if err != nil {
		log.Panic(err)
	}
	return encrypted{data: data, iv: iv}
}

// DecodeRailsSession takes a rails cookie, and the secret_key_base from your secrets.yml
// and decrypts the session as a string
func DecodeRailsSession(cookie, keyBase string) string {
	cipherData := decodeCookie(cookie)
	key := keyFromBase(keyBase, salt)
	return string(decrypt(key, cipherData))
}

// ExtractUserId extracts User Id from the decrypted cookie
// Please note that it assumes that the model name is user
func ExtractUserId(jsonString string) (int, error) {
	buffer := bytes.NewBuffer([]byte(jsonString))
	decoder := json.NewDecoder(buffer)
	var sess map[string]interface{}
	err := decoder.Decode(&sess)
	if err != nil {
		return -1, err
	}
	wUserKey, ok := sess["warden.user.user.key"]
	if !ok {
		return -1, errors.New(WARDEN_FORMAT_ERROR)
	}
	ints, ok := wUserKey.([]interface{})[0].([]interface{})
	if !ok {
		return -1, errors.New(WARDEN_FORMAT_ERROR)
	}
	userId, ok := ints[0].(float64)
	if !ok {
		return -1, errors.New(WARDEN_FORMAT_ERROR)
	}
	return int(userId), nil
}
