// go mod init example.com/nestedjwt
// go get github.com/go-jose/go-jose/v3

package wrappedjwt

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"fmt"
	"maps"
	"time"

	jose "github.com/go-jose/go-jose/v3"
	"github.com/golang-jwt/jwt/v5"
)

// WrapInnerJWT encrypts an existing compact JWS string as a JWE (RSA-OAEP-256 + A256GCM).
// Adds headers: typ="JWE", cty="JWT", and optional kid.
func createJWEToken(innerJWT string, recipientPub crypto.PublicKey, kid string) (string, error) {
	opts := (&jose.EncrypterOptions{}).
		WithType("JWE").        // typ: JWE
		WithContentType("JWT"). // cty: JWT (payload is another JWT)
		WithHeader("kid", kid)

	encrypter, err := jose.NewEncrypter(
		jose.A256GCM, // content encryption
		jose.Recipient{
			Algorithm: jose.RSA_OAEP_256, // key management
			Key:       recipientPub,
		},
		opts,
	)
	if err != nil {
		return "", err
	}
	jweObj, err := encrypter.Encrypt([]byte(innerJWT))
	if err != nil {
		return "", err
	}
	return jweObj.CompactSerialize()
}

func decryptJWE(jwe string, recipientPriv crypto.PrivateKey) (string, error) {
	parsed, err := jose.ParseEncrypted(jwe)
	if err != nil {
		return "", err
	}
	decrypted, err := parsed.Decrypt(recipientPriv)
	if err != nil {
		return "", err
	}
	return string(decrypted), nil
}

type EmbeddedTokenClaims struct {
	jwt.RegisteredClaims
	EmbeddedToken string `json:"t"`
}

type UpstreamTokenWrapper struct {
	KeyManager *KeyManager
}

func NewUpstreamTokenWrapper(keyManager *KeyManager) *UpstreamTokenWrapper {
	return &UpstreamTokenWrapper{
		KeyManager: keyManager,
	}
}

type WrapRequest struct {
	Token            string
	Issuer           string
	Subject          string
	Audience         string
	AdditionalClaims jwt.MapClaims
}

func (w *UpstreamTokenWrapper) Wrap(request WrapRequest) (string, error) {
	encKey, err := w.KeyManager.FindOrCreateForPurpose(KeyPurposeEncryption)
	if err != nil {
		return "", err
	}
	signKey, err := w.KeyManager.FindOrCreateForPurpose(KeyPurposeSigning)
	if err != nil {
		return "", err
	}

	jwe, err := createJWEToken(request.Token, encKey.Public(), encKey.KeyID())
	if err != nil {
		return "", err
	}

	claims := jwt.MapClaims{
		"iss": request.Issuer,
		"sub": request.Subject,
		"aud": request.Audience,
	}
	maps.Copy(claims, request.AdditionalClaims)

	claims["t"] = jwe
	claims["iat"] = time.Now().Unix()
	claims["exp"] = time.Now().Add(10 * time.Minute).Unix()
	claims["alg"] = jwt.SigningMethodRS256.Alg()
	claims["typ"] = "JWT"
	claims["kid"] = signKey.KeyID()

	signingMethod := findSigningMethod(signKey.Private())
	token := jwt.NewWithClaims(signingMethod, claims)
	return token.SignedString(signKey.Private())
}

func findSigningMethod(privateKey crypto.PrivateKey) jwt.SigningMethod {
	switch privateKey.(type) {
	case rsa.PrivateKey:
		return jwt.SigningMethodRS256
	case ecdsa.PrivateKey:
		return jwt.SigningMethodES256
	case ed25519.PrivateKey:
		return jwt.SigningMethodEdDSA
	default:
		panic(fmt.Sprintf("unsupported signing method: %T", privateKey))
	}
}

// Unwraps (decrypts) the outer JWT back to the original compact JWS string.
func (w *UpstreamTokenWrapper) Unwrap(token string) (string, error) {
	// N.B.: We don't ever need to create a key since this requires
	// an existing key.
	encKey, err := w.KeyManager.FindByPurpose(KeyPurposeEncryption)
	if err != nil {
		return "", err
	}
	signKey, err := w.KeyManager.FindByPurpose(KeyPurposeSigning)
	if err != nil {
		return "", err
	}
	outer, err := jwt.ParseWithClaims(token, &EmbeddedTokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		return signKey.Public(), nil
	})
	if err != nil {
		return "", err
	}

	claims := outer.Claims.(*EmbeddedTokenClaims)
	if claims.EmbeddedToken == "" {
		return "", fmt.Errorf("no embedded token found")
	}
	return decryptJWE(claims.EmbeddedToken, encKey.Private())
}
