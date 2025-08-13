package wrappedjwt

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"database/sql"
	"encoding/pem"
	"fmt"
	"sync"
	"time"

	_ "github.com/jackc/pgx/v5"
	"github.com/lestrrat-go/jwx/v3/jwk"
	_ "github.com/mattn/go-sqlite3"
)

type KeyPurpose string

const (
	KeyPurposeSigning    KeyPurpose = "signing"
	KeyPurposeEncryption KeyPurpose = "encryption"
)

// KeyPair represents a public/private key pair
// -- SQLite Schema
// CREATE TABLE KeyPair (
//     keyID TEXT PRIMARY KEY,
//     privateKey BLOB NOT NULL,
//     publicKey BLOB NOT NULL,
//     CreatedAt DATETIME NOT NULL,
//     Purpose TEXT NOT NULL
// );

// -- PostgreSQL Schema
// CREATE TABLE KeyPair (
//
//	keyID VARCHAR PRIMARY KEY,
//	privateKey BYTEA NOT NULL,
//	publicKey BYTEA NOT NULL,
//	CreatedAt TIMESTAMP NOT NULL,
//	Purpose VARCHAR NOT NULL
//
// );
type KeyPair struct {
	keyID      string
	privateKey crypto.PrivateKey
	publicKey  crypto.PublicKey
	CreatedAt  time.Time
	Purpose    KeyPurpose
	Algorithm  string
	Kty        string
	Curve      string
}

func (kp *KeyPair) Public() crypto.PublicKey {
	return kp.publicKey
}

func (kp *KeyPair) Private() crypto.PrivateKey {
	return kp.privateKey
}

func (kp *KeyPair) KeyID() string {
	return kp.keyID
}

// Get Public and Private Keys in DER format
func (kp *KeyPair) PublicDER() ([]byte, error) {
	return x509.MarshalPKIXPublicKey(kp.Public())
}

func (kp *KeyPair) PrivateDER() ([]byte, error) {
	return x509.MarshalPKCS8PrivateKey(kp.Private())
}

// KeyManager handles key generation and storage
type KeyManager struct {
	cache           map[string]*KeyPair
	mutex           sync.RWMutex
	db              *sql.DB
	initializedAt   time.Time     // Store a timestamp indicating when the KeyManager was initialized
	lastRefreshedAt time.Time     // Store a timestamp indicating the last time the KeyManager was refreshed
	refreshInterval time.Duration // Amount of time before we need to refresh
}

// To connect to SQLite, you need the following information:
// 1. Database File Path: The path to the SQLite database file. If the file does not exist, SQLite will create it.
// 2. SQLite Driver: Use the appropriate SQLite driver for your programming language. In Go, you can use "github.com/mattn/go-sqlite3".
// 3. Connection String: Typically, this is just the file path, but can include additional parameters like cache settings or mode.

func NewKeyManager(driverName string, connectionString string) (*KeyManager, error) {
	var db *sql.DB
	var err error
	switch driverName {
	case "sqlite":
		if db, err = sql.Open("sqlite3", connectionString); err != nil {
			panic(err)
		}
	case "postgres":
		if db, err = sql.Open("postgres", connectionString); err != nil {
			panic(err)
		}
	case "memory":
		db = nil
	default:
		return nil, fmt.Errorf("unsupported driver: %s", driverName)
	}

	return &KeyManager{
		cache:           make(map[string]*KeyPair),
		db:              db,
		initializedAt:   time.Now(),
		lastRefreshedAt: time.Unix(0, 0),
		refreshInterval: 10 * time.Minute,
	}, nil
}

func (km *KeyManager) Close() error {
	return km.db.Close()
}

// GenerateKeyPair creates a new RSA key pair
func (km *KeyManager) GenerateKeyPair(keyID string, purpose KeyPurpose, algorithm string) (*KeyPair, error) {
	// Generate 2048-bit RSA key pair (minimum recommended size)
	// For production, consider 4096-bit for higher security
	var keyPair *KeyPair
	switch algorithm {
	case "rsa":
		privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, fmt.Errorf("failed to generate private key: %w", err)
		}
		publicKey := privateKey.Public()
		keyPair = &KeyPair{
			privateKey: privateKey,
			publicKey:  publicKey,
			keyID:      keyID,
			CreatedAt:  time.Now(),
			Purpose:    purpose,
			Algorithm:  "RSA",
			Kty:        "RSA",
			Curve:      "",
		}
	case "ec":
		privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("failed to generate private key: %w", err)
		}
		publicKey := privateKey.Public()
		keyPair = &KeyPair{
			privateKey: privateKey,
			publicKey:  publicKey,
			keyID:      keyID,
			CreatedAt:  time.Now(),
			Purpose:    purpose,
			Algorithm:  "EC",
			Kty:        "EC",
			Curve:      "P-256",
		}
	case "ed25519":
		publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("failed to generate private key: %w", err)
		}
		keyPair = &KeyPair{
			privateKey: privateKey,
			publicKey:  publicKey,
			keyID:      keyID,
			CreatedAt:  time.Now(),
			Purpose:    purpose,
			Algorithm:  "EdDSA",
			Kty:        "OKP",
			Curve:      "Ed25519",
		}
	default:
		return nil, fmt.Errorf("unsupported algorithm: %s", algorithm)
	}

	// Store in cache
	km.mutex.Lock()
	defer km.mutex.Unlock()

	km.cache[keyID] = keyPair
	if err := km.addKeyToDatabase(keyPair); err != nil {
		return nil, fmt.Errorf("failed to add key to database: %w", err)
	}

	return keyPair, nil
}

// GetKeyPair retrieves a key pair from cache
func (km *KeyManager) FindByID(keyID string) (*KeyPair, bool) {
	_ = km.refreshKeysFromDatabaseIfNeeded()
	km.mutex.RLock()
	defer km.mutex.RUnlock()
	keyPair, exists := km.cache[keyID]
	return keyPair, exists
}

func (km *KeyManager) FindByPurpose(purpose KeyPurpose) (*KeyPair, error) {
	_ = km.refreshKeysFromDatabaseIfNeeded()
	for _, keyPair := range km.cache {
		if keyPair.Purpose == purpose {
			return keyPair, nil
		}
	}
	return nil, nil
}

func (km *KeyManager) FindAllByPurpose(purpose KeyPurpose) ([]*KeyPair, error) {
	_ = km.refreshKeysFromDatabaseIfNeeded()
	km.mutex.RLock()
	defer km.mutex.RUnlock()
	keys := make([]*KeyPair, 0, len(km.cache))
	for _, keyPair := range km.cache {
		if keyPair.Purpose == purpose {
			keys = append(keys, keyPair)
		}
	}
	return keys, nil
}

func (km *KeyManager) FindOrCreateForPurpose(purpose KeyPurpose) (*KeyPair, error) {
	_ = km.refreshKeysFromDatabaseIfNeeded()
	keyPair, err := km.FindByPurpose(purpose)
	if err != nil {
		return nil, err
	}
	if keyPair != nil {
		return keyPair, nil
	}
	id := rand.Text()
	switch purpose {
	case KeyPurposeEncryption:
		return km.GenerateKeyPair(id, purpose, "rsa")
	case KeyPurposeSigning:
		return km.GenerateKeyPair(id, purpose, "ed25519")
	default:
		return nil, fmt.Errorf("unsupported purpose: %s", purpose)
	}
}

// ListKeys returns all cached key IDs
func (km *KeyManager) ListKeys() []string {
	km.mutex.RLock()
	defer km.mutex.RUnlock()

	keys := make([]string, 0, len(km.cache))
	for keyID := range km.cache {
		// Put at the head of the list.
		keys = append([]string{keyID}, keys...)
	}
	return keys
}

// ExportPublicKey exports the public key in PEM format
func (kp *KeyPair) ExportPublicKey() (string, error) {
	publicKeyBytes, err := kp.PublicDER()
	if err != nil {
		return "", fmt.Errorf("failed to marshal public key: %w", err)
	}

	publicKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	})

	return string(publicKeyPEM), nil
}

type PublicKeysData struct {
	Keys []jwk.Key `json:"keys"`
}

func (kp *KeyPair) ExportPublicKeyAsJWK() (jwk.Key, error) {
	key, err := jwk.Import(kp.Public())
	if err != nil {
		return nil, fmt.Errorf("failed to create JWK: %w", err)
	}
	key.Set(jwk.KeyIDKey, kp.KeyID())
	switch kp.Purpose {
	case KeyPurposeSigning:
		key.Set(jwk.KeyUsageKey, "sig")
	case KeyPurposeEncryption:
		key.Set(jwk.KeyUsageKey, "enc")
	default:
		return nil, fmt.Errorf("unsupported purpose: %s", kp.Purpose)
	}
	return key, nil
}

func (km *KeyManager) ExportPublicKeyJWKs() (PublicKeysData, error) {
	keys, err := km.FindAllByPurpose(KeyPurposeSigning)
	keysData := PublicKeysData{
		Keys: make([]jwk.Key, len(keys)),
	}
	if err != nil {
		return keysData, fmt.Errorf("failed to find keys: %w", err)
	}
	for i, key := range keys {
		keysData.Keys[i], err = key.ExportPublicKeyAsJWK()
		if err != nil {
			return keysData, fmt.Errorf("failed to export public key as JWK: %w", err)
		}
	}
	return keysData, nil
}

// ExportPrivateKey exports the private key in PEM format (be careful with this!)
func (kp *KeyPair) ExportPrivateKey() (string, error) {
	privateKeyBytes, err := x509.MarshalPKCS8PrivateKey(kp.Private())
	if err != nil {
		return "", fmt.Errorf("failed to marshal private key: %w", err)
	}

	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privateKeyBytes,
	})

	return string(privateKeyPEM), nil
}

func (km *KeyManager) refreshKeysFromDatabaseIfNeeded() error {
	if km.db == nil {
		return nil
	}

	km.mutex.RLock()
	if time.Since(km.lastRefreshedAt) < km.refreshInterval {
		km.mutex.RUnlock()
		return nil
	}
	km.mutex.RUnlock() // Unlock the read lock before acquiring the write lock

	km.mutex.Lock()
	defer km.mutex.Unlock()
	km.lastRefreshedAt = time.Now()

	rows, err := km.db.Query("SELECT keyID, privateKey, publicKey, Purpose FROM KeyPair")
	if err != nil {
		return fmt.Errorf("failed to query database: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var keyID string
		var privateKeyBytes, publicKeyBytes []byte
		var purpose string

		if err := rows.Scan(&keyID, &privateKeyBytes, &publicKeyBytes, &purpose); err != nil {
			return fmt.Errorf("failed to scan row: %w", err)
		}

		if _, exists := km.cache[keyID]; !exists {
			privateKey, err := x509.ParsePKCS8PrivateKey(privateKeyBytes)
			if err != nil {
				return fmt.Errorf("failed to parse private key: %w", err)
			}

			publicKey, err := x509.ParsePKIXPublicKey(publicKeyBytes)
			if err != nil {
				return fmt.Errorf("failed to parse public key: %w", err)
			}

			km.cache[keyID] = &KeyPair{
				keyID:      keyID,
				privateKey: privateKey,
				publicKey:  publicKey,
				Purpose:    KeyPurpose(purpose),
			}
		}
	}

	if err := rows.Err(); err != nil {
		return fmt.Errorf("row iteration error: %w", err)
	}
	return nil
}

// N.B. This function is called with a lock held
func (km *KeyManager) addKeyToDatabase(keyPair *KeyPair) error {
	if km.db == nil {
		return nil
	}

	privateDER, err := keyPair.PrivateDER()
	if err != nil {
		return fmt.Errorf("failed to marshal private key: %w", err)
	}
	publicDER, err := keyPair.PublicDER()
	if err != nil {
		return fmt.Errorf("failed to marshal public key: %w", err)
	}

	_, err = km.db.Exec("INSERT INTO KeyPair (keyID, privateKey, publicKey, CreatedAt, Purpose) VALUES (?, ?, ?, ?, ?)", keyPair.KeyID(), privateDER, publicDER, time.Now().UTC(), string(keyPair.Purpose))
	if err != nil {
		return fmt.Errorf("failed to execute statement: %w", err)
	}

	return nil
}
