package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/ecdsa"
	"github.com/corvus-ch/shamir"
	"github.com/tyler-smith/go-bip32"
)

const nitridingURL = "http://127.0.0.1:8080"

// Root keys for the enclave
var (
	rootPrivKey *btcec.PrivateKey
	rootPubKey  *btcec.PublicKey
)

// In-memory storage for Enclave shards
var (
	shardsStore = make(map[string][]byte) // key: wallet address, value: enclave shard
	storeMutex  sync.RWMutex
)

// Request structures
type CreateWalletRequest struct {
	UserID            string `json:"user_id"`
	LoginToken        string `json:"login_token"`
	Nonce             string `json:"nonce"`
	EncryptedPassword string `json:"encrypted_password"` // encrypted with rootPubKey
}

type SignatureRequest struct {
	KeyShard string `json:"key_shard_b64"`
	PubKey   string `json:"pub_key"`
	TxHash   string `json:"tx_hash"`
}

// Response structures
type CreateWalletResponse struct {
	AuthShare    string `json:"auth_share"`    // encrypted with userPassword + rootPrivKey
	UserShare    string `json:"user_share"`    // encrypted with userPassword + rootPrivKey
	DeviceShare  string `json:"device_share"`  // encrypted with userPassword
	RecoverShare string `json:"recover_share"` // encrypted with userPassword
	PublicKey    string `json:"public_key"`
	SignedNonce  string `json:"signed_nonce"` // nonce signed with rootPrivKey
}

type SignatureResponse struct {
	Signature string `json:"signature"`
}

// Initialize root keys and register with nitriding
func initializeRootKeys() error {
	var err error
	rootPrivKey, err = btcec.NewPrivateKey()
	if err != nil {
		return fmt.Errorf("failed to generate root private key: %w", err)
	}
	rootPubKey = rootPrivKey.PubKey()

	// Register hash of rootPubKey with nitriding
	pubKeyBytes := rootPubKey.SerializeCompressed()
	pubKeyHash := sha256.Sum256(pubKeyBytes)
	pubKeyHashB64 := base64.StdEncoding.EncodeToString(pubKeyHash[:])

	resp, err := http.Post(
		nitridingURL+"/enclave/hash",
		"text/plain",
		bytes.NewReader([]byte(pubKeyHashB64)),
	)
	if err != nil {
		return fmt.Errorf("failed to register hash with nitriding: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("nitriding returned status %d", resp.StatusCode)
	}

	log.Printf("[go] Root keys initialized. Public key: %s\n", hex.EncodeToString(pubKeyBytes))
	return nil
}

// Decrypt password using rootPrivKey (Standard AES-GCM ECIES-like)
func decryptPassword(encryptedPasswordB64 string) (string, error) {
	encryptedData, err := base64.StdEncoding.DecodeString(encryptedPasswordB64)
	if err != nil {
		return "", fmt.Errorf("failed to decode b64: %w", err)
	}

	// 标准布局: [PubKey(33)] + [IV(12)] + [Ciphertext + Tag(min 16)]
	const (
		pubKeyLen = 33
		ivLen     = 12
		tagLen    = 16
	)

	if len(encryptedData) < pubKeyLen+ivLen+tagLen {
		return "", fmt.Errorf("encrypted data too short, length: %d", len(encryptedData))
	}

	// 1. 提取临时公钥
	ephemeralPubKeyBytes := encryptedData[:pubKeyLen]
	ephemeralPubKey, err := btcec.ParsePubKey(ephemeralPubKeyBytes)
	if err != nil {
		return "", fmt.Errorf("failed to parse ephemeral public key: %w", err)
	}

	// 2. 计算共享密钥 (ECDH)
	sharedSecret := btcec.GenerateSharedSecret(rootPrivKey, ephemeralPubKey)
	key := sha256.Sum256(sharedSecret)

	// 3. 提取 IV 和 密文(含Tag)
	iv := encryptedData[pubKeyLen : pubKeyLen+ivLen]
	ciphertext := encryptedData[pubKeyLen+ivLen:]

	// 4. AES-GCM 解密
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block) // 现在可以使用标准的 NewGCM，因为 IV 是 12 字节
	if err != nil {
		return "", err
	}

	plaintext, err := gcm.Open(nil, iv, ciphertext, nil)
	if err != nil {
		return "", fmt.Errorf("decryption failed (wrong key or corrupted data): %w", err)
	}

	return string(plaintext), nil
}

// Encrypt data with AES-256-GCM using password-derived key
func encryptWithPassword(data []byte, password string) (string, error) {
	// Derive key from password
	key := sha256.Sum256([]byte(password))

	block, err := aes.NewCipher(key[:])
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// Encrypt data with both password and rootPrivKey (double encryption)
func encryptWithPasswordAndRoot(data []byte, password string) (string, error) {
	// First encrypt with password
	passwordKey := sha256.Sum256([]byte(password))

	// Then encrypt with root key
	rootKey := sha256.Sum256(rootPrivKey.Serialize())

	// Combine keys
	combinedKey := sha256.Sum256(append(passwordKey[:], rootKey[:]...))

	block, err := aes.NewCipher(combinedKey[:])
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// Generate deterministic private key from user metadata
func generateUserPrivateKey(userID, loginToken, nonce string, timestamp int64) ([]byte, error) {
	// 1. 获取 32 字节的硬件级随机数
	// 在 Nitro Enclave 中，这会调用底层经由硬件认证的随机数生成器
	extraEntropy := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, extraEntropy); err != nil {
		return nil, fmt.Errorf("failed to read hardware entropy: %w", err)
	}

	// 2. 组合所有确定性输入
	// 包含元数据、时间戳以及纳秒，确保输入的唯一性
	deterministicInput := fmt.Sprintf("%s:%s:%s:%d:%d",
		userID,
		loginToken,
		nonce,
		timestamp,
		time.Now().UnixNano(),
	)

	// 3. 将确定性数据与硬件随机数混合
	// 使用 SHA-256 混合所有熵源，生成最终的私钥种子
	h := sha256.New()
	h.Write([]byte(deterministicInput))
	h.Write(extraEntropy)

	// 最终生成的 hash[:] 即为私钥
	return h.Sum(nil), nil
}

// Sign nonce with rootPrivKey
func signNonce(nonce string) (string, error) {
	nonceHash := sha256.Sum256([]byte(nonce))
	signature := ecdsa.Sign(rootPrivKey, nonceHash[:])
	return base64.StdEncoding.EncodeToString(signature.Serialize()), nil
}

// signalReady notifies nitriding that the application is ready.
func signalReady() error {
	resp, err := http.Get(nitridingURL + "/enclave/ready")
	if err != nil {
		return fmt.Errorf("failed to signal ready: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("expected status code %d but got %d", http.StatusOK, resp.StatusCode)
	}
	return nil
}

// createWalletHandler handles the creation of new wallets with enhanced security
func createWalletHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req CreateWalletRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	// 1. Decrypt user password
	userPassword, err := decryptPassword(req.EncryptedPassword)
	if err != nil {
		log.Printf("[go] Failed to decrypt password: %v\n", err)
		http.Error(w, "Failed to decrypt password", http.StatusBadRequest)
		return
	}

	// 2. Generate private key from user metadata
	timestamp := time.Now().Unix()
	privateKeyBytes, err := generateUserPrivateKey(req.UserID, req.LoginToken, req.Nonce, timestamp)
	if err != nil {
		http.Error(w, "Failed to generate key", http.StatusInternalServerError)
		return
	}

	// 3. Split into 3 shards with threshold 2
	parts, err := shamir.Split(privateKeyBytes, 3, 2)
	if err != nil {
		http.Error(w, "Failed to split secret", http.StatusInternalServerError)
		return
	}

	// Extract shards deterministically
	var shardIDs []byte
	for k := range parts {
		shardIDs = append(shardIDs, k)
	}

	shard1ID := shardIDs[0]
	shard2ID := shardIDs[1]
	shard3ID := shardIDs[2]

	shard1 := append([]byte{shard1ID}, parts[shard1ID]...)
	shard2 := append([]byte{shard2ID}, parts[shard2ID]...)
	shard3 := append([]byte{shard3ID}, parts[shard3ID]...)

	// 4. Encrypt shards
	// auth_share (shard1): encrypted with password + rootPrivKey
	authShare, err := encryptWithPasswordAndRoot(shard1, userPassword)
	if err != nil {
		http.Error(w, "Failed to encrypt auth share", http.StatusInternalServerError)
		return
	}

	// user_share (shard2): encrypted with password + rootPrivKey
	userShare, err := encryptWithPasswordAndRoot(shard2, userPassword)
	if err != nil {
		http.Error(w, "Failed to encrypt user share", http.StatusInternalServerError)
		return
	}

	// device_share (shard2): encrypted with password only
	deviceShare, err := encryptWithPassword(shard2, userPassword)
	if err != nil {
		http.Error(w, "Failed to encrypt device share", http.StatusInternalServerError)
		return
	}

	// recover_share (shard3): encrypted with password only
	recoverShare, err := encryptWithPassword(shard3, userPassword)
	if err != nil {
		http.Error(w, "Failed to encrypt recover share", http.StatusInternalServerError)
		return
	}

	// 5. Generate public key for wallet address
	privKey, _ := btcec.PrivKeyFromBytes(privateKeyBytes)
	pubKeyHex := hex.EncodeToString(privKey.PubKey().SerializeCompressed())

	// 6. Store shard1 (auth_share) in enclave memory
	storeMutex.Lock()
	shardsStore[pubKeyHex] = shard1
	storeMutex.Unlock()

	// 7. Sign nonce with rootPrivKey
	signedNonce, err := signNonce(req.Nonce)
	if err != nil {
		http.Error(w, "Failed to sign nonce", http.StatusInternalServerError)
		return
	}

	// 8. Return response
	resp := CreateWalletResponse{
		AuthShare:    authShare,
		UserShare:    userShare,
		DeviceShare:  deviceShare,
		RecoverShare: recoverShare,
		PublicKey:    pubKeyHex,
		SignedNonce:  signedNonce,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
	log.Printf("[go] Created wallet for user %s: %s\n", req.UserID, pubKeyHex)
}

// sssSignatureHandler handles signing using combined shards
func sssSignatureHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req SignatureRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	// 1. Get enclave shard from memory
	storeMutex.RLock()
	enclavePart, ok := shardsStore[req.PubKey]
	storeMutex.RUnlock()
	if !ok {
		http.Error(w, "Wallet not found", http.StatusNotFound)
		return
	}

	// 2. Decode user shard
	userPart, err := base64.StdEncoding.DecodeString(req.KeyShard)
	if err != nil {
		http.Error(w, "Invalid user shard", http.StatusBadRequest)
		return
	}

	// 3. Combine shards
	selection := map[byte][]byte{
		enclavePart[0]: enclavePart[1:],
		userPart[0]:    userPart[1:],
	}
	recoveredSecret, err := shamir.Combine(selection)
	if err != nil {
		http.Error(w, "Failed to combine shards", http.StatusInternalServerError)
		return
	}

	// 4. Derive child key (BIP44)
	master, _ := bip32.NewMasterKey(recoveredSecret)
	purpose, _ := master.NewChildKey(bip32.FirstHardenedChild + 44)
	coin, _ := purpose.NewChildKey(bip32.FirstHardenedChild + 60)
	account, _ := coin.NewChildKey(bip32.FirstHardenedChild + 0)
	change, _ := account.NewChildKey(0)
	addressKey, _ := change.NewChildKey(0)

	privKey, _ := btcec.PrivKeyFromBytes(addressKey.Key)

	txHashBytes, err := hex.DecodeString(req.TxHash)
	if err != nil {
		txHashBytes = []byte(req.TxHash)
	}

	// Sign using ECDSA
	sig := ecdsa.Sign(privKey, txHashBytes)

	resp := SignatureResponse{
		Signature: base64.StdEncoding.EncodeToString(sig.Serialize()),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
	log.Printf("[go] Signed tx for wallet: %s\n", req.PubKey)
}

func main() {
	// Initialize root keys
	if err := initializeRootKeys(); err != nil {
		log.Fatalf("Failed to initialize root keys: %v", err)
	}

	// Register HTTP handlers
	http.HandleFunc("/app/sss/key", createWalletHandler)
	http.HandleFunc("/app/sss/signature", sssSignatureHandler)

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Go Safe Wallet Service Running\n")
	})

	go func() {
		log.Println("[go] Running server on port 8088")
		if err := http.ListenAndServe(":8088", nil); err != nil {
			log.Fatalf("Server failed: %v", err)
		}
	}()

	// Signal ready to nitriding
	time.Sleep(1 * time.Second)
	if err := signalReady(); err != nil {
		log.Printf("[go] Error signaling ready: %v\n", err)
	} else {
		log.Println("[go] Signalled to nitriding that we're ready.")
	}

	// Keep main running
	select {}
}
