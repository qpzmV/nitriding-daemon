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

	"math/big"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/ecdsa"
	"github.com/corvus-ch/shamir"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/tyler-smith/go-bip32"

	"crypto/ed25519"

	"golang.org/x/crypto/blake2b"
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
	RootPubKey        string `json:"tee_pk"`
}

type SignatureRequest struct {
	EncryptedPassword string `json:"encrypted_password"` // encrypted with rootPubKey
	DeviceShare       string `json:"device_share"`       // encrypted with userPassword
	PubKey            string `json:"pub_key"`
	RawTx             string `json:"raw_tx"`     // hex encoded raw transaction bytes
	AuthShare         string `json:"auth_share"` // [Optional] encrypted with userPassword + rootPubKey
}

// Response structures
type CreateWalletResponse struct {
	AuthShare       string `json:"auth_share"`    // encrypted with userPassword + rootPrivKey
	UserShare       string `json:"user_share"`    // encrypted with userPassword + rootPrivKey
	DeviceShare     string `json:"device_share"`  // encrypted with userPassword
	RecoverShare    string `json:"recover_share"` // encrypted with userPassword
	WalletPublicKey string `json:"wallet_public_key"`
	SuiPublicKey    string `json:"sui_public_key"` // New SUI Public Key
	SignedNonce     string `json:"signed_nonce"`   // nonce signed with rootPrivKey
	Password        string `json:"password"`       // 仅开发测试时用 生产一定要去掉
}

type SignatureResponse struct {
	Signature       string `json:"signature"`
	WalletPublicKey string `json:"wallet_public_key"`
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

// getRootPubKeyHandler 返回当前 Enclave 的 Root 公钥 (Hex 格式)
func getRootPubKeyHandler(w http.ResponseWriter, r *http.Request) {
	if rootPubKey == nil {
		http.Error(w, "Root key not initialized", http.StatusInternalServerError)
		return
	}

	pubKeyBytes := rootPubKey.SerializeCompressed()
	pubKeyHex := hex.EncodeToString(pubKeyBytes)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"public_key": pubKeyHex,
		"status":     "initialized",
	})
}

// testWalletPubKeyHandler 用于测试，固定初始化并返回同一个 WalletPublicKey 和配套分片
func testWalletPubKeyHandler(w http.ResponseWriter, r *http.Request) {
	var req CreateWalletRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	// 1. 固定一个 32 字节的种子私钥
	testSeedHex := "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
	testSeed, _ := hex.DecodeString(testSeedHex)

	// 解密用户密码，为了兼容现有逻辑，我们这里解密 req.EncryptedPassword
	userPassword, err := decryptPassword(req.EncryptedPassword)
	if err != nil {
		http.Error(w, "Failed to decrypt password", http.StatusBadRequest)
		return
	}

	// 2. 生成 BIP44 公钥
	master, _ := bip32.NewMasterKey(testSeed)
	purpose, _ := master.NewChildKey(bip32.FirstHardenedChild + 44)
	coin, _ := purpose.NewChildKey(bip32.FirstHardenedChild + 60)
	account, _ := coin.NewChildKey(bip32.FirstHardenedChild + 0)
	change, _ := account.NewChildKey(0)
	addressKey, _ := change.NewChildKey(0)
	derivedPrivKey, _ := btcec.PrivKeyFromBytes(addressKey.Key)
	pubKeyHex := hex.EncodeToString(derivedPrivKey.PubKey().SerializeCompressed())

	// 2.2 生成 SUI 公钥 (Ed25519, path: m/44'/784'/0'/0'/0')
	suiPurpose, _ := master.NewChildKey(bip32.FirstHardenedChild + 44)
	suiCoin, _ := suiPurpose.NewChildKey(bip32.FirstHardenedChild + 784)
	suiAccount, _ := suiCoin.NewChildKey(bip32.FirstHardenedChild + 0)
	suiChange, _ := suiAccount.NewChildKey(bip32.FirstHardenedChild + 0)
	suiAddressKey, _ := suiChange.NewChildKey(bip32.FirstHardenedChild + 0)
	suiPrivKey := ed25519.NewKeyFromSeed(suiAddressKey.Key)
	suiPubKeyHex := hex.EncodeToString(suiPrivKey.Public().(ed25519.PublicKey))

	// 3. 将种子私钥分成 3 个分片，阈值为 2
	parts, err := shamir.Split(testSeed, 3, 2)
	if err != nil {
		http.Error(w, "Failed to split secret", http.StatusInternalServerError)
		return
	}

	var shardIDs []byte
	for k := range parts {
		shardIDs = append(shardIDs, k)
	}
	shard1 := append([]byte{shardIDs[0]}, parts[shardIDs[0]]...)
	shard2 := append([]byte{shardIDs[1]}, parts[shardIDs[1]]...)
	shard3 := append([]byte{shardIDs[2]}, parts[shardIDs[2]]...)

	// 4. 将分片 1 存入 Enclave 内存 (模拟存储)
	storeMutex.Lock()
	shardsStore[pubKeyHex] = shard1
	storeMutex.Unlock()

	// 5. 按照 createWalletHandler 的逻辑加密所有分片返回
	authShare, _ := encryptWithPasswordAndRoot(shard1, userPassword)
	userShare, _ := encryptWithPasswordAndRoot(shard2, userPassword)
	deviceShare, _ := encryptWithPassword(shard2, userPassword)
	recoverShare, _ := encryptWithPassword(shard3, userPassword)

	// 6. 签名 nonce
	signedNonce, _ := signNonce(req.Nonce)

	resp := CreateWalletResponse{
		AuthShare:       authShare,
		UserShare:       userShare,
		DeviceShare:     deviceShare,
		RecoverShare:    recoverShare,
		WalletPublicKey: pubKeyHex,
		SuiPublicKey:    suiPubKeyHex,
		SignedNonce:     signedNonce,
		Password:        userPassword,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// Decrypt password using rootPrivKey (Standard AES-GCM ECIES-like)
// getFixedSuiPubKeyForTestHandler 用于测试，固定初始化并返回 SUI 公钥和配套分片
func getFixedSuiPubKeyForTestHandler(w http.ResponseWriter, r *http.Request) {
	var req CreateWalletRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	// 1. 固定一个 32 字节的种子私钥
	testSeedHex := "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
	testSeed, _ := hex.DecodeString(testSeedHex)

	// 解密用户密码
	userPassword, err := decryptPassword(req.EncryptedPassword)
	if err != nil {
		http.Error(w, "Failed to decrypt password", http.StatusBadRequest)
		return
	}

	// 2. 生成基于 BIP44 的 EVM 公钥 (用于索引)
	master, _ := bip32.NewMasterKey(testSeed)
	purpose, _ := master.NewChildKey(bip32.FirstHardenedChild + 44)
	coin, _ := purpose.NewChildKey(bip32.FirstHardenedChild + 60)
	account, _ := coin.NewChildKey(bip32.FirstHardenedChild + 0)
	change, _ := account.NewChildKey(0)
	addressKey, _ := change.NewChildKey(0)
	derivedPrivKey, _ := btcec.PrivKeyFromBytes(addressKey.Key)
	pubKeyHex := hex.EncodeToString(derivedPrivKey.PubKey().SerializeCompressed())

	// 2.2 生成 SUI 公钥 (Ed25519, path: m/44'/784'/0'/0'/0')
	suiPurpose, _ := master.NewChildKey(bip32.FirstHardenedChild + 44)
	suiCoin, _ := suiPurpose.NewChildKey(bip32.FirstHardenedChild + 784)
	suiAccount, _ := suiCoin.NewChildKey(bip32.FirstHardenedChild + 0)
	suiChange, _ := suiAccount.NewChildKey(bip32.FirstHardenedChild + 0)
	suiAddressKey, _ := suiChange.NewChildKey(bip32.FirstHardenedChild + 0)
	suiPrivKey := ed25519.NewKeyFromSeed(suiAddressKey.Key)
	suiPubKeyHex := hex.EncodeToString(suiPrivKey.Public().(ed25519.PublicKey))

	// 3. 将种子私钥分成 3 个分片，阈值为 2
	parts, err := shamir.Split(testSeed, 3, 2)
	if err != nil {
		http.Error(w, "Failed to split secret", http.StatusInternalServerError)
		return
	}

	var shardIDs []byte
	for k := range parts {
		shardIDs = append(shardIDs, k)
	}
	shard1 := append([]byte{shardIDs[0]}, parts[shardIDs[0]]...)
	shard2 := append([]byte{shardIDs[1]}, parts[shardIDs[1]]...)
	shard3 := append([]byte{shardIDs[2]}, parts[shardIDs[2]]...)

	// 4. 将分片 1 存入 Enclave 内存 (模拟存储)
	storeMutex.Lock()
	shardsStore[pubKeyHex] = shard1
	storeMutex.Unlock()

	// 5. 加解密并返回
	authShare, _ := encryptWithPasswordAndRoot(shard1, userPassword)
	userShare, _ := encryptWithPasswordAndRoot(shard2, userPassword)
	deviceShare, _ := encryptWithPassword(shard2, userPassword)
	recoverShare, _ := encryptWithPassword(shard3, userPassword)

	// 6. 签名 nonce
	signedNonce, _ := signNonce(req.Nonce)

	resp := CreateWalletResponse{
		AuthShare:       authShare,
		UserShare:       userShare,
		DeviceShare:     deviceShare,
		RecoverShare:    recoverShare,
		WalletPublicKey: pubKeyHex,
		SuiPublicKey:    suiPubKeyHex,
		SignedNonce:     signedNonce,
		Password:        userPassword,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

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

// Decrypt data with both password and rootPrivKey
func decryptWithPasswordAndRoot(encryptedDataB64 string, password string) ([]byte, error) {
	encryptedData, err := base64.StdEncoding.DecodeString(encryptedDataB64)
	if err != nil {
		return nil, fmt.Errorf("failed to decode b64: %w", err)
	}

	// First reconstruct the key
	passwordKey := sha256.Sum256([]byte(password))
	rootKey := sha256.Sum256(rootPrivKey.Serialize())
	combinedKey := sha256.Sum256(append(passwordKey[:], rootKey[:]...))

	block, err := aes.NewCipher(combinedKey[:])
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(encryptedData) < nonceSize {
		return nil, fmt.Errorf("encrypted data too short")
	}

	nonce := encryptedData[:nonceSize]
	ciphertext := encryptedData[nonceSize:]

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %w", err)
	}

	return plaintext, nil
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

	// Check if rootPubKey matches
	enclaveRootPubKeyHex := hex.EncodeToString(rootPubKey.SerializeCompressed())
	if req.RootPubKey != enclaveRootPubKeyHex {
		log.Printf("[go] RootPubKey mismatch: expected %s, got %s\n", enclaveRootPubKeyHex, req.RootPubKey)
		http.Error(w, "RootPubKey mismatch", http.StatusBadRequest)
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

	// 5. Generate public key for wallet address (BIP44)
	master, _ := bip32.NewMasterKey(privateKeyBytes)
	purpose, _ := master.NewChildKey(bip32.FirstHardenedChild + 44)
	coin, _ := purpose.NewChildKey(bip32.FirstHardenedChild + 60)
	account, _ := coin.NewChildKey(bip32.FirstHardenedChild + 0)
	change, _ := account.NewChildKey(0)
	addressKey, _ := change.NewChildKey(0) // m/44'/60'/0'/0/0

	// Use derived key for public key response and storage
	derivedPrivKey, _ := btcec.PrivKeyFromBytes(addressKey.Key)
	pubKeyHex := hex.EncodeToString(derivedPrivKey.PubKey().SerializeCompressed())

	// 5.2 生成 SUI 公钥 (Ed25519, path: m/44'/784'/0'/0'/0')
	suiPurpose, _ := master.NewChildKey(bip32.FirstHardenedChild + 44)
	suiCoin, _ := suiPurpose.NewChildKey(bip32.FirstHardenedChild + 784)
	suiAccount, _ := suiCoin.NewChildKey(bip32.FirstHardenedChild + 0)
	suiChange, _ := suiAccount.NewChildKey(bip32.FirstHardenedChild + 0)
	suiAddressKey, _ := suiChange.NewChildKey(bip32.FirstHardenedChild + 0)
	suiPrivKey := ed25519.NewKeyFromSeed(suiAddressKey.Key)
	suiPubKeyHex := hex.EncodeToString(suiPrivKey.Public().(ed25519.PublicKey))

	log.Printf("[go] Derived BIP44 public key: %s\n", pubKeyHex)

	// 6. Store shard1 (auth_share) in enclave memory using DERIVED public key as index
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
		AuthShare:       authShare,
		UserShare:       userShare,
		DeviceShare:     deviceShare,
		RecoverShare:    recoverShare,
		WalletPublicKey: pubKeyHex,
		SuiPublicKey:    suiPubKeyHex,
		SignedNonce:     signedNonce,
		Password:        userPassword,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
	log.Printf("[go] Created wallet for user %s: %s\n", req.UserID, pubKeyHex)
}

// 假设在 const 处定义了 ChainID (需与测试代码一致)
const enclaveChainID = 11155111

// signEvmTxHandler 处理 EVM 交易签名
func signEvmTxHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req SignatureRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	// 1. 解密用户密码
	userPassword, err := decryptPassword(req.EncryptedPassword)
	if err != nil {
		http.Error(w, "Failed to decrypt password", http.StatusBadRequest)
		return
	}

	// 2. 解密 device_share 并通过 Shamir 恢复私钥
	deviceShareEncrypted, _ := base64.StdEncoding.DecodeString(req.DeviceShare)
	passwordKey := sha256.Sum256([]byte(userPassword))
	block, _ := aes.NewCipher(passwordKey[:])
	gcm, _ := cipher.NewGCM(block)
	nonceSize := gcm.NonceSize()
	userPart, _ := gcm.Open(nil, deviceShareEncrypted[:nonceSize], deviceShareEncrypted[nonceSize:], nil)

	storeMutex.RLock()
	enclavePart, ok := shardsStore[req.PubKey]
	storeMutex.RUnlock()

	// 2.2 如果内存中没有，尝试从请求参数里的 AuthShare 解密
	if !ok {
		if req.AuthShare == "" {
			http.Error(w, "Wallet shard not found in memory and no AuthShare provided", http.StatusNotFound)
			return
		}
		log.Printf("[go] Shard1 missing from memory, attempting to decrypt from AuthShare for wallet: %s\n", req.PubKey)
		enclavePart, err = decryptWithPasswordAndRoot(req.AuthShare, userPassword)
		if err != nil {
			log.Printf("[go] Failed to decrypt AuthShare: %v\n", err)
			http.Error(w, "Failed to decrypt AuthShare", http.StatusBadRequest)
			return
		}
	}

	selection := map[byte][]byte{
		enclavePart[0]: enclavePart[1:],
		userPart[0]:    userPart[1:],
	}
	recoveredSecret, _ := shamir.Combine(selection)

	// 3. 派生私钥 (BIP44)
	master, _ := bip32.NewMasterKey(recoveredSecret)
	purpose, _ := master.NewChildKey(bip32.FirstHardenedChild + 44)
	coin, _ := purpose.NewChildKey(bip32.FirstHardenedChild + 60)
	account, _ := coin.NewChildKey(bip32.FirstHardenedChild + 0)
	change, _ := account.NewChildKey(0)
	addressKey, _ := change.NewChildKey(0)
	privKey, _ := btcec.PrivKeyFromBytes(addressKey.Key)

	// 4. 解析 RawTx
	txBytes, err := hex.DecodeString(req.RawTx)
	if err != nil {
		http.Error(w, "Invalid raw_tx hex", http.StatusBadRequest)
		return
	}

	var tx types.Transaction
	// 使用 RLP 解码原始交易
	if err := rlp.DecodeBytes(txBytes, &tx); err != nil {
		log.Printf("[go] RLP Decode failed: %v\n", err)
		http.Error(w, "RLP decode failed", http.StatusBadRequest)
		return
	}

	// 5. 计算符合 EIP-155 标准的签名哈希
	signer := types.LatestSignerForChainID(big.NewInt(enclaveChainID))
	txHash := signer.Hash(&tx)

	log.Printf("[go] Enclave computed Hash: %s\n", txHash.Hex())

	// 6. 使用私钥签名该哈希
	sig := ecdsa.Sign(privKey, txHash.Bytes())

	// 7. 返回结果
	resp := SignatureResponse{
		Signature:       base64.StdEncoding.EncodeToString(sig.Serialize()),
		WalletPublicKey: hex.EncodeToString(privKey.PubKey().SerializeCompressed()),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// signSuiTxHandler 处理 SUI 交易签名
func signSuiTxHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req SignatureRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	// 1. 解密用户密码
	userPassword, err := decryptPassword(req.EncryptedPassword)
	if err != nil {
		http.Error(w, "Failed to decrypt password", http.StatusBadRequest)
		return
	}

	// 2. 恢复 Shamir 分片并恢复私钥
	deviceShareEncrypted, _ := base64.StdEncoding.DecodeString(req.DeviceShare)
	passwordKey := sha256.Sum256([]byte(userPassword))
	block, _ := aes.NewCipher(passwordKey[:])
	gcm, _ := cipher.NewGCM(block)
	nonceSize := gcm.NonceSize()
	userPart, _ := gcm.Open(nil, deviceShareEncrypted[:nonceSize], deviceShareEncrypted[nonceSize:], nil)

	storeMutex.RLock()
	enclavePart, ok := shardsStore[req.PubKey]
	storeMutex.RUnlock()

	if !ok {
		if req.AuthShare == "" {
			http.Error(w, "Wallet shard not found", http.StatusNotFound)
			return
		}
		enclavePart, err = decryptWithPasswordAndRoot(req.AuthShare, userPassword)
		if err != nil {
			http.Error(w, "Failed to decrypt AuthShare", http.StatusBadRequest)
			return
		}
	}

	selection := map[byte][]byte{
		enclavePart[0]: enclavePart[1:],
		userPart[0]:    userPart[1:],
	}
	recoveredSecret, _ := shamir.Combine(selection)

	// 3. 派生 SUI 私钥 (BIP44)
	// SUI 路径: m/44'/784'/0'/0'/0'
	master, _ := bip32.NewMasterKey(recoveredSecret)
	purpose, _ := master.NewChildKey(bip32.FirstHardenedChild + 44)
	coin, _ := purpose.NewChildKey(bip32.FirstHardenedChild + 784)
	account, _ := coin.NewChildKey(bip32.FirstHardenedChild + 0)
	change, _ := account.NewChildKey(bip32.FirstHardenedChild + 0)
	addressKey, _ := change.NewChildKey(bip32.FirstHardenedChild + 0)

	privKey := ed25519.NewKeyFromSeed(addressKey.Key)
	pubKey := privKey.Public().(ed25519.PublicKey)

	// 4. 解析 RawTx
	txBytes, err := hex.DecodeString(req.RawTx)
	if err != nil {
		http.Error(w, "Invalid raw_tx hex", http.StatusBadRequest)
		return
	}

	// 5. 计算 SUI Intent Hash
	// SUI Intent: [IntentScope(0), Version(0), AppID(0)] + tx_bytes
	intent := []byte{0, 0, 0}
	intent = append(intent, txBytes...)

	h, _ := blake2b.New256(nil)
	h.Write(intent)
	txHash := h.Sum(nil)

	// 6. 使用 Ed25519 签名
	sig := ed25519.Sign(privKey, txHash)

	// 7. 返回序列化签名: [flag(0)] + [sig(64)] + [pubkey(32)]
	serializedSig := make([]byte, 1+64+32)
	serializedSig[0] = 0 // Ed25519 flag
	copy(serializedSig[1:], sig)
	copy(serializedSig[1+64:], pubKey)

	resp := SignatureResponse{
		Signature:       base64.StdEncoding.EncodeToString(serializedSig),
		WalletPublicKey: hex.EncodeToString(pubKey),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// corsMiddleware 处理跨域请求
func corsMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
		w.Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		next(w, r)
	}
}

func main() {
	// Initialize root keys
	if err := initializeRootKeys(); err != nil {
		log.Fatalf("Failed to initialize root keys: %v", err)
	}

	// Register HTTP handlers with CORS middleware
	http.HandleFunc("/tee_wallet/create_key_share", corsMiddleware(createWalletHandler))
	http.HandleFunc("/tee_wallet/sign_evm_tx", corsMiddleware(signEvmTxHandler))
	http.HandleFunc("/tee_wallet/sign_sui_tx", corsMiddleware(signSuiTxHandler))
	http.HandleFunc("/tee_wallet/tee_pubkey", corsMiddleware(getRootPubKeyHandler))
	http.HandleFunc("/tee_wallet/test_pubkey", corsMiddleware(testWalletPubKeyHandler))
	http.HandleFunc("/tee_wallet/get_fixed_sui_pubkey_for_test", corsMiddleware(getFixedSuiPubKeyForTestHandler))

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
