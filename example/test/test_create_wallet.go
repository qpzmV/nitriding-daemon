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

	"github.com/btcsuite/btcd/btcec/v2"
)

const (
	enclaveBaseURL = "http://127.0.0.1:8088"
)

func encryptPassword(rootPubKeyHex string, password string) (string, error) {
	// 1. 解析 Root 公钥
	pubKeyBytes, err := hex.DecodeString(rootPubKeyHex)
	if err != nil {
		return "", err
	}
	rootPubKey, err := btcec.ParsePubKey(pubKeyBytes)
	if err != nil {
		return "", err
	}

	// 2. 生成临时密钥对
	ephemeralPrivKey, err := btcec.NewPrivateKey()
	if err != nil {
		return "", err
	}
	ephemeralPubKey := ephemeralPrivKey.PubKey().SerializeCompressed() // 33字节

	// 3. ECDH 共享密钥
	sharedSecret := btcec.GenerateSharedSecret(ephemeralPrivKey, rootPubKey)
	aesKey := sha256.Sum256(sharedSecret)

	// 4. AES-GCM 加密 (使用标准 12 字节 IV)
	block, err := aes.NewCipher(aesKey[:])
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	iv := make([]byte, 12) // 业界习俗：GCM 使用 12 字节 IV
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}

	// Seal 会返回 [ciphertext][tag]
	ciphertext := gcm.Seal(nil, iv, []byte(password), nil)

	// 5. 拼接: [PubKey(33)][IV(12)][Ciphertext+Tag]
	finalData := make([]byte, 0, len(ephemeralPubKey)+len(iv)+len(ciphertext))
	finalData = append(finalData, ephemeralPubKey...)
	finalData = append(finalData, iv...)
	finalData = append(finalData, ciphertext...)

	return base64.StdEncoding.EncodeToString(finalData), nil
}

func main() {
	var rootPubKeyHex string
	fmt.Print("请输入 Enclave Root PubKey Hex: ")
	fmt.Scanln(&rootPubKeyHex)

	encryptedPass, err := encryptPassword(rootPubKeyHex, "my-secure-pin-123456")
	if err != nil {
		log.Fatalf("加密失败: %v", err)
	}

	requestBody := map[string]string{
		"user_id":            "user_888",
		"login_token":        "token_123",
		"nonce":              "nonce_abc",
		"encrypted_password": encryptedPass,
	}

	jsonData, _ := json.Marshal(requestBody)
	resp, err := http.Post(enclaveBaseURL+"/app/sss/key", "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		log.Fatalf("请求失败: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	fmt.Printf("状态码: %d\n响应内容: %s\n", resp.StatusCode, string(body))
}
