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
	"github.com/btcsuite/btcd/btcec/v2/ecdsa"
)

const (
	enclaveBaseURL = "http://127.0.0.1:8088"
)

// CreateWalletResponse 匹配后端返回的 JSON 结构
type CreateWalletResponse struct {
	AuthShare    string `json:"auth_share"`
	UserShare    string `json:"user_share"`
	DeviceShare  string `json:"device_share"`
	RecoverShare string `json:"recover_share"`
	PublicKey    string `json:"public_key"`
	SignedNonce  string `json:"signed_nonce"`
}

// verifySignature 使用 RootPubKey 验证签名后的 Nonce
func verifySignature(pubKeyHex, nonce, signedNonceBase64 string) error {
	// 1. 解析公钥
	pubKeyBytes, err := hex.DecodeString(pubKeyHex)
	if err != nil {
		return fmt.Errorf("invalid pubkey hex: %v", err)
	}
	pubKey, err := btcec.ParsePubKey(pubKeyBytes)
	if err != nil {
		return fmt.Errorf("failed to parse pubkey: %v", err)
	}

	// 2. 解码签名 (Base64 -> DER)
	sigBytes, err := base64.StdEncoding.DecodeString(signedNonceBase64)
	if err != nil {
		return fmt.Errorf("failed to decode signature b64: %v", err)
	}
	signature, err := ecdsa.ParseSignature(sigBytes)
	if err != nil {
		return fmt.Errorf("failed to parse DER signature: %v", err)
	}

	// 3. 计算原始数据的哈希 (必须与后端签名时的 hash 逻辑一致)
	// 后端逻辑: nonceHash := sha256.Sum256([]byte(nonce))
	messageHash := sha256.Sum256([]byte(nonce))

	// 4. 验证签名
	if signature.Verify(messageHash[:], pubKey) {
		return nil
	}
	return fmt.Errorf("signature verification failed")
}

func encryptPassword(rootPubKeyHex string, password string) (string, error) {
	pubKeyBytes, err := hex.DecodeString(rootPubKeyHex)
	if err != nil {
		return "", err
	}
	rootPubKey, err := btcec.ParsePubKey(pubKeyBytes)
	if err != nil {
		return "", err
	}

	ephemeralPrivKey, err := btcec.NewPrivateKey()
	if err != nil {
		return "", err
	}
	ephemeralPubKey := ephemeralPrivKey.PubKey().SerializeCompressed()

	sharedSecret := btcec.GenerateSharedSecret(ephemeralPrivKey, rootPubKey)
	aesKey := sha256.Sum256(sharedSecret)

	block, err := aes.NewCipher(aesKey[:])
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	iv := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}

	ciphertext := gcm.Seal(nil, iv, []byte(password), nil)

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

	nonce := "nonce_abc" // 客户端发送的 Nonce
	encryptedPass, err := encryptPassword(rootPubKeyHex, "my-secure-pin-123456")
	if err != nil {
		log.Fatalf("加密失败: %v", err)
	}

	requestBody := map[string]string{
		"user_id":            "user_888",
		"login_token":        "token_123",
		"nonce":              nonce,
		"encrypted_password": encryptedPass,
	}

	jsonData, _ := json.Marshal(requestBody)
	resp, err := http.Post(enclaveBaseURL+"/app/sss/key", "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		log.Fatalf("请求失败: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		log.Fatalf("服务器返回错误: %d - %s", resp.StatusCode, string(body))
	}

	// 解析响应内容
	var walletResp CreateWalletResponse
	if err := json.Unmarshal(body, &walletResp); err != nil {
		log.Fatalf("解析响应失败: %v", err)
	}

	fmt.Printf("\n[Step 1] 收到响应，准备验证签名...\n")

	// 执行验签逻辑
	err = verifySignature(rootPubKeyHex, nonce, walletResp.SignedNonce)
	if err != nil {
		fmt.Printf("❌ 签名验证失败: %v\n", err)
	} else {
		fmt.Println("✅ 签名验证成功！响应内容确由 Enclave 签发且 Nonce 匹配。")
		fmt.Printf("新钱包公钥: %s\n", walletResp.PublicKey)
	}
}
