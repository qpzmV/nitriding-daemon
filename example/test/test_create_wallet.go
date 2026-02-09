package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/ecdsa"
	"github.com/fxamacker/cbor/v2"
)

const (
	enclaveAppURL = "http://127.0.0.1:8088"
	nitridingURL  = "https://localhost:10443/enclave/attestation"
	testNonce     = "abc1111111111111111111111111111111111111"
	testUserPIN   = "my-secure-pin-123456"
)

type CreateWalletResponse struct {
	AuthShare    string `json:"auth_share"`
	UserShare    string `json:"user_share"`
	DeviceShare  string `json:"device_share"`
	RecoverShare string `json:"recover_share"`
	PublicKey    string `json:"public_key"`
	SignedNonce  string `json:"signed_nonce"`
}

// 1. 获取并解析证明文档，提取 Public Key
func fetchRootPubKeyFromAttestation(nonce string) (string, error) {
	fmt.Printf("[Step 1] 正在从 Nitriding 获取证明文档...\n")

	// 配置跳过 HTTPS 证书验证
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}

	resp, err := client.Get(nitridingURL + "?nonce=" + nonce)
	if err != nil {
		return "", fmt.Errorf("请求失败: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	// 去掉可能存在的换行符
	b64Doc := strings.TrimSpace(string(body))

	// Base64 解码
	rawDoc, err := base64.StdEncoding.DecodeString(b64Doc)
	if err != nil {
		return "", fmt.Errorf("Base64 解码失败: %v", err)
	}

	// CBOR 解码
	var doc map[string]interface{}
	if err := cbor.Unmarshal(rawDoc, &doc); err != nil {
		return "", fmt.Errorf("CBOR 解析失败: %v", err)
	}

	// 打印人类可读的关键信息
	fmt.Println("--- 证明文档信息 ---")
	fmt.Printf("Instance ID: %v\n", doc["module_id"])
	if pcrs, ok := doc["pcrs"].(map[interface{}]interface{}); ok {
		fmt.Printf("PCR0 (镜像哈希): %x\n", pcrs[uint64(0)])
	}

	// 提取 Public Key
	pubKeyBytes, ok := doc["public_key"].([]byte)
	if !ok {
		return "", fmt.Errorf("文档中未找到 public_key 字段")
	}

	pubKeyHex := hex.EncodeToString(pubKeyBytes)
	fmt.Printf("提取到 Root PubKey: %s\n", pubKeyHex)
	return pubKeyHex, nil
}

// 2. 验证签名逻辑
func verifySignature(pubKeyHex, nonce, signedNonceBase64 string) error {
	pubKeyBytes, _ := hex.DecodeString(pubKeyHex)
	pubKey, err := btcec.ParsePubKey(pubKeyBytes)
	if err != nil {
		return err
	}

	sigBytes, _ := base64.StdEncoding.DecodeString(signedNonceBase64)
	signature, err := ecdsa.ParseSignature(sigBytes)
	if err != nil {
		return err
	}

	messageHash := sha256.Sum256([]byte(nonce))
	if signature.Verify(messageHash[:], pubKey) {
		return nil
	}
	return fmt.Errorf("签名验证不匹配")
}

// 3. 符合后端标准的加密逻辑 (12字节 IV)
func encryptPassword(rootPubKeyHex string, password string) (string, error) {
	pubKeyBytes, _ := hex.DecodeString(rootPubKeyHex)
	rootPubKey, _ := btcec.ParsePubKey(pubKeyBytes)

	ephemeralPrivKey, _ := btcec.NewPrivateKey()
	ephemeralPubKey := ephemeralPrivKey.PubKey().SerializeCompressed()

	sharedSecret := btcec.GenerateSharedSecret(ephemeralPrivKey, rootPubKey)
	aesKey := sha256.Sum256(sharedSecret)

	block, _ := aes.NewCipher(aesKey[:])
	gcm, _ := cipher.NewGCM(block)

	iv := make([]byte, 12)
	io.ReadFull(rand.Reader, iv)

	ciphertext := gcm.Seal(nil, iv, []byte(password), nil)

	finalData := append(ephemeralPubKey, iv...)
	finalData = append(finalData, ciphertext...)

	return base64.StdEncoding.EncodeToString(finalData), nil
}

func main() {
	// A. 自动获取公钥
	rootPubKeyHex, err := fetchRootPubKeyFromAttestation(testNonce)
	if err != nil {
		log.Fatalf("获取公钥失败: %v", err)
	}

	// B. 加密用户 PIN
	encryptedPass, err := encryptPassword(rootPubKeyHex, testUserPIN)
	if err != nil {
		log.Fatalf("加密失败: %v", err)
	}

	// C. 请求创建钱包
	fmt.Printf("\n[Step 2] 正在请求 Enclave 创建钱包...\n")
	requestBody := map[string]string{
		"user_id":            "user_888",
		"login_token":        "token_123",
		"nonce":              testNonce,
		"encrypted_password": encryptedPass,
	}
	jsonData, _ := json.Marshal(requestBody)

	resp, err := http.Post(enclaveAppURL+"/app/sss/key", "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		log.Fatalf("请求失败: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		log.Fatalf("后端返回错误: %s", string(body))
	}

	var walletResp CreateWalletResponse
	json.Unmarshal(body, &walletResp)

	// D. 验证签名
	fmt.Printf("\n[Step 3] 收到响应，验证签名...\n")
	err = verifySignature(rootPubKeyHex, testNonce, walletResp.SignedNonce)
	if err != nil {
		fmt.Printf("❌ 验签失败: %v\n", err)
	} else {
		fmt.Println("✅ 验签成功！该响应确实来自受信任的 Enclave。")
		fmt.Printf("钱包地址(公钥): %s\n", walletResp.PublicKey)
		fmt.Println("Auth Share (加密后):", walletResp.AuthShare[:30]+"...")
	}
}
