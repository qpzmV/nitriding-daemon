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

// fetchRootPubKeyFromAttestation 从 Nitriding 获取证明文档，并解析提取 Root 公钥
func fetchRootPubKeyFromAttestation(nonce string) (string, error) {
	fmt.Printf("[Step 1] 正在从 Nitriding 获取证明文档...\n")

	// 1. 配置 HTTP 客户端 (跳过本地自签名证书校验)
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}

	// 2. 发起请求
	url := fmt.Sprintf("https://localhost:10443/enclave/attestation?nonce=%s", nonce)
	resp, err := client.Get(url)
	if err != nil {
		return "", fmt.Errorf("请求 Nitriding 失败: %v (请检查 Enclave 是否运行且 10443 端口已映射)", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	b64Doc := strings.TrimSpace(string(body))

	// 3. Base64 解码
	rawDoc, err := base64.StdEncoding.DecodeString(b64Doc)
	if err != nil {
		return "", fmt.Errorf("Base64 解码失败: %v", err)
	}

	// 4. 解析 COSE 外壳 (COSE Sign1 是一个 Array)
	var coseSign1 []cbor.RawMessage
	if err := cbor.Unmarshal(rawDoc, &coseSign1); err != nil {
		return "", fmt.Errorf("COSE 外壳解析失败 (不是 Array): %v", err)
	}

	if len(coseSign1) < 4 {
		return "", fmt.Errorf("COSE 结构异常: 预期长度 4, 实际 %d", len(coseSign1))
	}

	// 5. 提取 Payload 字节流 (Index 2 是内容主体)
	// 在 Nitro 中，Payload 被封装为一个 Byte String，需要二次解码
	var payloadBytes []byte
	if err := cbor.Unmarshal(coseSign1[2], &payloadBytes); err != nil {
		return "", fmt.Errorf("无法从 COSE 提取 Payload 字节流: %v", err)
	}

	// 6. 将 Payload 解析为真正的内容 Map
	var doc map[string]interface{}
	if err := cbor.Unmarshal(payloadBytes, &doc); err != nil {
		return "", fmt.Errorf("Payload 内容解析失败 (Map): %v", err)
	}

	// 打印人类可读的信息
	fmt.Println("-------------------------------------------")
	fmt.Printf("Instance ID: %v\n", doc["module_id"])

	// 健壮地提取 PCR0
	if pcrs, ok := doc["pcrs"].(map[interface{}]interface{}); ok {
		for k, v := range pcrs {
			// CBOR 中的键可能是 uint64 类型
			if fmt.Sprintf("%v", k) == "0" {
				fmt.Printf("PCR0 (Image Hash): %x\n", v)
			}
		}
	}

	// 7. 提取 Public Key
	pubKeyBytes, ok := doc["public_key"].([]byte)
	if !ok {
		return "", fmt.Errorf("证明文档中未找到 public_key 字段")
	}

	pubKeyHex := hex.EncodeToString(pubKeyBytes)
	fmt.Printf("成功提取 Root PubKey: %s\n", pubKeyHex)
	fmt.Println("-------------------------------------------")

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
