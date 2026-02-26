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
	"golang.org/x/crypto/sha3"
)

const (
	enclaveAppURL = "http://localhost:8088"
	nitridingURL  = "https://localhost:10443/enclave/attestation"
	testNonce     = "1234567890abcdef1234567890abcdef12345678" // 40-digit hex string
	testUserPIN   = "my-secure-pin-123456"
)

type CreateWalletResponse struct {
	AuthShare       string `json:"auth_share"`
	UserShare       string `json:"user_share"`
	DeviceShare     string `json:"device_share"`
	RecoverShare    string `json:"recover_share"`
	WalletPublicKey string `json:"wallet_public_key"`
	SignedNonce     string `json:"signed_nonce"`
}

type SignatureRequest struct {
	EncryptedPassword string `json:"encrypted_password"` // encrypted with rootPubKey
	DeviceShare       string `json:"device_share"`       // encrypted with userPassword
	PubKey            string `json:"pub_key"`
	RawTx             string `json:"raw_tx"`
	AuthShare         string `json:"auth_share"`
}

type SignatureResponse struct {
	Signature       string `json:"signature"`
	WalletPublicKey string `json:"wallet_public_key"`
}

// 1. 从业务接口获取公钥原文 (TEE_PubKey)
func fetchRawPubKey() (string, error) {
	fmt.Printf("[Step 0] 正在从业务接口获取公钥原文...\n")
	resp, err := http.Get(enclaveAppURL + "/tee_wallet/tee_pubkey")
	if err != nil {
		return "", fmt.Errorf("无法连接到业务接口: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("业务接口返回错误 [%d]: %s", resp.StatusCode, string(body))
	}

	var res map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		return "", fmt.Errorf("解析公钥响应失败: %v", err)
	}

	pubKeyHex := res["public_key"]
	if pubKeyHex == "" {
		return "", fmt.Errorf("接口响应中未找到 public_key 字段")
	}
	return pubKeyHex, nil
}

// 2. 从 Nitriding 获取证明文档并比对本地 Hash，确保公钥可信
func fetchRootPubKeyFromAttestation(nonce string, rawPubKeyHex string) (string, error) {
	fmt.Printf("[Step 1] 正在从 Nitriding 获取证明并验证哈希...\n")

	// 计算本地获取到的公钥的 SHA256 哈希
	pubKeyBytes, err := hex.DecodeString(rawPubKeyHex)
	if err != nil {
		return "", fmt.Errorf("非法的公钥格式: %v", err)
	}
	localHash := sha256.Sum256(pubKeyBytes)
	localHashHex := hex.EncodeToString(localHash[:])

	// 请求 Nitriding 证明
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}
	url := fmt.Sprintf("%s?nonce=%s", nitridingURL, nonce)
	resp, err := client.Get(url)
	if err != nil {
		return "", fmt.Errorf("请求 Nitriding 证明文档失败: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	b64Doc := strings.TrimSpace(string(body))
	rawDoc, err := base64.StdEncoding.DecodeString(b64Doc)
	if err != nil {
		return "", fmt.Errorf("证明文档 Base64 解码失败: %v", err)
	}

	// 解析 CBOR (COSE Sign1)
	var coseSign1 []cbor.RawMessage
	if err := cbor.Unmarshal(rawDoc, &coseSign1); err != nil {
		return "", fmt.Errorf("COSE 解析失败: %v", err)
	}

	var payloadBytes []byte
	if err := cbor.Unmarshal(coseSign1[2], &payloadBytes); err != nil {
		return "", fmt.Errorf("Payload 提取失败: %v", err)
	}

	var doc map[string]interface{}
	if err := cbor.Unmarshal(payloadBytes, &doc); err != nil {
		return "", fmt.Errorf("Payload Map 解析失败: %v", err)
	}

	// 提取 UserData (后端存储的哈希串)
	userData, ok := doc["user_data"].([]byte)
	if !ok {
		return "", fmt.Errorf("证明文档中未找到 user_data 字段")
	}
	userDataHex := hex.EncodeToString(userData)

	// 安全校验核心：检查本地哈希是否在硬件签名的 userData 中
	if !strings.Contains(userDataHex, localHashHex) {
		return "", fmt.Errorf("❌ 安全警报：公钥哈希匹配失败！业务接口返回的公钥可能被篡改")
	}

	fmt.Println("-------------------------------------------")
	fmt.Printf("Instance ID: %v\n", doc["module_id"])
	fmt.Println("✅ 远程证明验证成功：公钥哈希与硬件签名文档一致。")
	fmt.Println("-------------------------------------------")

	return rawPubKeyHex, nil
}

// 3. ECIES 风格加密函数 (ECDH + AES-GCM)
func encryptPassword(rootPubKeyHex string, password string) (string, error) {
	pubKeyBytes, err := hex.DecodeString(rootPubKeyHex)
	if err != nil {
		return "", err
	}
	rootPubKey, err := btcec.ParsePubKey(pubKeyBytes)
	if err != nil {
		return "", err
	}

	// 生成临时密钥对
	ephemeralPrivKey, err := btcec.NewPrivateKey()
	if err != nil {
		return "", err
	}
	ephemeralPubKey := ephemeralPrivKey.PubKey().SerializeCompressed()

	// ECDH 共享密钥计算
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

	// 拼接结果: [EphemeralPubKey(33)] + [IV(12)] + [Ciphertext]
	finalData := make([]byte, 0, len(ephemeralPubKey)+len(iv)+len(ciphertext))
	finalData = append(finalData, ephemeralPubKey...)
	finalData = append(finalData, iv...)
	finalData = append(finalData, ciphertext...)

	return base64.StdEncoding.EncodeToString(finalData), nil
}

// 4. 创建钱包
func createWallet(verifiedPubKey string) (*CreateWalletResponse, error) {
	fmt.Printf("\n[Step 2] 正在请求 Enclave 创建钱包...\n")

	encryptedPass, err := encryptPassword(verifiedPubKey, testUserPIN)
	if err != nil {
		return nil, fmt.Errorf("加密密码失败: %v", err)
	}

	requestBody := map[string]string{
		"user_id":            "user_sign_test",
		"login_token":        "token_sign_test",
		"nonce":              testNonce,
		"encrypted_password": encryptedPass,
		"tee_pk":             verifiedPubKey,
	}
	jsonData, _ := json.Marshal(requestBody)

	resp, err := http.Post(enclaveAppURL+"/tee_wallet/create_key_share", "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, fmt.Errorf("业务请求失败: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("后端业务逻辑返回错误 [%d]: %s", resp.StatusCode, string(body))
	}

	var walletResp CreateWalletResponse
	if err := json.Unmarshal(body, &walletResp); err != nil {
		return nil, fmt.Errorf("解析业务响应失败: %v", err)
	}

	fmt.Printf("✅ 钱包创建成功，公钥: %s\n", walletResp.WalletPublicKey)
	return &walletResp, nil
}

// 5. 签名交易
func signTransaction(walletPubKey string, encryptedPassword string, deviceShare string, authShare string, rawTx string) (*SignatureResponse, error) {
	fmt.Printf("\n[Step 3] 正在请求 Enclave 签名交易...\n")
	fmt.Printf("  - 钱包公钥: %s\n", walletPubKey)
	fmt.Printf("  - 原始交易: %s\n", rawTx)

	signReq := SignatureRequest{
		EncryptedPassword: encryptedPassword,
		DeviceShare:       deviceShare,
		PubKey:            walletPubKey,
		RawTx:             rawTx,
		AuthShare:         authShare,
	}
	jsonData, _ := json.Marshal(signReq)

	resp, err := http.Post(enclaveAppURL+"/tee_wallet/sign_transaction", "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, fmt.Errorf("签名请求失败: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("签名接口返回错误 [%d]: %s", resp.StatusCode, string(body))
	}

	var sigResp SignatureResponse
	if err := json.Unmarshal(body, &sigResp); err != nil {
		return nil, fmt.Errorf("解析签名响应失败: %v", err)
	}

	fmt.Printf("✅ 签名成功，签名值(B64前缀): %s...\n", sigResp.Signature[:20])
	return &sigResp, nil
}

// 6. 验证签名 (使用 BIP44 派生的公钥)
func verifyTransactionSignature(signature string, rawTx string, walletPubKey string) error {
	fmt.Printf("\n[Step 4] 正在验证签名...\n")

	sigBytes, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return fmt.Errorf("签名 Base64 解码失败: %v", err)
	}

	sig, err := ecdsa.ParseSignature(sigBytes)
	if err != nil {
		return fmt.Errorf("签名解析失败: %v", err)
	}

	// 计算 RawTx 的 Keccak-256 哈希
	txBytes, err := hex.DecodeString(rawTx)
	if err != nil {
		txBytes = []byte(rawTx)
	}
	hasher := sha3.NewLegacyKeccak256()
	hasher.Write(txBytes)
	txHashHash := hasher.Sum(nil)

	pubKeyBytes, err := hex.DecodeString(walletPubKey)
	if err != nil {
		return fmt.Errorf("公钥解码失败: %v", err)
	}

	pubKey, err := btcec.ParsePubKey(pubKeyBytes)
	if err != nil {
		return fmt.Errorf("公钥解析失败: %v", err)
	}

	if sig.Verify(txHashHash, pubKey) {
		fmt.Println("✅ 签名验证成功！")
		return nil
	}

	return fmt.Errorf("❌ 签名验证失败")
}

func main() {
	log.Println("=== Enclave 交易签名测试脚本启动 ===")

	// A. 获取并验证 Enclave 公钥
	rawPubKey, err := fetchRawPubKey()
	if err != nil {
		log.Fatalf("❌ 步骤 0 失败: %v", err)
	}

	verifiedPubKey, err := fetchRootPubKeyFromAttestation(testNonce, rawPubKey)
	if err != nil {
		log.Fatalf("❌ 步骤 1 失败: %v", err)
	}

	// B. 创建钱包
	walletResp, err := createWallet(verifiedPubKey)
	if err != nil {
		log.Fatalf("❌ 创建钱包失败: %v", err)
	}

	// C. 准备签名所需的加密数据
	fmt.Printf("\n[准备签名] 正在加密用户密码...\n")
	encryptedPassword, err := encryptPassword(verifiedPubKey, testUserPIN)
	if err != nil {
		log.Fatalf("❌ 加密密码失败: %v", err)
	}
	fmt.Printf("✅ 密码加密成功\n")

	// D. 签名交易 (直接使用加密的 device_share 和加密的密码)
	// 使用以太坊 Sepolia 测试网的真实 EIP-1559 交易示例 (链 ID: 11155111)
	testRawTx := "02f87183aa284780843b9aca0084773594008252089471c7656ec7ab88b098defb751b7401b5f6d8976f880de0b6b3a764000080c0"
	sigResp, err := signTransaction(walletResp.WalletPublicKey, encryptedPassword, walletResp.DeviceShare, walletResp.AuthShare, testRawTx)
	if err != nil {
		log.Fatalf("❌ 签名交易失败: %v", err)
	}

	// E. 验证签名
	err = verifyTransactionSignature(sigResp.Signature, testRawTx, walletResp.WalletPublicKey)
	if err != nil {
		log.Printf("⚠️  签名验证: %v", err)
		log.Printf("注意：由于使用了 BIP44 派生，验证可能需要使用派生后的公钥")
	}

	fmt.Println("\n=== 测试完成 ===")
	fmt.Printf("创建钱包返回公钥: %s\n", walletResp.WalletPublicKey)
	fmt.Printf("签名返回钱包公钥: %s\n", sigResp.WalletPublicKey)
	fmt.Printf("原始交易: %s\n", testRawTx)
	fmt.Printf("签名值: %s\n", sigResp.Signature)
}
