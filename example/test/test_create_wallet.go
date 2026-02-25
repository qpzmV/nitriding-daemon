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

// 1. 从业务接口获取公钥原文 (TEE_PubKey)
func fetchRawPubKey() (string, error) {
	fmt.Printf("[Step 0] 正在从业务接口获取公钥原文...\n")
	// 注意：这里使用的是您在后端注册的接口路径 /tee_wallet/tee_pubkey
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

// 4. 验证响应签名逻辑
func verifySignature(pubKeyHex, nonce, signedNonceBase64 string) error {
	pubKeyBytes, _ := hex.DecodeString(pubKeyHex)
	pubKey, err := btcec.ParsePubKey(pubKeyBytes)
	if err != nil {
		return err
	}

	sigBytes, err := base64.StdEncoding.DecodeString(signedNonceBase64)
	if err != nil {
		return err
	}
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

// 5. PublicKeyToEthAddress 将压缩公钥转换为以太坊地址
func PublicKeyToEthAddress(pubKeyHex string) (string, error) {
	pubKeyBytes, err := hex.DecodeString(pubKeyHex)
	if err != nil {
		return "", err
	}

	pubKey, err := btcec.ParsePubKey(pubKeyBytes)
	if err != nil {
		return "", err
	}

	// 以太坊使用非压缩公钥 (65字节) 的后64字节进行哈希
	uncompressedPubKey := pubKey.SerializeUncompressed()

	// 计算 Keccak-256 哈希
	hash := sha3.NewLegacyKeccak256()
	hash.Write(uncompressedPubKey[1:]) // 跳过 0x04 控制字节
	pubKeyHash := hash.Sum(nil)

	// 取最后 20 字节
	address := "0x" + hex.EncodeToString(pubKeyHash[12:])
	return address, nil
}

func main() {
	log.Println("=== Enclave 钱包创建测试脚本启动 ===")

	// A. 先从业务端口拿公钥原文
	rawPubKey, err := fetchRawPubKey()
	if err != nil {
		log.Fatalf("❌ 步骤 0 失败: %v", err)
	}

	// B. 拿证明文档比对哈希，确保证明该公钥来自合法 Enclave
	verifiedPubKey, err := fetchRootPubKeyFromAttestation(testNonce, rawPubKey)
	if err != nil {
		log.Fatalf("❌ 步骤 1 失败: %v", err)
	}

	// C. 使用验证过的公钥加密用户 PIN
	encryptedPass, err := encryptPassword(verifiedPubKey, testUserPIN)
	if err != nil {
		log.Fatalf("❌ 步骤 2 失败: %v", err)
	}

	// D. 发起创建钱包业务请求
	fmt.Printf("\n[Step 2] 正在请求 Enclave 创建钱包...\n")
	requestBody := map[string]string{
		"user_id":            "user_888",
		"login_token":        "token_123",
		"nonce":              testNonce,
		"encrypted_password": encryptedPass,
	}
	jsonData, _ := json.Marshal(requestBody)

	resp, err := http.Post(enclaveAppURL+"/tee_wallet/create_key_share", "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		log.Fatalf("❌ 业务请求失败: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		log.Fatalf("❌ 后端业务逻辑返回错误: %s", string(body))
	}

	var walletResp CreateWalletResponse
	if err := json.Unmarshal(body, &walletResp); err != nil {
		log.Fatalf("❌ 解析业务响应失败: %v", err)
	}

	// E. 验证响应签名，确保返回的 Share 数据未被篡改
	fmt.Printf("\n[Step 3] 收到响应，验证签名...\n")
	err = verifySignature(verifiedPubKey, testNonce, walletResp.SignedNonce)
	if err != nil {
		fmt.Printf("❌ 验签失败: %v\n", err)
	} else {
		fmt.Println("✅ 验签成功！该响应确实来自受信任的 Enclave。")
		fmt.Printf("钱包公钥: %s\n", walletResp.PublicKey)

		// 生成并显示 ETH 地址
		ethAddr, err := PublicKeyToEthAddress(walletResp.PublicKey)
		if err != nil {
			fmt.Printf("❌ 转换 ETH 地址失败: %v\n", err)
		} else {
			fmt.Printf("以太坊地址: %s\n", ethAddr)
		}

		fmt.Printf("Auth Share (B64前缀): %s...\n", walletResp.AuthShare[:20])
	}
}
