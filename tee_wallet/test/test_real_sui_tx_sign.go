package main

import (
	"bufio"
	"bytes"
	"context"
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
	"os"
	"strings"

	"github.com/block-vision/sui-go-sdk/common/keypair"
	"github.com/block-vision/sui-go-sdk/models"
	"github.com/block-vision/sui-go-sdk/sui"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/fxamacker/cbor/v2"
	"golang.org/x/crypto/blake2b"
)

const (
	suiEnclaveAppURL = "http://localhost:8088"
	suiNitridingURL  = "http://localhost:8088/tee_wallet/attestation"
	suiNonce         = "abcdef1234567890abcdef1234567890abcdef12" // 40-digit hex string
	suiUserPIN       = "my-secure-pin-123456"
	suiDevnetRpc     = "https://fullnode.devnet.sui.io"
)

type SuiKeyShares struct {
	AuthShare    string `json:"auth_share"`
	DeviceShare  string `json:"device_share"`
	RecoverShare string `json:"recover_share"`
}

type SuiWalletPubKeys struct {
	EvmWalletPubKey string `json:"evm_wallet_pub_key"`
	SuiWalletPubKey string `json:"sui_wallet_pub_key"`
}

type SuiCreateWalletResponse struct {
	KeyShares     SuiKeyShares     `json:"key_shares"`
	WalletPubKeys SuiWalletPubKeys `json:"wallet_pub_keys"`
	SignedNonce   string           `json:"signed_nonce"`
	Password      string           `json:"password"`
}

type SuiSignatureRequest struct {
	EncryptedPassword string `json:"encrypted_password"`
	DeviceShare       string `json:"device_share"`
	PubKey            string `json:"wallet_pub_key"`
	RawTx             string `json:"raw_tx"`
	AuthShare         string `json:"auth_share"`
}

type SuiSignatureResponse struct {
	Signature       string `json:"signature"`
	WalletPublicKey string `json:"wallet_public_key"`
}

// fetchSuiRawPubKey 从业务接口获取公钥原文 (TEE_PubKey)
func fetchSuiRawPubKey() (string, error) {
	fmt.Printf("[Step 0] 正在从业务接口获取公钥原文...\n")
	resp, err := http.Get(suiEnclaveAppURL + "/tee_wallet/tee_pubkey")
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

// fetchSuiRootPubKeyFromAttestation 从 Nitriding 获取证明文档并比对本地 Hash
func fetchSuiRootPubKeyFromAttestation(nonce string, rawPubKeyHex string) (string, error) {
	fmt.Printf("[Step 1] 正在从 Nitriding 获取证明并验证哈希...\n")

	pubKeyBytes, err := hex.DecodeString(rawPubKeyHex)
	if err != nil {
		return "", fmt.Errorf("非法的公钥格式: %v", err)
	}
	localHash := sha256.Sum256(pubKeyBytes)
	localHashHex := hex.EncodeToString(localHash[:])

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}
	url := fmt.Sprintf("%s?nonce=%s", suiNitridingURL, nonce)
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

	userData, ok := doc["user_data"].([]byte)
	if !ok {
		return "", fmt.Errorf("证明文档中未找到 user_data 字段")
	}
	userDataHex := hex.EncodeToString(userData)

	if !strings.Contains(userDataHex, localHashHex) {
		return "", fmt.Errorf("❌ 安全警报：公钥哈希匹配失败！业务接口返回的公钥可能被篡改")
	}

	fmt.Println("-------------------------------------------")
	fmt.Printf("Instance ID: %v\n", doc["module_id"])
	fmt.Println("✅ 远程证明验证成功：公钥哈希与硬件签名文档一致。")
	fmt.Println("-------------------------------------------")

	return rawPubKeyHex, nil
}

// encryptSuiPassword ECIES 风格加密函数 (ECDH + AES-GCM)
func encryptSuiPassword(rootPubKeyHex string, password string) (string, error) {
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

// createSuiWallet 创建钱包
func createSuiWallet(verifiedPubKey string) (*SuiCreateWalletResponse, error) {
	fmt.Printf("\n[Step 2] 正在请求 Enclave 创建钱包...\n")

	encryptedPass, err := encryptSuiPassword(verifiedPubKey, suiUserPIN)
	if err != nil {
		return nil, fmt.Errorf("加密密码失败: %v", err)
	}

	requestBody := map[string]string{
		"user_id":            "user_sui_test",
		"login_token":        "token_sui_test",
		"nonce":              suiNonce,
		"encrypted_password": encryptedPass,
		"tee_pk":             verifiedPubKey,
	}
	jsonData, _ := json.Marshal(requestBody)

	resp, err := http.Post(suiEnclaveAppURL+"/tee_wallet/get_fixed_sui_pubkey_for_test", "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, fmt.Errorf("业务请求失败: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("后端业务逻辑返回错误 [%d]: %s", resp.StatusCode, string(body))
	}

	var walletResp SuiCreateWalletResponse
	if err := json.Unmarshal(body, &walletResp); err != nil {
		return nil, fmt.Errorf("解析业务响应失败: %v", err)
	}

	fmt.Printf("✅ 钱包创建成功，公钥: %s\n", walletResp.WalletPubKeys.SuiWalletPubKey)
	return &walletResp, nil
}

// deriveSuiAddressByPubKey 从 Ed25519 公钥派生 SUI 地址
func deriveSuiAddressByPubKey(pubKeyHex string) (string, error) {
	pubKeyBytes, err := hex.DecodeString(pubKeyHex)
	if err != nil {
		return "", err
	}
	tmp := []byte{byte(keypair.Ed25519Flag)}
	tmp = append(tmp, pubKeyBytes...)
	addrBytes := blake2b.Sum256(tmp)
	return "0x" + hex.EncodeToString(addrBytes[:])[:64], nil
}

// signSuiTransactionWithEnclave 请求 Enclave 签名 SUI 交易
func signSuiTransactionWithEnclave(walletPubKey string, encryptedPassword string, deviceShare string, authShare string, txBytesB64 string) (string, error) {
	fmt.Printf("\n[Step 3] 正在请求 Enclave 签名 SUI 交易...\n")

	signReq := SuiSignatureRequest{
		EncryptedPassword: encryptedPassword,
		DeviceShare:       deviceShare,
		PubKey:            walletPubKey,
		RawTx:             txBytesB64, // 注意：SUI 交易在 Enclave 中是 Base64 -> Hex 转换后处理的，但请求结构是 Hex
	}

	// 将 Base64 的 TxBytes 转换为 Hex，因为 Enclave Handler 期望 Hex
	txBytes, _ := base64.StdEncoding.DecodeString(txBytesB64)
	signReq.RawTx = hex.EncodeToString(txBytes)
	signReq.AuthShare = authShare

	jsonData, _ := json.Marshal(signReq)

	resp, err := http.Post(suiEnclaveAppURL+"/tee_wallet/sign_sui_tx", "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return "", fmt.Errorf("签名请求失败: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("签名接口返回错误 [%d]: %s", resp.StatusCode, string(body))
	}

	var sigResp SuiSignatureResponse
	if err := json.Unmarshal(body, &sigResp); err != nil {
		return "", fmt.Errorf("解析签名响应失败: %v", err)
	}

	return sigResp.Signature, nil
}

func main() {
	log.Println("=== Enclave SUI 真实交易签名 & 上链测试启动 ===")

	// 1. 初始化 SUI 客户端
	cli := sui.NewSuiClient(suiDevnetRpc)

	// 2. 获取 Enclave 公钥并验证
	rawPubKey, err := fetchSuiRawPubKey()
	if err != nil {
		log.Fatalf("❌ 步骤 0 失败: %v", err)
	}
	verifiedPubKey, err := fetchSuiRootPubKeyFromAttestation(suiNonce, rawPubKey)
	if err != nil {
		log.Fatalf("❌ 步骤 1 失败: %v", err)
	}

	// 3. 创建钱包
	walletResp, err := createSuiWallet(verifiedPubKey)
	if err != nil {
		log.Fatalf("❌ 创建钱包失败: %v", err)
	}

	// 4. 派生 SUI 地址
	// 注意：在 example/service.go 中，SUI 派生路径是 m/44'/784'/0'/0'/0'，
	// 返回的是该路径下的公钥。
	suiAddr, err := deriveSuiAddressByPubKey(walletResp.WalletPubKeys.SuiWalletPubKey)
	if err != nil {
		log.Fatalf("❌ 派生 SUI 地址失败: %v", err)
	}

	fmt.Printf("\n>>> 你的 SUI 钱包地址: %s <<<\n", suiAddr)
	fmt.Printf("请确保该地址在 SUI Devnet 上有足够的 SUI (Gas 费)\n")
	fmt.Printf("\n[等待中] 请通过 Discord 或 Faucet 领水到上述地址。完成领水后，在当前终端输入 'continue' 并回车以继续...\n")

	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		if strings.ToLower(strings.TrimSpace(scanner.Text())) == "continue" {
			break
		}
		fmt.Printf("输入无效。请输入 'continue' 以继续：")
	}

	// 5. 获取 Coins 用于转账
	ctx := context.Background()
	coinsResp, err := cli.SuiXGetCoins(ctx, models.SuiXGetCoinsRequest{
		Owner:    suiAddr,
		CoinType: "0x2::sui::SUI",
		Limit:    3,
	})
	if err != nil || len(coinsResp.Data) == 0 {
		log.Fatalf("❌ 获取 Coins 失败或余额不足: %v", err)
	}

	// 6. 创建转账交易 (PaySui)
	recipient := "0x579434e13a2d6ffd86979c8bab020bb4eebd3d710a6b764a76b80dbcabd68df6"
	amount := "1000000" // 0.001 SUI
	gasBudget := "100000000"

	txResp, err := cli.PaySui(ctx, models.PaySuiRequest{
		Signer:      suiAddr,
		SuiObjectId: []string{coinsResp.Data[0].CoinObjectId},
		Recipient:   []string{recipient},
		Amount:      []string{amount},
		GasBudget:   gasBudget,
	})
	if err != nil {
		log.Fatalf("❌ 创建 SUI 交易失败: %v", err)
	}

	// 7. 请求 Enclave 签名
	encryptedPassword, _ := encryptSuiPassword(verifiedPubKey, suiUserPIN)
	signature, err := signSuiTransactionWithEnclave(
		walletResp.WalletPubKeys.SuiWalletPubKey,
		encryptedPassword,
		walletResp.KeyShares.DeviceShare,
		walletResp.KeyShares.AuthShare,
		txResp.TxBytes,
	)
	if err != nil {
		log.Fatalf("❌ SUI 签名失败: %v", err)
	}

	// 8. 执行交易
	fmt.Printf("\n[Step 4] 正在广播 SUI 交易...\n")
	executeResp, err := cli.SuiExecuteTransactionBlock(ctx, models.SuiExecuteTransactionBlockRequest{
		TxBytes:   txResp.TxBytes,
		Signature: []string{signature},
		Options: models.SuiTransactionBlockOptions{
			ShowInput:   true,
			ShowEffects: true,
		},
		RequestType: "WaitForLocalExecution",
	})
	if err != nil {
		log.Fatalf("❌ 广播 SUI 交易失败: %v", err)
	}

	fmt.Printf("\n✅ 交易已发送! Hash: %s\n", executeResp.Digest)
	fmt.Printf("执行状态: %s\n", executeResp.Effects.Status.Status)
	fmt.Printf("\n📱 浏览器查看交易:\n")
	fmt.Printf("  Devnet Suivision: https://devnet.suivision.xyz/txblock/%s\n", executeResp.Digest)

	fmt.Println("\n=== SUI 测试完成 ===")
}
