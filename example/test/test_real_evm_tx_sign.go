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
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"os"
	"strings"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/fxamacker/cbor/v2"
)

const (
	realTxEnclaveAppURL = "http://localhost:8088"
	realTxNitridingURL  = "https://localhost:10443/enclave/attestation"
	realTxNonce         = "1234567890abcdef1234567890abcdef12345678" // 40-digit hex string
	realTxUserPIN       = "my-secure-pin-123456"
	realTxRpcURL        = "https://ethereum-sepolia-rpc.publicnode.com" // Sepolia Testnet RPC
	realTxChainID       = 11155111                                      // Sepolia Chain ID
)

type RealTxCreateWalletResponse struct {
	AuthShare       string `json:"auth_share"`
	UserShare       string `json:"user_share"`
	DeviceShare     string `json:"device_share"`
	RecoverShare    string `json:"recover_share"`
	EvmWalletPubKey string `json:"evm_wallet_pub_key"`
	SignedNonce     string `json:"signed_nonce"`
}

type RealTxSignatureRequest struct {
	EncryptedPassword string `json:"encrypted_password"` // encrypted with rootPubKey
	DeviceShare       string `json:"device_share"`       // encrypted with userPassword
	PubKey            string `json:"pub_key"`
	RawTx             string `json:"raw_tx"`
	AuthShare         string `json:"auth_share"`
}

type RealTxSignatureResponse struct {
	Signature       string `json:"signature"`
	WalletPublicKey string `json:"wallet_public_key"`
}

// fetchRealTxRawPubKey 从业务接口获取公钥原文 (TEE_PubKey)
func fetchRealTxRawPubKey() (string, error) {
	fmt.Printf("[Step 0] 正在从业务接口获取公钥原文...\n")
	resp, err := http.Get(realTxEnclaveAppURL + "/tee_wallet/tee_pubkey")
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

// fetchRealTxRootPubKeyFromAttestation 从 Nitriding 获取证明文档并比对本地 Hash
func fetchRealTxRootPubKeyFromAttestation(nonce string, rawPubKeyHex string) (string, error) {
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
	url := fmt.Sprintf("%s?nonce=%s", realTxNitridingURL, nonce)
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
		return "", fmt.Errorf("\u274C 安全警报：公钥哈希匹配失败！业务接口返回的公钥可能被篡改")
	}

	fmt.Println("-------------------------------------------")
	fmt.Printf("Instance ID: %v\n", doc["module_id"])
	fmt.Println("\u2705 远程证明验证成功：公钥哈希与硬件签名文档一致。")
	fmt.Println("-------------------------------------------")

	return rawPubKeyHex, nil
}

// encryptRealTxPassword ECIES 风格加密函数 (ECDH + AES-GCM)
func encryptRealTxPassword(rootPubKeyHex string, password string) (string, error) {
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

// createRealTxWallet 创建钱包
func createRealTxWallet(verifiedPubKey string) (*RealTxCreateWalletResponse, error) {
	fmt.Printf("\n[Step 2] 正在请求 Enclave 创建钱包...\n")

	encryptedPass, err := encryptRealTxPassword(verifiedPubKey, realTxUserPIN)
	if err != nil {
		return nil, fmt.Errorf("加密密码失败: %v", err)
	}

	requestBody := map[string]string{
		"user_id":            "user_real_tx_test",
		"login_token":        "token_real_tx_test",
		"nonce":              realTxNonce,
		"encrypted_password": encryptedPass,
	}
	jsonData, _ := json.Marshal(requestBody)

	resp, err := http.Post(realTxEnclaveAppURL+"/tee_wallet/get_fixed_evm_pubkey_for_test", "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, fmt.Errorf("业务请求失败: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("后端业务逻辑返回错误 [%d]: %s", resp.StatusCode, string(body))
	}

	var walletResp RealTxCreateWalletResponse
	if err := json.Unmarshal(body, &walletResp); err != nil {
		return nil, fmt.Errorf("解析业务响应失败: %v", err)
	}

	fmt.Printf("\u2705 钱包创建成功，公钥: %s\n", walletResp.EvmWalletPubKey)
	return &walletResp, nil
}

// signTransactionWithRecovery 签名交易并获取完整的以太坊签名 (含 Recovery ID)
func signTransactionWithRecovery(walletPubKey string, encryptedPassword string, deviceShare string, authShare string, tx *types.Transaction) ([]byte, error) {
	fmt.Printf("\n[Step 3] 正在请求 Enclave 签名交易...\n")

	// 计算交易哈希
	signer := types.LatestSignerForChainID(big.NewInt(realTxChainID))
	h := signer.Hash(tx)

	// 准备原始交易数据的十六进制
	rawTxBytes, err := tx.MarshalBinary()
	if err != nil {
		return nil, err
	}
	rawTxHex := hex.EncodeToString(rawTxBytes)

	signReq := RealTxSignatureRequest{
		EncryptedPassword: encryptedPassword,
		DeviceShare:       deviceShare,
		PubKey:            walletPubKey,
		RawTx:             rawTxHex,
		AuthShare:         authShare,
	}
	jsonData, _ := json.Marshal(signReq)

	resp, err := http.Post(realTxEnclaveAppURL+"/tee_wallet/sign_evm_tx", "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, fmt.Errorf("签名请求失败: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("签名接口返回错误 [%d]: %s", resp.StatusCode, string(body))
	}

	var sigResp RealTxSignatureResponse
	if err := json.Unmarshal(body, &sigResp); err != nil {
		return nil, fmt.Errorf("解析签名响应失败: %v", err)
	}

	sigBytes, err := base64.StdEncoding.DecodeString(sigResp.Signature)
	if err != nil {
		return nil, err
	}

	// 解析 DER 签名获取 R, S (由于 btcec 字段不导出，我们手动解析 ASN1)
	var derSig struct {
		R, S *big.Int
	}
	if _, err := asn1.Unmarshal(sigBytes, &derSig); err != nil {
		return nil, fmt.Errorf("ASN1 解析签名失败: %v", err)
	}

	rBytes := derSig.R.Bytes()
	sBytes := derSig.S.Bytes()

	// 补全到 32 字节
	rBlock := make([]byte, 32)
	sBlock := make([]byte, 32)
	copy(rBlock[32-len(rBytes):], rBytes)
	copy(sBlock[32-len(sBytes):], sBytes)

	// 尝试恢复 V (Recovery ID)
	walletPubKeyBytes, _ := hex.DecodeString(walletPubKey)

	fullSig := make([]byte, 65)
	copy(fullSig[0:32], rBlock)
	copy(fullSig[32:64], sBlock)

	for v := 0; v <= 1; v++ {
		fullSig[64] = byte(v)
		recoveredPubKey, err := crypto.Ecrecover(h.Bytes(), fullSig)
		if err != nil {
			continue
		}

		parsedRecovered, err := crypto.UnmarshalPubkey(recoveredPubKey)
		if err != nil {
			continue
		}
		compressedRecovered := crypto.CompressPubkey(parsedRecovered)

		if bytes.Equal(compressedRecovered, walletPubKeyBytes) {
			fmt.Printf("\u2705 签名成功并校准 Recovery ID: %d\n", v)
			return fullSig, nil
		}
	}

	return nil, fmt.Errorf("无法恢复有效的 Recovery ID")
}

func main() {
	log.Println("=== Enclave 真实交易签名 & 上链测试启动 ===")

	// 1. 初始化客户端
	client, err := ethclient.Dial(realTxRpcURL)
	if err != nil {
		log.Fatalf("无法连接到 RPC: %v", err)
	}
	defer client.Close()

	// 2. 获取 Enclave 公钥并验证
	rawPubKey, err := fetchRealTxRawPubKey()
	if err != nil {
		log.Fatalf("\u274C 步骤 0 失败: %v", err)
	}
	verifiedPubKey, err := fetchRealTxRootPubKeyFromAttestation(realTxNonce, rawPubKey)
	if err != nil {
		log.Fatalf("\u274C 步骤 1 失败: %v", err)
	}

	// 3. 创建钱包
	walletResp, err := createRealTxWallet(verifiedPubKey)
	if err != nil {
		log.Fatalf("\u274C 创建钱包失败: %v", err)
	}

	pkBytes, _ := hex.DecodeString(walletResp.EvmWalletPubKey)
	pk, err := crypto.DecompressPubkey(pkBytes)
	if err != nil {
		log.Fatalf("解析钱包公钥失败: %v", err)
	}
	walletAddr := crypto.PubkeyToAddress(*pk)

	fmt.Printf("\n>>> 你的钱包地址: %s <<<\n", walletAddr.Hex())
	fmt.Printf("请确保该地址在 Sepolia 测试网上有足够的 ETH (Gas 费)\n")
	fmt.Printf("\n[等待中] 请通过网页领水到上述地址。完成领水后，在当前终端输入 'continue' 并回车以继续...\n")

	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		if strings.ToLower(strings.TrimSpace(scanner.Text())) == "continue" {
			break
		}
		fmt.Printf("输入无效。请输入 'continue' 以继续：")
	}

	// 4. 构造交易
	nonce, err := client.PendingNonceAt(context.Background(), walletAddr)
	if err != nil {
		log.Fatalf("获取 Nonce 失败: %v", err)
	}

	gasPrice, err := client.SuggestGasPrice(context.Background())
	if err != nil {
		log.Fatalf("获取 GasPrice 失败: %v", err)
	}

	toAddress := common.HexToAddress("0x71C7656EC7ab88b098defB751B7401B5f6d8976F")
	value := big.NewInt(1000000000000000) // 0.001 ETH
	gasLimit := uint64(21000)

	// 使用 Legacy 交易
	tx := types.NewTransaction(nonce, toAddress, value, gasLimit, gasPrice, nil)

	// 5. 请求 Enclave 签名
	encryptedPassword, _ := encryptRealTxPassword(verifiedPubKey, realTxUserPIN)
	fullSignature, err := signTransactionWithRecovery(walletResp.EvmWalletPubKey, encryptedPassword, walletResp.DeviceShare, walletResp.AuthShare, tx)
	if err != nil {
		log.Fatalf("\u274C 签名失败: %v", err)
	}

	// 6. 装配已签名交易
	signer := types.LatestSignerForChainID(big.NewInt(realTxChainID))
	signedTx, err := tx.WithSignature(signer, fullSignature)
	if err != nil {
		log.Fatalf("装配签名交易失败: %v", err)
	}

	// 7. 发送交易
	fmt.Printf("\n[Step 4] 正在广播交易...\n")
	err = client.SendTransaction(context.Background(), signedTx)
	if err != nil {
		log.Printf("\u274C 广播交易失败: %v (通常是因为余额不足)\n", err)
		fmt.Printf("你可以手动给 %s 充值后重新运行此脚本\n", walletAddr.Hex())
		return
	}

	fmt.Printf("\u2705 交易已发送! Hash: %s\n", signedTx.Hash().Hex())
	fmt.Printf("等待区块确认...\n")

	// 8. 验证余额
	balance, err := client.BalanceAt(context.Background(), walletAddr, nil)
	if err == nil {
		fmt.Printf("当前账户余额: %s Wei\n", balance.String())
	}

	fmt.Println("\n=== 测试完成 ===")
}
