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
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/fxamacker/cbor/v2"
)

const (
	realTxEnclaveAppURL = "http://localhost:8088"
	realTxNitridingURL  = "https://localhost:10443/enclave/attestation"
	realTxNonce         = "1234567890abcdef1234567890abcdef12345678"
	realTxUserPIN       = "my-secure-pin-123456"
	realTxRpcURL        = "https://ethereum-sepolia-rpc.publicnode.com"
	realTxChainID       = 11155111
)

// -----------------------------------------------------------------------------
// 数据结构定义
// -----------------------------------------------------------------------------

type RealTxKeyShares struct {
	AuthShare    string `json:"auth_share"`
	DeviceShare  string `json:"device_share"`
	RecoverShare string `json:"recover_share"`
}

type RealTxWalletPubKeys struct {
	EvmWalletPubKey string `json:"evm_wallet_pub_key"`
	SuiWalletPubKey string `json:"sui_wallet_pub_key"`
}

type RealTxCreateWalletResponse struct {
	KeyShares     RealTxKeyShares     `json:"key_shares"`
	WalletPubKeys RealTxWalletPubKeys `json:"wallet_pub_keys"`
	SignedNonce   string              `json:"signed_nonce"`
	Password      string              `json:"password"`
}

type RealTxSignatureRequest struct {
	EncryptedPassword string `json:"encrypted_password"`
	DeviceShare       string `json:"device_share"`
	PubKey            string `json:"wallet_pub_key"`
	RawTx             string `json:"raw_tx"` // Hex string of 0x02 || RLP(...)
	AuthShare         string `json:"auth_share"`
}

type RealTxSignatureResponse struct {
	Signature       string `json:"signature"`
	WalletPublicKey string `json:"wallet_public_key"`
}

// -----------------------------------------------------------------------------
// 核心修复：构造 EIP-1559 未签名交易 RLP (不使用反射)
// -----------------------------------------------------------------------------

func encodeUnsignedEIP1559Tx(chainId *big.Int, nonce uint64, gasTipCap, gasFeeCap *big.Int, gas uint64, to *common.Address, value *big.Int, data []byte, accessList types.AccessList) (string, error) {
	// EIP-1559 编码规范: 0x02 || RLP([chainID, nonce, maxPriorityFeePerGas, maxFeePerGas, gasLimit, to, value, data, accessList])
	var toField interface{}
	if to != nil {
		toField = to
	} else {
		toField = []byte{}
	}

	unsignedFields := []interface{}{
		chainId,
		nonce,
		gasTipCap,
		gasFeeCap,
		gas,
		toField,
		value,
		data,
		accessList,
	}

	encodedPayload, err := rlp.EncodeToBytes(unsignedFields)
	if err != nil {
		return "", fmt.Errorf("RLP 编码失败: %v", err)
	}

	// 前置 EIP-2718 类型字节 0x02
	result := append([]byte{types.DynamicFeeTxType}, encodedPayload...)
	return hex.EncodeToString(result), nil
}

// -----------------------------------------------------------------------------
// 签名与网络交互
// -----------------------------------------------------------------------------

func signTransactionWithRecovery(walletPubKey string, encryptedPassword, deviceShare, authShare string, innerTx *types.DynamicFeeTx) ([]byte, error) {
	fmt.Printf("\n[Step 3] 正在请求 Enclave 签名交易...\n")

	// 1. 生成 RawTx 用于发送给 TEE (0x02 || RLP)
	rawTxHex, err := encodeUnsignedEIP1559Tx(
		innerTx.ChainID, innerTx.Nonce, innerTx.GasTipCap, innerTx.GasFeeCap,
		innerTx.Gas, innerTx.To, innerTx.Value, innerTx.Data, innerTx.AccessList,
	)
	if err != nil {
		return nil, err
	}

	// 2. 计算本地哈希用于恢复 V (Recovery ID)
	tx := types.NewTx(innerTx)
	signer := types.NewLondonSigner(innerTx.ChainID)
	txHash := signer.Hash(tx)

	// 3. 发送请求
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
		return nil, err
	}
	defer resp.Body.Close()

	var sigResp RealTxSignatureResponse
	if err := json.NewDecoder(resp.Body).Decode(&sigResp); err != nil {
		return nil, err
	}

	sigBytes, _ := base64.StdEncoding.DecodeString(sigResp.Signature)
	var derSig struct{ R, S *big.Int }
	if _, err := asn1.Unmarshal(sigBytes, &derSig); err != nil {
		return nil, fmt.Errorf("ASN1 解析失败: %v", err)
	}

	// 拼接 R(32) + S(32)
	rBytes, sBytes := derSig.R.Bytes(), derSig.S.Bytes()
	fullSig := make([]byte, 65)
	copy(fullSig[32-len(rBytes):32], rBytes)
	copy(fullSig[64-len(sBytes):64], sBytes)

	// 4. 恢复 Recovery ID
	walletPubKeyBytes, _ := hex.DecodeString(walletPubKey)
	for v := 0; v <= 1; v++ {
		fullSig[64] = byte(v)
		recovered, err := crypto.Ecrecover(txHash.Bytes(), fullSig)
		if err == nil {
			recParsed, _ := crypto.UnmarshalPubkey(recovered)
			if bytes.Equal(crypto.CompressPubkey(recParsed), walletPubKeyBytes) {
				fmt.Printf("✅ 签名成功，Recovery ID: %d\n", v)
				return fullSig, nil
			}
		}
	}
	return nil, fmt.Errorf("无法校准 Recovery ID，请检查 Enclave 内部签名逻辑")
}

// -----------------------------------------------------------------------------
// 其他辅助函数 (保持不变)
// -----------------------------------------------------------------------------

func fetchRealTxRawPubKey() (string, error) {
	resp, err := http.Get(realTxEnclaveAppURL + "/tee_wallet/tee_pubkey")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	var res map[string]string
	json.NewDecoder(resp.Body).Decode(&res)
	return res["public_key"], nil
}

func fetchRealTxRootPubKeyFromAttestation(nonce string, rawPubKeyHex string) (string, error) {
	pubKeyBytes, _ := hex.DecodeString(rawPubKeyHex)
	localHash := sha256.Sum256(pubKeyBytes)
	localHashHex := hex.EncodeToString(localHash[:])
	tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	client := &http.Client{Transport: tr}
	resp, err := client.Get(fmt.Sprintf("%s?nonce=%s", realTxNitridingURL, nonce))
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	b64Doc := strings.TrimSpace(string(body))
	rawDoc, _ := base64.StdEncoding.DecodeString(b64Doc)
	var coseSign1 []cbor.RawMessage
	cbor.Unmarshal(rawDoc, &coseSign1)
	var payloadBytes []byte
	cbor.Unmarshal(coseSign1[2], &payloadBytes)
	var doc map[string]interface{}
	cbor.Unmarshal(payloadBytes, &doc)
	userDataHex := hex.EncodeToString(doc["user_data"].([]byte))
	if !strings.Contains(userDataHex, localHashHex) {
		return "", fmt.Errorf("哈希不匹配")
	}
	return rawPubKeyHex, nil
}

func encryptRealTxPassword(rootPubKeyHex string, password string) (string, error) {
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

func createRealTxWallet(verifiedPubKey string) (*RealTxCreateWalletResponse, error) {
	encryptedPass, _ := encryptRealTxPassword(verifiedPubKey, realTxUserPIN)
	requestBody := map[string]string{
		"user_id":            "user_real_tx_test",
		"encrypted_password": encryptedPass,
		"tee_pk":             verifiedPubKey,
	}
	jsonData, _ := json.Marshal(requestBody)
	resp, _ := http.Post(realTxEnclaveAppURL+"/tee_wallet/get_fixed_evm_pubkey_for_test", "application/json", bytes.NewBuffer(jsonData))
	defer resp.Body.Close()
	var walletResp RealTxCreateWalletResponse
	json.NewDecoder(resp.Body).Decode(&walletResp)
	return &walletResp, nil
}

// -----------------------------------------------------------------------------
// 主程序
// -----------------------------------------------------------------------------

func main() {
	client, err := ethclient.Dial(realTxRpcURL)
	if err != nil {
		log.Fatal(err)
	}
	defer client.Close()

	// 1. 获取并验证 TEE 公钥
	rawPubKey, _ := fetchRealTxRawPubKey()
	verifiedPubKey, _ := fetchRealTxRootPubKeyFromAttestation(realTxNonce, rawPubKey)

	// 2. 创建钱包
	walletResp, _ := createRealTxWallet(verifiedPubKey)
	pkBytes, _ := hex.DecodeString(walletResp.WalletPubKeys.EvmWalletPubKey)
	pk, _ := crypto.DecompressPubkey(pkBytes)
	walletAddr := crypto.PubkeyToAddress(*pk)

	fmt.Printf("\n>>> 钱包地址: %s <<<\n", walletAddr.Hex())
	fmt.Println("请确保有 Sepolia ETH，完成后输入 'continue':")
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		if strings.ToLower(scanner.Text()) == "continue" {
			break
		}
	}

	// 3. 构造交易参数
	nonce, _ := client.PendingNonceAt(context.Background(), walletAddr)
	header, _ := client.HeaderByNumber(context.Background(), nil)
	gasTipCap := big.NewInt(1500000000) // 1.5 Gwei
	gasFeeCap := new(big.Int).Add(header.BaseFee, gasTipCap)

	// 直接定义 DynamicFeeTx 结构体，避免从 Transaction 反射提取
	innerTx := &types.DynamicFeeTx{
		ChainID:   big.NewInt(realTxChainID),
		Nonce:     nonce,
		GasTipCap: gasTipCap,
		GasFeeCap: gasFeeCap,
		Gas:       21000,
		To:        &common.Address{0x01},
		Value:     big.NewInt(1000000000000000), // 0.001 ETH
	}

	// 4. 请求签名
	encPass, _ := encryptRealTxPassword(verifiedPubKey, realTxUserPIN)
	fullSig, err := signTransactionWithRecovery(walletResp.WalletPubKeys.EvmWalletPubKey, encPass, walletResp.KeyShares.DeviceShare, walletResp.KeyShares.AuthShare, innerTx)
	if err != nil {
		log.Fatal(err)
	}

	// 5. 装配并广播
	signer := types.NewLondonSigner(innerTx.ChainID)
	signedTx, _ := types.NewTx(innerTx).WithSignature(signer, fullSig)

	fmt.Printf("[Step 4] 正在广播交易...\n")
	err = client.SendTransaction(context.Background(), signedTx)
	if err != nil {
		fmt.Printf("❌ 广播失败: %v\n", err)
		return
	}
	fmt.Printf("✅ 交易发送成功! Hash: %s\n", signedTx.Hash().Hex())
}
