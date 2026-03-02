package main

import (
	"context"
	"fmt"
	"log"
	"strings"

	"github.com/block-vision/sui-go-sdk/constant"
	"github.com/block-vision/sui-go-sdk/models"
	"github.com/block-vision/sui-go-sdk/signer"
	"github.com/block-vision/sui-go-sdk/sui"
)

func main() {
	ctx := context.Background()

	// ✅ 默认使用 Devnet
	network := constant.SuiDevnet

	// 步骤0：初始化客户端
	fmt.Println("=== Sui 转账完整流程 ===\n")
	fmt.Printf("步骤0：初始化%s客户端...\n", getNetworkName(network))

	var cli sui.ISuiAPI
	switch network {
	case constant.SuiTestnet:
		cli = sui.NewSuiClient(constant.SuiTestnetEndpoint)
	case constant.SuiDevnet:
		cli = sui.NewSuiClient("https://fullnode.devnet.sui.io")
	case constant.SuiLocalnet:
		cli = sui.NewSuiClient("http://127.0.0.1:9000")
	default:
		cli = sui.NewSuiClient("https://fullnode.devnet.sui.io")
	}
	fmt.Printf("✓ %s客户端连接成功\n\n", getNetworkName(network))

	// 步骤1：生成两个新账户 (Ed25519 方案)
	fmt.Println("步骤1：生成测试账户...")

	// 账户 A (发送方) - 使用助记词生成
	signerA, err := signer.NewSignertWithMnemonic("test walk nut penalty hip pave soap entry language right filter choice")
	if err != nil {
		log.Fatalf("Failed to generate account A: %v", err)
	}
	addrA := signerA.Address

	fmt.Printf("账户 A (发送方)\n")
	fmt.Printf("  地址: %s\n\n", addrA)

	// 账户 B (接收方)
	signerB, err := signer.NewSignertWithMnemonic("letter advice cage absurd amount doctor acoustic avoid letter advice cage above")
	if err != nil {
		log.Fatalf("Failed to generate account B: %v", err)
	}
	addrB := signerB.Address

	fmt.Printf("账户 B (接收方)\n")
	fmt.Printf("  地址: %s\n\n", addrB)

	// 步骤2：确认账户余额 (跳过从Faucet领取，用户已手动充值)
	fmt.Println("步骤2：确认账户 A 余额...")
	fmt.Printf("账户 A: %s\n\n", addrA)

	// 步骤3：获取coins
	fmt.Println("步骤3：获取账户 coins...")
	coins, err := getCoinObjects(ctx, cli, addrA)
	if err != nil {
		log.Fatalf("❌ 无法获取coins: %v\n请检查：\n1. 账户地址是否正确\n2. 是否已充值\n3. 网络连接是否正常", err)
	}
	fmt.Printf("✓ 找到 %d 个coin对象\n", len(coins))

	for i, coin := range coins {
		fmt.Printf("  Coin %d: %s (Version: %s, Balance: %s MIST)\n",
			i+1, coin.CoinObjectId, coin.Version, coin.Balance)
	}
	fmt.Println()

	// 步骤4：获取参考gas价格
	fmt.Println("步骤4：获取参考gas价格...")
	gasPrice, err := cli.SuiXGetReferenceGasPrice(ctx)
	if err != nil {
		log.Fatalf("Failed to get reference gas price: %v", err)
	}
	fmt.Printf("✓ 当前Gas价格: %s MIST/单位\n\n", gasPrice)

	// 步骤5：创建转账交易
	fmt.Println("步骤5：创建转账交易...")
	gasObjectID := coins[0].CoinObjectId
	transferAmount := "1000000" // 0.001 SUI
	gasBudget := "100000000"    // 0.1 SUI

	fmt.Printf("转账信息:\n")
	fmt.Printf("  网络: %s\n", getNetworkName(network))
	fmt.Printf("  发送方: %s\n", addrA)
	fmt.Printf("  接收方: %s\n", addrB)
	fmt.Printf("  转账金额: %s MIST (0.001 SUI)\n", transferAmount)
	fmt.Printf("  Gas预算: %s MIST (0.1 SUI)\n", gasBudget)
	fmt.Printf("  Gas对象ID: %s\n\n", gasObjectID)

	txResp, err := cli.PaySui(ctx, models.PaySuiRequest{
		Signer:      addrA,
		SuiObjectId: []string{coins[0].CoinObjectId},
		Recipient:   []string{addrB},
		Amount:      []string{transferAmount},
		GasBudget:   gasBudget,
	})
	if err != nil {
		log.Fatalf("Failed to create transaction: %v", err)
	}
	fmt.Println("✓ 交易创建成功")
	if len(txResp.TxBytes) > 60 {
		fmt.Printf("  交易字节 (base64): %s...\n\n", txResp.TxBytes[:60])
	} else {
		fmt.Printf("  交易字节 (base64): %s\n\n", txResp.TxBytes)
	}

	// 步骤6：签名交易
	fmt.Println("步骤6：对交易进行签名...")
	// 💡 注意：在该版本的 SDK 中，signerA.SignTransaction 内部使用了错误的 IntentScope (PersonalMessage)
	// 对于交易，我们必须使用 TransactionDataIntentScope (0)
	signedTx, err := signerA.SignMessage(txResp.TxBytes, constant.TransactionDataIntentScope)
	if err != nil {
		log.Fatalf("Failed to sign transaction: %v", err)
	}
	fmt.Println("✓ 交易签名成功")
	if len(signedTx.Signature) > 60 {
		fmt.Printf("  签名 (base64): %s...\n\n", signedTx.Signature[:60])
	} else {
		fmt.Printf("  签名 (base64): %s\n\n", signedTx.Signature)
	}

	// 步骤7：执行交易（上链）
	fmt.Println("步骤7：提交交易到Sui网络...")
	executeResp, err := cli.SuiExecuteTransactionBlock(ctx, models.SuiExecuteTransactionBlockRequest{
		TxBytes:   txResp.TxBytes,
		Signature: []string{signedTx.Signature},
		Options: models.SuiTransactionBlockOptions{
			ShowInput:         true,
			ShowEffects:       true,
			ShowEvents:        true,
			ShowObjectChanges: true,
		},
		RequestType: "WaitForLocalExecution",
	})
	if err != nil {
		log.Fatalf("Failed to execute transaction: %v", err)
	}

	// 步骤8：打印结果
	fmt.Println("\n" + strings.Repeat("=", 60))
	fmt.Println("✅ 交易执行成功!")
	fmt.Println(strings.Repeat("=", 60))
	fmt.Printf("\n交易哈希: %s\n", executeResp.Digest)
	fmt.Printf("执行状态: %s\n", executeResp.Effects.Status.Status)
	fmt.Printf("网络: %s\n", getNetworkName(network))

	fmt.Printf("\nGas消耗详情:\n")
	fmt.Printf("  计算费用: %s MIST\n", executeResp.Effects.GasUsed.ComputationCost)
	fmt.Printf("  存储费用: %s MIST\n", executeResp.Effects.GasUsed.StorageCost)
	fmt.Printf("  存储返还: %s MIST\n", executeResp.Effects.GasUsed.StorageRebate)

	fmt.Printf("\n账户变动:\n")
	fmt.Printf("  账户 A (发送方): %s\n", addrA)
	fmt.Printf("  账户 B (接收方): %s\n", addrB)

	fmt.Printf("\n📱 浏览器查看交易:\n")
	printExplorerLink(network, executeResp.Digest)

	fmt.Println("\n" + strings.Repeat("=", 60))
}

// 从Faucet领取测试币
func requestSuiFromFaucet(network string, address string) error {
	faucetHost, err := sui.GetFaucetHost(network)
	if err != nil {
		return err
	}

	err = sui.RequestSuiFromFaucet(faucetHost, address, nil)
	if err != nil {
		return fmt.Errorf("faucet request failed: %v", err)
	}

	return nil
}

// 获取账户的coin对象
func getCoinObjects(ctx context.Context, client sui.ISuiAPI, address string) ([]models.CoinData, error) {
	fmt.Printf("🔍 正在为地址 %s 查询 SUI coins...\n", address)
	resp, err := client.SuiXGetCoins(ctx, models.SuiXGetCoinsRequest{
		Owner:    address,
		CoinType: "0x2::sui::SUI",
		Limit:    10,
	})
	if err != nil {
		// 💡 针对 "no result field" 错误的临时处理：如果看到该错误，说明 SDK 可能不兼容当前 RPC 的响应格式
		if strings.Contains(err.Error(), "no result field") {
			fmt.Printf("⚠️ 警告: SDK 与 RPC 响应格式不匹配 (%v)\n", err)
			fmt.Println("💡 提示: 这通常是因为 SDK 版本较旧。建议尝试使用 block-vision 官方最新的 RPC 节点或联系支持。")
		}
		fmt.Printf("❌ SuiXGetCoins 失败: %v\n", err)
		return nil, fmt.Errorf("failed to get coins: %v", err)
	}

	if len(resp.Data) == 0 {
		fmt.Printf("⚠️ 响应成功但未找到数据 (Data 长度为 0)\n")
		return nil, fmt.Errorf("no coins found for address")
	}

	return resp.Data, nil
}

// 获取网络名称
func getNetworkName(network string) string {
	switch network {
	case constant.SuiTestnet:
		return "Testnet"
	case constant.SuiDevnet:
		return "Devnet"
	case constant.SuiLocalnet:
		return "Localnet"
	default:
		return "Unknown"
	}
}

// 打印浏览器链接
func printExplorerLink(network string, txDigest string) {
	switch network {
	case constant.SuiTestnet:
		fmt.Printf("  Testnet Suivision: https://testnet.suivision.xyz/txblock/%s\n", txDigest)
		fmt.Printf("  Testnet Explorer: https://testnet-explorer.sui.io/txblock/%s\n", txDigest)
	case constant.SuiDevnet:
		fmt.Printf("  Devnet Suivision: https://devnet.suivision.xyz/txblock/%s\n", txDigest)
		fmt.Printf("  Devnet Explorer: https://devnet-explorer.sui.io/txblock/%s\n", txDigest)
	case constant.SuiLocalnet:
		fmt.Printf("  Localnet (需要本地部署): http://localhost:3000/txblock/%s\n", txDigest)
	}
}
