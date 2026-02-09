package main

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/ecdsa"
	"github.com/corvus-ch/shamir"
	"github.com/tyler-smith/go-bip32"
)

const nitridingURL = "http://127.0.0.1:8080/enclave/ready"

// In-memory storage for Enclave shards
var (
	shardsStore = make(map[string][]byte) // key: public key hex, value: enclave shard
	storeMutex  sync.RWMutex
)

// Response structures
type KeyResponse struct {
	KeyShard      string `json:"key_shard"`
	PublicKey     string `json:"public_key"`
	RecoveryShard string `json:"recovery_shard"`
}

type SignatureRequest struct {
	KeyShard string `json:"key_shard_b64"`
	PubKey   string `json:"pub_key"`
	TxHash   string `json:"tx_hash"`
}

type SignatureResponse struct {
	Signature string `json:"signature"`
}

// signalReady notifies nitriding that the application is ready.
func signalReady() error {
	resp, err := http.Get(nitridingURL)
	if err != nil {
		return fmt.Errorf("failed to signal ready: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("expected status code %d but got %d", http.StatusOK, resp.StatusCode)
	}
	return nil
}

// sssKeyHandler handles the generation of new keys and SSS shards.
func sssKeyHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// 1. Generate new private key
	privKey, err := btcec.NewPrivateKey()
	if err != nil {
		http.Error(w, "Failed to generate key", http.StatusInternalServerError)
		return
	}
	secret := privKey.Serialize()
	pubKeyHex := hex.EncodeToString(privKey.PubKey().SerializeCompressed())

	// 2. Split into 3 shards, threshold 2
	parts, err := shamir.Split(secret, 3, 2)
	if err != nil {
		http.Error(w, "Failed to split secret", http.StatusInternalServerError)
		return
	}

	// Extract shards in a deterministic way
	var keys []byte
	for k := range parts {
		keys = append(keys, k)
	}
	// We just pick them
	enclaveShardID := keys[0]
	userShardID := keys[1]
	recoveryShardID := keys[2]

	// 3. Store enclave shard in memory
	storeMutex.Lock()
	shardsStore[pubKeyHex] = append([]byte{enclaveShardID}, parts[enclaveShardID]...)
	storeMutex.Unlock()

	// 4. Return user shard and recovery shard (placeholder for encryption)
	resp := KeyResponse{
		KeyShard:      base64.StdEncoding.EncodeToString(append([]byte{userShardID}, parts[userShardID]...)),
		PublicKey:     pubKeyHex,
		RecoveryShard: base64.StdEncoding.EncodeToString(append([]byte{recoveryShardID}, parts[recoveryShardID]...)),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
	log.Printf("[go] Created new wallet: %s\n", pubKeyHex)
}

// sssSignatureHandler handles signing using combined shards.
func sssSignatureHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req SignatureRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	// 1. Get enclave shard from memory
	storeMutex.RLock()
	enclavePart, ok := shardsStore[req.PubKey]
	storeMutex.RUnlock()
	if !ok {
		http.Error(w, "Wallet not found", http.StatusNotFound)
		return
	}

	// 2. Decode user shard
	userPart, err := base64.StdEncoding.DecodeString(req.KeyShard)
	if err != nil {
		http.Error(w, "Invalid user shard", http.StatusBadRequest)
		return
	}

	// 3. Combine shards
	selection := map[byte][]byte{
		enclavePart[0]: enclavePart[1:],
		userPart[0]:    userPart[1:],
	}
	recoveredSecret, err := shamir.Combine(selection)
	if err != nil {
		http.Error(w, "Failed to combine shards", http.StatusInternalServerError)
		return
	}

	// 4. Derive child key (BIP44)
	master, _ := bip32.NewMasterKey(recoveredSecret)
	// Simplified BIP44: m/44'/60'/0'/0/0 (Ethereum path)
	purpose, _ := master.NewChildKey(bip32.FirstHardenedChild + 44)
	coin, _ := purpose.NewChildKey(bip32.FirstHardenedChild + 60)
	account, _ := coin.NewChildKey(bip32.FirstHardenedChild + 0)
	change, _ := account.NewChildKey(0)
	addressKey, _ := change.NewChildKey(0)

	privKey, _ := btcec.PrivKeyFromBytes(addressKey.Key)

	txHashBytes, err := hex.DecodeString(req.TxHash)
	if err != nil {
		// Try interpreting as raw string if hex decode fails
		txHashBytes = []byte(req.TxHash)
	}

	// Sign using standard ECDSA
	sig := ecdsa.Sign(privKey, txHashBytes)

	resp := SignatureResponse{
		Signature: base64.StdEncoding.EncodeToString(sig.Serialize()),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
	log.Printf("[go] Signed tx for wallet: %s\n", req.PubKey)
}

func main() {
	// Start the application server
	http.HandleFunc("/app/sss/key", sssKeyHandler)
	http.HandleFunc("/app/sss/signature", sssSignatureHandler)

	// Add a simple health check or root handler
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Go Safe Wallet Service Running\n")
	})

	go func() {
		log.Println("[go] Running server on port 8088")
		if err := http.ListenAndServe(":8088", nil); err != nil {
			log.Fatalf("Server failed: %v", err)
		}
	}()

	// Signal ready to nitriding
	time.Sleep(1 * time.Second) // Wait a bit for server to start
	if err := signalReady(); err != nil {
		log.Printf("[go] Error signaling ready: %v\n", err)
	} else {
		log.Println("[go] Signalled to nitriding that we're ready.")
	}

	// Keep main running
	select {}
}
