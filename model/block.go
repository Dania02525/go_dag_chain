package model

import (
	"errors"
	"go-metering/database"
	"github.com/lib/pq"
	"encoding/json"
	"crypto/sha256"
	"crypto/ed25519"
	"encoding/hex"
)

type Block struct {
    BlockHash     string  	`json:"block_hash"`
    BlockType     string  	`json:"block_type"`
    PreviousHash  string  	`json:"previous_hash"`
    LinkedHash    string  	`json:"linked_hash"`
    Account       string  	`json:"account_id"`
    Receivers     []string  `json:"receiver_ids"`
    Amount        uint64  	`json:"amount;default:0"`
    Balance       uint64  	`json:"balance;default:0"`
    Signature     string  	`json:"signature"`
    Timestamp     uint32  	`json:"timestamp"`
}

type BlockIndex struct {
	Unique			bool
	Name    		string
	KeyDerivation 	func(*Block) string
	ValueDerivation func(*Block) *Block
}

func calculateBlockHash(block *Block) ([32]byte, error) {
	bytes, err := json.Marshal(struct {
		BlockType string
		PreviousHash string
		LinkedHash string
		Account string
		Receivers []string
		Amount uint64
		Balance uint64
	}{
		BlockType: block.BlockType,
		PreviousHash: block.PreviousHash,
		LinkedHash: block.LinkedHash,
		Account: block.Account,
		Receivers: block.Receivers,
		Amount: block.Amount,
		Balance: block.Balance,
	})
	if err != nil {
		return [32]byte{}, err
	}

	return sha256.Sum256(bytes), nil
}

func (block *Block) PreviousBlock() (*Block, error) {
	value, closer, err := db.Get(block.PreviousHash)
	if err != nil {
		return &Block{}, err
	}
	closer.Close()

	return value, nil
}

func (block *Block) LinkedBlock() (*Block, error) {
	value, closer, err := db.Get(block.LinkedHash)
	if err != nil {
		return &Block{}, err
	}
	closer.Close()
	
	return value, nil
}

func (block *Block) indexes() ([]BlockIndex) {
	var indices []BlockIndex
	switch blockType := block.BlockType; blockType {
	case "genesis":
		indices = append(indices, BlockIndex{
			// ensure there is only one genesis type block
			Unique: true,
			Name: "single_genesis"
			KeyDerivation: func(block *Block) string {
				return block.BlockType
			},
			ValueDerivation: func(block *Block) *Block {
				return block
			}
		}, BlockIndex{
			// genesis block should surface in account blocks
			Unique: false
			Name: "account_blocks"
			KeyDerivation: func(block *Block) string {
				return block.Account
			},
			ValueDerivation: func(block *Block) *Block {
				return block
			}
		})
	case "account_create":
		indices = indices.append(BlockIndex{
			Unique: false
			Name: "account_blocks"
			KeyDerivation: func(block *Block) string {
				return block.Account
			},
			ValueDerivation: func(block *Block) *Block {
				return block
			}
		})
	case "recieve":
		indices = indices.append(BlockIndex{
			Unique: true
			Name: "receive_account_linked_hash"
			KeyDerivation: func(block *Block) string {
				return block.Account + ":" + block.LinkedHash
			},
			ValueDerivation: func(block *Block) *Block {
				return block.LinkedBlock
			}
		}, BlockIndex{
			Unique: false
			Name: "account_blocks"
			KeyDerivation: func(block *Block) string {
				return block.Account
			},
			ValueDerivation: func(block *Block) *Block {
				return block
			}
		}, BlockIndex{
			Unique: false
			Name: "previous_blocks"
			KeyDerivation: func(block *Block) string {
				return block.PreviousHash
			},
			ValueDerivation: func(block *Block) *Block {
				return block.PreviousBlock
			}
		})
	case "payout":
		indices = indices.append(BlockIndex{
			Unique: false
			Name: "account_blocks"
			KeyDerivation: func(block *Block) string {
				return block.Account
			}
		}, BlockIndex{
			Unique: false
			Name: "previous_blocks"
			KeyDerivation: func(block *Block) string {
				return block.PreviousHash
			},
			ValueDerivation: func(block *Block) *Block {
				return block.PreviousBlock
			}
		})
	}

	return indices
}

func (block *Block) Save() (*Block, error) {
	err := database.Database.Set(block.BlockHash, block, database.Sync)
	if err != nil {
		return &Block{}, err
	}
	// save the indexes
	for _, index := range indexes(block) {
		val, closer, err := database.Database.Get(index.KeyDerivation(block))
		if block.Unique && err == nil {
			// unique indexes should not exist already and should result in the error
			closer.Close()
			return &Block{}, errors.New("failed on unique index violation: " + index.Name)
		}
		if err == database.NotFound {
			// simply write the index
			closer.Close()
			err := database.Database.Set(index.KeyDerivation(block), index.ValueDerivation(block), database.Sync)
			if err != nil {
				return &Block{}, err
			}
		}
		if err != nil {
			// return any other errors
			return &Block{}, err
		}
		// append to the value
		closer.Close()
		err := database.Database.Set(index.KeyDerivation(block), val.append(index.ValueDerivation(block)), database.Sync)
		if err != nil {
			return &Block{}, err
		}
	}

	return block, nil
}

func (block *Block) HashAndSign(privateKey ed25519.PrivateKey) (*Block, error) {
		hash, err := calculateBlockHash(block)
		if err != nil {
			return &Block{}, err
		}

		signature := ed25519.Sign(privateKey, hash[:])

    block.BlockHash = hex.EncodeToString(hash[:])
    block.Signature = hex.EncodeToString(signature)
    return block, nil
}

func genesis() (ed25519.PublicKey, ed25519.PrivateKey, *Block, error) {
	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		panic(err)
	}

	block := Block{
		BlockType: "genesis",
		Account: hex.EncodeToString(publicKey),
		Amount: 0,
		Balance: 9223372036854775807,
	}

	signedBlock, err := block.HashAndSign(privateKey)
	if err != nil {
		return publicKey, privateKey, &Block{}, err
	}

	savedBlock, err := signedBlock.Save()
	if err != nil {
		return publicKey, privateKey, &Block{}, err
	}
	return publicKey, privateKey, savedBlock, nil
}

func ValidateGenesisBlock(block *Block) (bool) {
	value, closer, err := db.Get("genesis_block")
	closer.Close()
	if err != database.NotFound {
		return false
	}

	if !validateHash(block) {
		return false
	}

	if !validateSignature(block) {
		return false
	}

	if block.Amount != 0 {
		return false
	}

	if block.PreviousHash != "" {
		return false
	}

	return true
}

func validateSignature(block *Block) (bool) {
	pubkeyBytes, err := hex.DecodeString(block.Account)
	if err != nil {
		return false
	}
	hashBytes, err := hex.DecodeString(block.BlockHash)
	if err != nil {
		return false
	}
	signatureBytes, err := hex.DecodeString(block.Signature)
	if err != nil {
		return false
	}

	if !ed25519.Verify(ed25519.PublicKey(pubkeyBytes), hashBytes, signatureBytes) {
		return false 
	}

	return true
}

func validateHash(block *Block) (bool) {
	calculatedHash, err := calculateBlockHash(block)
	if err != nil || hex.EncodeToString(calculatedHash[:]) != block.BlockHash {
		return false
	}
	return true
}

func AccountCreate() (ed25519.PublicKey, ed25519.PrivateKey, *Block, error) {
	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		panic(err)
	}
	block := Block{
		BlockType: "account_create",
		Account: hex.EncodeToString(publicKey),
		Amount: 0,
		Balance: 0,

	}

	signedBlock, err := block.HashAndSign(privateKey)
	if err != nil {
		return publicKey, privateKey, &Block{}, err
	}

	savedBlock, err := signedBlock.Save()
	if err != nil {
		return publicKey, privateKey, &Block{}, err
	}
	return publicKey, privateKey, savedBlock, nil
}

func ValidateAccountCreateBlock(block *Block) (bool) {
	if !validateHash(block) {
		return false
	}

	if !validateSignature(block) {
		return false
	}

	if block.Amount != 0 {
		return false
	}

	if block.Balance != 0 {
		return false
	}

	if block.PreviousHash != "" {
		return false
	}

	return true
}

func receive(fromBlock *Block, previousBlock *Block, publicKey ed25519.PublicKey, privateKey ed25519.PrivateKey) (*Block, error) {
	block := Block{
		BlockType: "receive",
		Account: hex.EncodeToString(publicKey),
		Amount: fromBlock.Amount,
		Balance: previousBlock.Balance + fromBlock.Amount,
		PreviousHash: previousBlock.BlockHash,
		LinkedHash: fromBlock.BlockHash,
	}

	signedBlock, err := block.HashAndSign(privateKey)
	if err != nil {
		return &Block{}, err
	}

	savedBlock, err := signedBlock.Save()
	if err != nil {
		return &Block{}, err
	}
	return savedBlock, nil
}

func ValidateReceiveBlock(block *Block) (bool) {
	if !validateHash(block) {
		return false
	}

	if !validateSignature(block) {
		return false
	}

	// ensure only one of these exists
	value, closer, err := db.Get(block.Account + ":" + block.LinkedHash)
	closer.Close()
	if err != database.NotFound {
		return false
	}

	if block.Amount != block.LinkedBlock.Amount {
		return false
	}

	if block.Balance != (block.Amount + block.PreviousBlock.Balance) {
		return false
	}

	return true
}

func payout(receivers []ed25519.PublicKey, previousBlock *Block, amount uint64, publicKey ed25519.PublicKey, privateKey ed25519.PrivateKey) (*Block, error) {
	receiver_ids := make([]string, len(receivers))
	for i, v := range receivers {
		receiver_ids[i] = hex.EncodeToString(v)
	}

	block := Block{
		BlockType: "payout",
		Account: hex.EncodeToString(publicKey),
		Amount: amount,
		Balance: previousBlock.Balance - (amount * uint64(len(receivers))),
		PreviousHash: previousBlock.BlockHash,
		Receivers: receiver_ids,
	}

	signedBlock, err := block.HashAndSign(privateKey)
	if err != nil {
		return &Block{}, err
	}

	savedBlock, err := signedBlock.Save()
	if err != nil {
		return &Block{}, err
	}
	return savedBlock, nil
}

func ValidatePayoutBlock(block *Block) (bool) {
	if !validateHash(block) {
		return false
	}

	if !validateSignature(block) {
		return false
	}

	if tx == nil {
		tx = database.Database
	}

	if block.Amount <= 0  {
		return false
	}

	if block.Balance != (block.PreviousBlock.Balance - (uint64(len(block.Receivers)) * block.Amount)) {
		return false
	}

	return true
}

func InitChain() (error) {
	gpubkey, gpkey, genesisBlock, err := genesis()
	if err != nil {
		return err
	}

	if !ValidateGenesisBlock(genesisBlock) {
		return errors.New("fail- genesis invalid")
	}

	pubkey, pkey, createBlock, err := AccountCreate()
	if err != nil {
		return err
	}

	if !ValidateAccountCreateBlock(createBlock) {
		return errors.New("fail- account_create invalid")
	}

	payoutBlock, err := payout([]ed25519.PublicKey{pubkey}, genesisBlock, uint64(9223372036854775807), gpubkey, gpkey)
	if err != nil {
		return err
	}

	if !ValidatePayoutBlock(payoutBlock) {
		return errors.New("fail- payout invalid")
	}

	receiveBlock, err := receive(payoutBlock, createBlock, pubkey, pkey)
	if err != nil {
		return err
	}

	if !ValidateReceiveBlock(receiveBlock) {
		return errors.New("fail- receive invalid")
	}

	return nil
}
