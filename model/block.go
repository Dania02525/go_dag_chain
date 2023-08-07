package model

import (
	"errors"
	"go-metering/database"
	"gorm.io/gorm"
	"github.com/lib/pq"
	"encoding/json"
	"crypto/sha256"
	"crypto/ed25519"
	"encoding/hex"
)

type Block struct {
    BlockHash     string  				`gorm:"primaryKey;size:64;not null" json:"block_hash"`
    BlockType     string  				`gorm:"size:64;not null;index;uniqueIndex:idx_blocks_one_genesis,where: block_type = 'genesis'" json:"block_type"`
    PreviousHash  string  				`gorm:"size:64;uniqueIndex;default:null" json:"previous_hash"`
    LinkedHash    string  				`gorm:"size:64;index;uniqueIndex:idx_blocks_account_linkedhash;default:null" json:"linked_hash"`
    Account       string  				`gorm:"size:64;not null;index;uniqueIndex:idx_blocks_account_linkedhash" json:"account_id"`
    Receivers     pq.StringArray  `gorm:"type:varchar(64)[];index:,type:gin;default:null" json:"receiver_ids"`
    Amount        uint64  				`json:"amount;default:0"`
    Balance       uint64  				`json:"balance;default:0"`
    Signature     string  				`gorm:"not null" json:"signature"`
    Timestamp     uint32  				`gorm:"autoCreateTime" json:"timestamp"`
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

func (block *Block) Save(tx *gorm.DB) (*Block, error) {
	if tx == nil {
		tx = database.Database
	}
	err := tx.Create(&block).Error
	if err != nil {
		return &Block{}, err
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

func genesis(tx *gorm.DB) (ed25519.PublicKey, ed25519.PrivateKey, *Block, error) {
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

	savedBlock, err := signedBlock.Save(tx)
	if err != nil {
		return publicKey, privateKey, &Block{}, err
	}
	return publicKey, privateKey, savedBlock, nil
}

func ValidateGenesisBlock(block *Block) (bool) {
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

func AccountCreate(tx *gorm.DB) (ed25519.PublicKey, ed25519.PrivateKey, *Block, error) {
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

	savedBlock, err := signedBlock.Save(tx)
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

func receive(tx *gorm.DB, fromBlock *Block, previousBlock *Block, publicKey ed25519.PublicKey, privateKey ed25519.PrivateKey) (*Block, error) {
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

	savedBlock, err := signedBlock.Save(tx)
	if err != nil {
		return &Block{}, err
	}
	return savedBlock, nil
}

func ValidateReceiveBlock(block *Block, tx *gorm.DB) (bool) {
	if !validateHash(block) {
		return false
	}

	if !validateSignature(block) {
		return false
	}

	if tx == nil {
		tx = database.Database
	}

	var previousBlock Block
	var linkedBlock Block
	err := tx.Take(&previousBlock, "block_hash = ?", block.PreviousHash).Error
	if err != nil {
		return false
	}
	err = tx.Take(&linkedBlock, "block_hash = ?", block.LinkedHash).Error
	if err != nil {
		return false
	}

	if block.Amount != linkedBlock.Amount {
		return false
	}

	if block.Balance != (block.Amount + previousBlock.Balance) {
		return false
	}

	return true
}

func payout(tx *gorm.DB, receivers []ed25519.PublicKey, previousBlock *Block, amount uint64, publicKey ed25519.PublicKey, privateKey ed25519.PrivateKey) (*Block, error) {
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

	savedBlock, err := signedBlock.Save(tx)
	if err != nil {
		return &Block{}, err
	}
	return savedBlock, nil
}

func ValidatePayoutBlock(block *Block, tx *gorm.DB) (bool) {
	if !validateHash(block) {
		return false
	}

	if !validateSignature(block) {
		return false
	}

	if tx == nil {
		tx = database.Database
	}

	var previousBlock Block
	err := tx.Take(&previousBlock, "block_hash = ?", block.PreviousHash).Error
	if err != nil {
		return false
	}

	if block.Amount <= 0  {
		return false
	}

	if block.Balance != (previousBlock.Balance - (uint64(len(block.Receivers)) * block.Amount)) {
		return false
	}

	return true
}

func InitChain() (error) {
	return (database.Database.Transaction(func(tx *gorm.DB) error {
		gpubkey, gpkey, genesisBlock, err := genesis(tx)
		if err != nil {
			return err
		}

		if !ValidateGenesisBlock(genesisBlock) {
			return errors.New("fail- genesis invalid")
		}

		pubkey, pkey, createBlock, err := AccountCreate(tx)
		if err != nil {
			return err
		}

		if !ValidateAccountCreateBlock(createBlock) {
			return errors.New("fail- account_create invalid")
		}

		payoutBlock, err := payout(tx, []ed25519.PublicKey{pubkey}, genesisBlock, uint64(9223372036854775807), gpubkey, gpkey)
		if err != nil {
			return err
		}

		if !ValidatePayoutBlock(payoutBlock, tx) {
			return errors.New("fail- payout invalid")
		}

		receiveBlock, err := receive(tx, payoutBlock, createBlock, pubkey, pkey)
		if err != nil {
			return err
		}

		if !ValidateReceiveBlock(receiveBlock, tx) {
			return errors.New("fail- receive invalid")
		}

		return nil
	}))
}
