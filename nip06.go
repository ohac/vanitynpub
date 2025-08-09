package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha512"
	"encoding/hex"
	"flag"
	"fmt"
	"hash"
	"math/big"
	"sync"

	_ "github.com/nbd-wtf/go-nostr"
	"github.com/nbd-wtf/go-nostr/nip06"
	"github.com/nbd-wtf/go-nostr/nip19"
	"github.com/tyler-smith/go-bip32"
	"github.com/tyler-smith/go-bip39"

	btcutil "github.com/FactomProject/btcutilecc"
	_ "github.com/btcsuite/btcd/btcec/v2"
	_ "github.com/btcsuite/btcd/btcec/v2/schnorr"
	secp "github.com/decred/dcrd/dcrec/secp256k1/v4"
)

var (
	curve = btcutil.Secp256k1()
)

func GenerateSeedWords() (string, error) {
	entropy, err := bip39.NewEntropy(256)
	if err != nil {
		return "", err
	}

	words, err := bip39.NewMnemonic(entropy)
	if err != nil {
		return "", err
	}

	return words, nil
}

func SeedFromWords(words string) []byte {
	return bip39.NewSeed(words, "")
}

func compressPublicKey(x *big.Int, y *big.Int) *bytes.Buffer {
	var key bytes.Buffer
	key.WriteByte(byte(0x2) + byte(y.Bit(0)))
	xBytes := x.Bytes()
	for i := 0; i < (bip32.PublicKeyCompressedLength - 1 - len(xBytes)); i++ {
		key.WriteByte(0x0)
	}
	key.Write(xBytes)
	return &key
}

func keyToBytes(key []byte) []byte {
	var data []byte
	x, y := curve.ScalarBaseMult(key)
	bb := compressPublicKey(x, y)
	childIndexBytes := make([]byte, 4)
	bb.Write(childIndexBytes)
	data = bb.Bytes()
	return data
}

func keyToBigInt(key []byte) big.Int {
	var key2Int big.Int
	key2Int.SetBytes(key)
	return key2Int
}

func newChildKey(data []byte, key1Int, key2Int *big.Int,
	key *bip32.Key, childIdx uint32, hmac hash.Hash, n *big.Int) []byte {
	data[33] = byte(childIdx >> 24)
	data[34] = byte(childIdx >> 16)
	data[35] = byte(childIdx >> 8)
	data[36] = byte(childIdx)
	hmac.Write(data)
	intermediary := hmac.Sum(nil)
	var key1 []byte
	key1 = intermediary[:32]
	key1Int.SetBytes(key1)
	key1Int.Add(key1Int, key2Int)
	key1Int.Mod(key1Int, n)
	b := key1Int.Bytes()
	return b
}

func mining(seed []byte, thread uint32, lenckeymax int,
	filter1, filter2 byte, target string, usefilter bool) error {
	key, err := bip32.NewMasterKey(seed)
	if err != nil {
		return err
	}

	derivationPath := []uint32{
		bip32.FirstHardenedChild + 44,
		bip32.FirstHardenedChild + 1237,
		bip32.FirstHardenedChild + 0,
		thread,
	}

	next := key
	for _, idx := range derivationPath {
		var err error
		if next, err = next.NewChildKey(idx); err != nil {
			return err
		}
	}

	data := keyToBytes(next.Key)
	var key1Int big.Int
	key2Int := keyToBigInt(next.Key)
	var chainCode []byte
	chainCode = next.ChainCode
	hmac := hmac.New(sha512.New, chainCode)
	max := uint32(4)
	max = bip32.FirstHardenedChild
	n := curve.Params().N
	for i := uint32(0); i < max; i++ {
		var ckey []byte
		hmac.Reset()
		ckey = newChildKey(data, &key1Int, &key2Int, next, i, hmac, n)
		lenckey := len(ckey)
		if usefilter && lenckey < lenckeymax {
			continue
		}
		privKey := secp.PrivKeyFromBytes(ckey)
		pk := privKey.PubKey()
		schn := pk.SerializeCompressed()
		schn = schn[1:]

		if !usefilter || (schn[0] == filter1 && schn[1] == filter2) {
			npub := hex.EncodeToString(schn)
			npubs, _ := nip19.EncodePublicKey(npub)
			if npubs[:9] == target {
				fmt.Println(thread, i, npubs, npub[:4], schn[:4], lenckey)
			}
		}
		if i&0x3fffff == 0 && thread == 0 {
			fmt.Println(thread, i)
		}
	}

	return nil
}

func main() {
	testvectors := "leader monkey parrot ring guide accident before fence cannon height naive bean"

	wordsp := flag.String("s", testvectors, "words")

	// default: npub10hac
	lenckeymaxp := flag.Int("L", 32, "30 or 31 or 32")
	filter1p := flag.Int("f", 125, "filter1")
	filter2p := flag.Int("g", 251, "filter2")
	targetp := flag.String("t", "npub10hac", "target string")
	usefilter := flag.Bool("u", false, "use lenckeymax, filter1 and 2")

	coresp := flag.Int("c", 6, "cores")
	verbose := flag.Bool("v", false, "verbose")
	genseed := flag.Bool("S", false, "generate seed words")

	flag.Parse()

	words := *wordsp

	if *genseed {
		words, _ = nip06.GenerateSeedWords()
	}
	if *genseed || *verbose {
		fmt.Println(words)
	}
	seed := nip06.SeedFromWords(words)
	offset := uint32(7)

	lenckeymax := *lenckeymaxp
	filter1 := byte(*filter1p)
	filter2 := byte(*filter2p)

	cores := *coresp

	var wg sync.WaitGroup
	wg.Add(cores)
	for i := 0; i < cores; i++ {
		go mining(seed, offset+1+uint32(i), lenckeymax, filter1, filter2,
			*targetp, *usefilter)
	}
	wg.Wait()
}
