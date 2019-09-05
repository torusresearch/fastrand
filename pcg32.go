package fastrand

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"math/big"

	"github.com/torusresearch/torus-common/secp256k1"
)

const inc = uint64(0xda3e39cb94b95bdb)

var randomBytes, _ = GenerateRandomBytes(8)
var state = binary.BigEndian.Uint64(randomBytes)

func GetState() uint64 {
	return state
}

func SetState(newState uint64) {
	state = newState
}

// GenerateRandomBytes returns securely generated random bytes.
func GenerateRandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}

	return b, nil
}

// PCG32 returns a random unsigned 32 bit integer using PCG.
func PCG32() uint32 {
	oldstate := uint64(state)
	state = (oldstate*uint64(0x5851f42d4c957f2d) + inc)
	xorshifted := uint32(((oldstate >> 18) ^ oldstate) >> 27)
	rot := uint32(oldstate >> 59)
	return (xorshifted >> rot) | (xorshifted << (-rot & 31))
}

// PCG32Bounded returns a random unsigned 32 bit integer in the interval [0, bound) using PCG.
func PCG32Bounded(bound uint32) uint32 {
	bound64 := uint64(bound)
	random32bits := uint64(PCG32())
	multiresult := random32bits * bound64
	leftover := uint32(multiresult)
	if leftover < bound {
		threshold := -bound % bound
		for leftover < threshold {
			random32bits = uint64(PCG32())
			multiresult = random32bits * bound64
			leftover = uint32(multiresult)
		}
	}

	return uint32(multiresult >> 32)
}

// RandomBigInt returns a random big integer in the interval [0, secp256k1.GeneratorOrder)
func RandomBigInt() *big.Int {
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, []uint32{PCG32(), PCG32(), PCG32(), PCG32(), PCG32(), PCG32(), PCG32(), PCG32()})

	randomBigInt := new(big.Int)
	randomBigInt.SetBytes(buf.Bytes())
	// return randomBigInt

	if randomBigInt.Cmp(secp256k1.GeneratorOrder) == -1 {
		return randomBigInt
	}
	return RandomBigInt()
}

// CryptoRandomBigInt returns a random big integer in the interval [0, secp256k1.GeneratorOrder)
func CryptoRandomBigInt() *big.Int {
	randomInt, _ := rand.Int(rand.Reader, secp256k1.GeneratorOrder)
	return randomInt
}
