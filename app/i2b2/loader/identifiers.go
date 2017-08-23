package loader

import (
	"errors"
	"gopkg.in/dedis/onet.v1/log"
	"regexp"
	"strconv"
)

/*
   Defines and manipulates the identifiers that are meant to be encrypted by Unlynx for the purpose of answering queries.

   Convention: 64 bits integers.

   Genomic variant:
   	1 bit (2): flag genomic variant (1)
   	5 bits (32): chromosome id
   	28 bits (268'435'456): start position of the mutation (1-based coordinate system)
   	3 bits (8): length in # bases of the reference allele
   	12 bits (4'096): reference allele (6 bases)
   	3 bits (8): length in # bases of the alternative allele (mutated)
   	12 bits (4'096): alternative allele (6 bases)
*/

// IDBitSize size in bits of the identifier.
const IDBitSize = 64

// Breakdown of the size in bits.
const (
	TypeFlagBitSize          = 1
	ChrBitSize               = 5
	PosBitSize               = 28
	AllelesBaseLengthBitSize = 3
	AllelesBitSize           = 12
)

// Regex expressions
const (
	/*
	 Valid values for the chromosome id:
	 Number from 1 to 23 inclusive, or
	 X, Y, or M

	 -> Range from 1 to 26 inclusive, 2^5 = 32 ==> 5 bits storage
	*/
	ChromosomeIDRegex = "^[XYM]|[1-9]|(1[0-9])|(2[0-3])$"

	/*
	 Valid values for the alleles.
	 Either nothing ("-") or a certain number of bases ({A, T, G, C}).
	 Each [A, T, G, C] base is encoded on 2 bits.

	 The maximum number of bases supported is  6 -> 12bits and an additional 3 bits are used to encode the length.
	*/
	AllelesRegex = "^([ATCG]{1,6}|-)$"
)

// Mapping to encode non-numeric chromosome ids.
const (
	ChromosomeXintID = int64(24)
	ChromosomeYintID = int64(25)
	ChromosomeMintID = int64(26)
)

// TypeFlagGenomicVariant encodes the type of id.
const TypeFlagGenomicVariant = int64(0)

/*
 Possible range of positions values (position in 1-based coordinate system, minimum is 1).
 Result is encoded into bits so the range is rounded to the nearest power of 2.
 According to https://en.wikipedia.org/wiki/Human_genome#Molecular_organization_and_gene_content,
 the chromosome with the higher number of base is #1 with 248'956'422 bases. 2^28 = 268'435'456.
 ==> 28 bits storage
*/
const (
	PositionMin = int64(1)
	PositionMax = int64(1) << PosBitSize
)

// AlleleMaping encodes alleles.
func AlleleMaping(allele string) (int64, error) {
	switch allele {
	case "A":
		return int64(0), nil
	case "T":
		return int64(1), nil
	case "G":
		return int64(2), nil
	case "C":
		return int64(3), nil
	default:
		return int64(-1), errors.New("Wrong allele format")
	}
}

func checkRegex(input, expression, errorMessage string) error {
	var aux = regexp.MustCompile(expression)

	correct := aux.MatchString(input)

	if !correct {
		log.Error(errorMessage)
		return errors.New(errorMessage)
	}

	return nil
}

// GetVariantID encodes a genomic variant ID to be encrypted, according to the specifications.
func GetVariantID(chromosomeID string, startPosition int64, refAlleles, altAlleles string) (int64, error) {

	// validate input
	if checkRegex(chromosomeID, ChromosomeIDRegex, "Invalid Chromosome ID") != nil ||
		checkRegex(refAlleles, AllelesRegex, "Invalid reference allele") != nil || checkRegex(altAlleles, AllelesRegex, "Invalid alternate allele") != nil ||
		startPosition < PositionMin || startPosition > PositionMax || TypeFlagBitSize+ChrBitSize+PosBitSize+2*(AllelesBaseLengthBitSize+AllelesBitSize) != IDBitSize {

		return int64(-1), errors.New("Invalid input: chr=" + chromosomeID + ", pos=" + strconv.FormatInt(startPosition, 10) + ", ref=" + refAlleles + ", alt=" + altAlleles)
	}

	// interpret chromosome id (content validated by regex)
	chromosomeIntID, err := strconv.ParseInt(chromosomeID, 10, 64)

	if err != nil {
		switch chromosomeID {
		case "X":
			chromosomeIntID = ChromosomeXintID
			break
		case "Y":
			chromosomeIntID = ChromosomeYintID
			break
		case "M":
			chromosomeIntID = ChromosomeMintID
			break
		default:
			log.Fatal("Invalid Chromosome ID")
			return int64(-1), err
		}
	}

	// alleles
	if refAlleles == "-" {
		refAlleles = ""
	}

	if altAlleles == "-" {
		altAlleles = ""
	}

	refAllelesBaseLength := int64(len(refAlleles))
	altAllelesBaseLength := int64(len(altAlleles))

	// generate the variant
	id := int64(0)
	id = PushBitsFromRight(id, TypeFlagBitSize, TypeFlagGenomicVariant)
	id = PushBitsFromRight(id, ChrBitSize, chromosomeIntID)
	id = PushBitsFromRight(id, PosBitSize, startPosition)
	id = PushBitsFromRight(id, AllelesBaseLengthBitSize, refAllelesBaseLength)
	id = PushBitsFromRight(id, AllelesBitSize, EncodeAlleles(refAlleles))
	id = PushBitsFromRight(id, AllelesBaseLengthBitSize, altAllelesBaseLength)
	id = PushBitsFromRight(id, AllelesBitSize, EncodeAlleles(altAlleles))

	return id, nil
}

// EncodeAlleles encodes a string containing alleles.
func EncodeAlleles(alleles string) int64 {
	encodedAlleles := int64(0)

	for i := 0; i < len(alleles); i++ {
		mapV, err := AlleleMaping(alleles[i : i+1])
		if err != nil {
			log.Fatal(err)
		}

		encodedAlleles = PushBitsFromRight(encodedAlleles, 2, mapV)

	}

	//padding
	encodedAlleles = PushBitsFromRight(encodedAlleles, AllelesBitSize-len(alleles)*2, int64(0))

	return encodedAlleles
}

// PushBitsFromRight takes the nbBits rightmost bits of bitsToPush, and push them to the right of origBits.
func PushBitsFromRight(origBits int64, nbBits int, bitsToPush int64) int64 {
	newBits := origBits << uint(nbBits)

	// generate mask
	mask := GetMask(nbBits)

	// get final value
	newBits |= (mask & bitsToPush)
	return newBits
}

// GetMask generates a bit mask (support pushing bits)
func GetMask(nbBits int) int64 {
	mask := int64(0)

	for i := 0; i < nbBits; i++ {
		mask <<= 1
		mask |= int64(1)
	}

	return mask
}
