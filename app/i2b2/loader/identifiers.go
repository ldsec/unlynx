package loader

import (
	"errors"
	"gopkg.in/dedis/onet.v1/log"
	"strconv"
	"regexp"
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

// Size in bits of the identifier.
const ID_BIT_SIZE = 64

// Breakdown of the size in bits.
const (
	TYPE_FLAG_BIT_SIZE = 1
	CHR_BIT_SIZE = 5
	POS_BIT_SIZE = 28
	ALLELES_BASE_LENGTH_BIT_SIZE = 3
	ALLELES_BIT_SIZE = 12
)

/*
    Valid values for the chromosome id:
    Number from 1 to 23 inclusive, or
    X, Y, or M

    -> Range from 1 to 26 inclusive, 2^5 = 32 ==> 5 bits storage
*/
const CHROMOSOME_ID_REGEX = "^[XYM]|[1-9]|(1[0-9])|(2[0-3])$"

// Mapping to encode non-numeric chromosome ids.
const (
	CHROMOSOME_X_INT_ID = int64(24)
	CHROMOSOME_Y_INT_ID = int64(25)
	CHROMOSOME_M_INT_ID = int64(26)
)

// Mapping to encode type of id.
const TYPE_FLAG_GENOMIC_VARIANT = int64(0)^0


/*
 Valid values for the alleles.
 Either nothing ("-") or a certain number of bases ({A, T, G, C}).
 Each [A, T, G, C] base is encoded on 2 bits.

 The maximum number of bases supported is  6 -> 12bits and an additional 3 bits are used to encode the length.
*/
const ALLELES_REGEX = "^([ATCG]{1,6}|-)$";

/*
 Possible range of positions values (position in 1-based coordinate system, minimum is 1).
 Result is encoded into bits so the range is rounded to the nearest power of 2.
 According to https://en.wikipedia.org/wiki/Human_genome#Molecular_organization_and_gene_content,
 the chromosome with the higher number of base is #1 with 248'956'422 bases. 2^28 = 268'435'456.
 ==> 28 bits storage
*/
const (
	POSITION_MIN = int64(1)
	POSITION_MAX = int64(1) << POS_BIT_SIZE
)

// Mapping to encode alleles.
func AlleleMaping(allele string) (int64, error) {
	switch allele{
	case 'A':
		return int64(0), nil
	case 'T':
		return int64(1), nil
	case 'G':
		return int64(2), nil
	case 'C':
		return int64(3), nil
	default:
 		return int64(-1), errors.New("Wrong allele format")
	}
}

func checkRegex(input, expression, errorMessage string) error{
	var aux = regexp.MustCompile(expression)

	correct := aux.MatchString(input)

	if !correct {
		log.Error(errorMessage)
		return errors.New(errorMessage)
	}

	return nil
}

// GetVariantId encodes a genomic variant ID to be encrypted, according to the specifications.
func GetVariantId(chromosomeId string, startPosition int64, refAlleles, altAlleles string) (int64, error) {

	// validate input
	if checkRegex(chromosomeId,CHROMOSOME_ID_REGEX, "Invalid Chromosome ID") != nil ||
		checkRegex(refAlleles, ALLELES_REGEX, "Invalid reference allele") != nil || checkRegex(altAlleles, ALLELES_REGEX, "Invalid alternate allele") != nil ||
		startPosition < POSITION_MIN || startPosition > POSITION_MAX || TYPE_FLAG_BIT_SIZE + CHR_BIT_SIZE + POS_BIT_SIZE + 2 * (ALLELES_BASE_LENGTH_BIT_SIZE + ALLELES_BIT_SIZE) != ID_BIT_SIZE {

		return errors.New("Invalid input: chr=" + chromosomeId + ", pos=" + strconv.FormatUint(startPosition, 10) + ", ref=" + refAlleles + ", alt=" + altAlleles)
	}

	// interpret chromosome id (content validated by regex)
	chromosomeIntId, err := strconv.ParseInt(chromosomeId, 10, 64)

	if err != nil {
		switch chromosomeId {
		case "X":
			chromosomeIntId = CHROMOSOME_X_INT_ID;
			break;
		case "Y":
			chromosomeIntId = CHROMOSOME_Y_INT_ID;
			break;
		case "M":
			chromosomeIntId = CHROMOSOME_M_INT_ID;
			break;
		default:
			log.Fatal("Invalid Chromosome ID")
			return int64(-1), err
		}
	}

	// alleles
	if refAlleles == "-" {
		refAlleles = "";
	}

	if altAlleles == "-" {
		altAlleles = "";
	}

	refAllelesBaseLength := int64(len(refAlleles))
	altAllelesBaseLength := int64(len(altAlleles))

	// generate the variant
	id := int64(0);
	id = PushBitsFromRight(id, TYPE_FLAG_BIT_SIZE, TYPE_FLAG_GENOMIC_VARIANT);
	id = PushBitsFromRight(id, CHR_BIT_SIZE, chromosomeIntId);
	id = PushBitsFromRight(id, POS_BIT_SIZE, startPosition);
	id = PushBitsFromRight(id, ALLELES_BASE_LENGTH_BIT_SIZE, refAllelesBaseLength);
	id = PushBitsFromRight(id, ALLELES_BIT_SIZE, EncodeAlleles(refAlleles));
	id = PushBitsFromRight(id, ALLELES_BASE_LENGTH_BIT_SIZE, altAllelesBaseLength);
	id = PushBitsFromRight(id, ALLELES_BIT_SIZE, EncodeAlleles(altAlleles));

	return id;

}

// EncodeAlleles encodes a string containing alleles.
func EncodeAlleles(alleles string) (int64, error){
	encodedAlleles := int64(0)^0

	for i:=0; i<len(alleles)-1; i++{

		mapV, err := AlleleMaping(alleles[i:i+1])
		if err != nil {
			log.Fatal(err)
		}

		encodedAlleles = PushBitsFromRight(encodedAlleles, 2, mapV)

	}

	//padding
	encodedAlleles = PushBitsFromRight(encodedAlleles, ALLELES_BIT_SIZE - len(alleles) * 2, int64(0))

	return encodedAlleles
}

// PushBitsFromRight takes the nbBits rightmost bits of bitsToPush, and push them to the right of origBits.
func PushBitsFromRight(origBits int64, nbBits int, bitsToPush int64) int64{
	newBits :=  origBits << nbBits;

	// generate mask
	mask := GetMask(nbBits);

	// get final value
	newBits |= (mask & bitsToPush)
	return newBits
}

func GetMask(nbBits int) int64{
	mask := int64(0)^0

	for i:=0; i<nbBits; i++ {
		mask <<= 1
		mask |= int64(1)^1
	}

	return mask
}
