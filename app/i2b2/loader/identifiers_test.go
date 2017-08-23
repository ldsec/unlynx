package loader_test

import (
	"testing"
	"github.com/lca1/unlynx/app/i2b2/loader"
	"github.com/stretchr/testify/assert"
)

func TestAlleleMaping(t *testing.T) {
	res, err := loader.AlleleMaping("A")
	assert.Equal(t,res,int64(0))
	assert.Nil(t,err)

	res, err = loader.AlleleMaping("T")
	assert.Equal(t,res,int64(1))
	assert.Nil(t,err)

	res, err = loader.AlleleMaping("G")
	assert.Equal(t,res,int64(2))
	assert.Nil(t,err)

	res, err = loader.AlleleMaping("C")
	assert.Equal(t,res,int64(3))
	assert.Nil(t,err)

	res, err = loader.AlleleMaping("")
	assert.Equal(t,res,int64(-1))
	assert.NotNil(t,err)

	res, err = loader.AlleleMaping("test")
	assert.Equal(t,res,int64(-1))
	assert.NotNil(t,err)
}

func TestGetMask(t *testing.T) {
	assert.Equal(t, loader.GetMask(1), int64(1))
	assert.Equal(t, loader.GetMask(4), int64(15))
	assert.Equal(t, loader.GetMask(10), int64(1023))
}

func TestPushBitsFromRight(t *testing.T) {
	assert.Equal(t,loader.PushBitsFromRight(int64(0),2,int64(1)),int64(1))
	assert.Equal(t,loader.PushBitsFromRight(int64(0),2,int64(7)),int64(3))
	assert.Equal(t,loader.PushBitsFromRight(int64(0),3,int64(7)),int64(7))
	assert.Equal(t,loader.PushBitsFromRight(int64(0),4,int64(7)),int64(7))
}

func TestEncodeAlleles(t *testing.T) {
	assert.Equal(t,loader.EncodeAlleles("A"), int64(0))
	assert.Equal(t,loader.EncodeAlleles("T"), int64(1024))
	assert.Equal(t,loader.EncodeAlleles("G"), int64(2048))
	assert.Equal(t,loader.EncodeAlleles("C"), int64(3072))

	assert.Equal(t,loader.EncodeAlleles("AA"), int64(0))
	assert.Equal(t,loader.EncodeAlleles("ATCG"), int64(480))
	assert.Equal(t,loader.EncodeAlleles("GGTTCA"), int64(2652))
	assert.Equal(t,loader.EncodeAlleles("TGACTA"), int64(1588))

	assert.Equal(t,loader.EncodeAlleles("TGACTAT"), int64(0)) //strange!!
}

func TestGetVariantID(t *testing.T) {
	res, err :=loader.GetVariantID("1",int64(6),"AC","ATTT")
	assert.Nil(t,err)
	assert.Equal(t,res,int64(288230382887780688))

	res, err =loader.GetVariantID("100",int64(2300),"C","T")
	assert.Nil(t,err)
	assert.Equal(t,res,int64(1152923974447928320))

	res, err =loader.GetVariantID("1",int64(999999),"TAAAC","G")
	assert.Nil(t,err)
	assert.Equal(t,res,int64(289304117607012352))

}
