package aptos

import "fmt"

type TypeTagType uint64

const (
	TypeTag_Bool           TypeTagType = 0
	TypeTag_U8             TypeTagType = 1
	TypeTag_U64            TypeTagType = 2
	TypeTag_U128           TypeTagType = 3
	TypeTag_AccountAddress TypeTagType = 4
	TypeTag_Signer         TypeTagType = 5
	TypeTag_Vector         TypeTagType = 6
	TypeTag_Struct         TypeTagType = 7
	TypeTag_U16            TypeTagType = 8
	TypeTag_U32            TypeTagType = 9
	TypeTag_U256           TypeTagType = 10
)

type TypeTagImpl interface {
	BCSStruct
	GetType() TypeTagType
}

type TypeTag struct {
	Value TypeTagImpl
}

func (tt *TypeTag) MarshalBCS(bcs *Serializer) {
	bcs.Uleb128(uint64(tt.Value.GetType()))
	tt.Value.MarshalBCS(bcs)

}
func (tt *TypeTag) UnmarshalBCS(bcs *Deserializer) {
	variant := bcs.Uleb128()
	switch TypeTagType(variant) {
	case TypeTag_Bool:
		xt := &BoolTag{}
		xt.UnmarshalBCS(bcs)
		tt.Value = xt
	default:
		bcs.SetError(fmt.Errorf("unknown TypeTag enum %d", variant))
	}
}

func NewTypeTag(v any) *TypeTag {
	switch tv := v.(type) {
	case uint8:
		return &TypeTag{
			Value: &U8Tag{Value: tv},
		}
	}
	return nil
}

type BoolTag struct {
	Value bool
}

func (xt *BoolTag) GetType() TypeTagType {
	return TypeTag_Bool
}

func (xt *BoolTag) MarshalBCS(bcs *Serializer) {
	bcs.Bool(xt.Value)

}
func (xt *BoolTag) UnmarshalBCS(bcs *Deserializer) {
	xt.Value = bcs.Bool()
}

type U8Tag struct {
	Value uint8
}

func (xt *U8Tag) GetType() TypeTagType {
	return TypeTag_U8
}

func (xt *U8Tag) MarshalBCS(bcs *Serializer) {
	bcs.U8(xt.Value)

}
func (xt *U8Tag) UnmarshalBCS(bcs *Deserializer) {
	xt.Value = bcs.U8()
}

type U16Tag struct {
	Value uint16
}

func (xt *U16Tag) GetType() TypeTagType {
	return TypeTag_U16
}

func (xt *U16Tag) MarshalBCS(bcs *Serializer) {
	bcs.U16(xt.Value)

}
func (xt *U16Tag) UnmarshalBCS(bcs *Deserializer) {
	xt.Value = bcs.U16()
}

type U32Tag struct {
	Value uint32
}

func (xt *U32Tag) GetType() TypeTagType {
	return TypeTag_U32
}

func (xt *U32Tag) MarshalBCS(bcs *Serializer) {
	bcs.U32(xt.Value)

}
func (xt *U32Tag) UnmarshalBCS(bcs *Deserializer) {
	xt.Value = bcs.U32()
}

type U64Tag struct {
	Value uint64
}

func (xt *U64Tag) GetType() TypeTagType {
	return TypeTag_U64
}

func (xt *U64Tag) MarshalBCS(bcs *Serializer) {
	bcs.U64(xt.Value)

}
func (xt *U64Tag) UnmarshalBCS(bcs *Deserializer) {
	xt.Value = bcs.U64()
}

type AccountAddressTag struct {
	Value AccountAddress
}

func (xt *AccountAddressTag) GetType() TypeTagType {
	return TypeTag_AccountAddress
}

func (xt *AccountAddressTag) MarshalBCS(bcs *Serializer) {
	xt.Value.MarshalBCS(bcs)

}
func (xt *AccountAddressTag) UnmarshalBCS(bcs *Deserializer) {
	xt.Value.UnmarshalBCS(bcs)
}