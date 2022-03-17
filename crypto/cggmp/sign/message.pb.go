// Copyright © 2022 AMIS Technologies
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.26.0
// 	protoc        v3.6.1
// source: github.com/getamis/alice/crypto/cggmp/sign/message.proto

package sign

import (
	ecpointgrouplaw "github.com/getamis/alice/crypto/ecpointgrouplaw"
	paillier "github.com/getamis/alice/crypto/zkproof/paillier"
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type Type int32

const (
	Type_Round1 Type = 0
	Type_Round2 Type = 1
	Type_Round3 Type = 2
	Type_Round4 Type = 3
)

// Enum value maps for Type.
var (
	Type_name = map[int32]string{
		0: "Round1",
		1: "Round2",
		2: "Round3",
		3: "Round4",
	}
	Type_value = map[string]int32{
		"Round1": 0,
		"Round2": 1,
		"Round3": 2,
		"Round4": 3,
	}
)

func (x Type) Enum() *Type {
	p := new(Type)
	*p = x
	return p
}

func (x Type) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (Type) Descriptor() protoreflect.EnumDescriptor {
	return file_github_com_getamis_alice_crypto_cggmp_sign_message_proto_enumTypes[0].Descriptor()
}

func (Type) Type() protoreflect.EnumType {
	return &file_github_com_getamis_alice_crypto_cggmp_sign_message_proto_enumTypes[0]
}

func (x Type) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use Type.Descriptor instead.
func (Type) EnumDescriptor() ([]byte, []int) {
	return file_github_com_getamis_alice_crypto_cggmp_sign_message_proto_rawDescGZIP(), []int{0}
}

type Message struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Type Type   `protobuf:"varint,1,opt,name=type,proto3,enum=sign.Type" json:"type,omitempty"`
	Id   string `protobuf:"bytes,2,opt,name=id,proto3" json:"id,omitempty"`
	// Types that are assignable to Body:
	//	*Message_Round1
	//	*Message_Round2
	//	*Message_Round3
	//	*Message_Round4
	Body isMessage_Body `protobuf_oneof:"body"`
}

func (x *Message) Reset() {
	*x = Message{}
	if protoimpl.UnsafeEnabled {
		mi := &file_github_com_getamis_alice_crypto_cggmp_sign_message_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Message) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Message) ProtoMessage() {}

func (x *Message) ProtoReflect() protoreflect.Message {
	mi := &file_github_com_getamis_alice_crypto_cggmp_sign_message_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Message.ProtoReflect.Descriptor instead.
func (*Message) Descriptor() ([]byte, []int) {
	return file_github_com_getamis_alice_crypto_cggmp_sign_message_proto_rawDescGZIP(), []int{0}
}

func (x *Message) GetType() Type {
	if x != nil {
		return x.Type
	}
	return Type_Round1
}

func (x *Message) GetId() string {
	if x != nil {
		return x.Id
	}
	return ""
}

func (m *Message) GetBody() isMessage_Body {
	if m != nil {
		return m.Body
	}
	return nil
}

func (x *Message) GetRound1() *Round1Msg {
	if x, ok := x.GetBody().(*Message_Round1); ok {
		return x.Round1
	}
	return nil
}

func (x *Message) GetRound2() *Round2Msg {
	if x, ok := x.GetBody().(*Message_Round2); ok {
		return x.Round2
	}
	return nil
}

func (x *Message) GetRound3() *Round3Msg {
	if x, ok := x.GetBody().(*Message_Round3); ok {
		return x.Round3
	}
	return nil
}

func (x *Message) GetRound4() *Round4Msg {
	if x, ok := x.GetBody().(*Message_Round4); ok {
		return x.Round4
	}
	return nil
}

type isMessage_Body interface {
	isMessage_Body()
}

type Message_Round1 struct {
	Round1 *Round1Msg `protobuf:"bytes,4,opt,name=round1,proto3,oneof"`
}

type Message_Round2 struct {
	Round2 *Round2Msg `protobuf:"bytes,5,opt,name=round2,proto3,oneof"`
}

type Message_Round3 struct {
	Round3 *Round3Msg `protobuf:"bytes,6,opt,name=round3,proto3,oneof"`
}

type Message_Round4 struct {
	Round4 *Round4Msg `protobuf:"bytes,7,opt,name=round4,proto3,oneof"`
}

func (*Message_Round1) isMessage_Body() {}

func (*Message_Round2) isMessage_Body() {}

func (*Message_Round3) isMessage_Body() {}

func (*Message_Round4) isMessage_Body() {}

type Round1Msg struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	KCiphertext     []byte                        `protobuf:"bytes,1,opt,name=kCiphertext,proto3" json:"kCiphertext,omitempty"`
	GammaCiphertext []byte                        `protobuf:"bytes,2,opt,name=gammaCiphertext,proto3" json:"gammaCiphertext,omitempty"`
	Psi             *paillier.EncryptRangeMessage `protobuf:"bytes,3,opt,name=psi,proto3" json:"psi,omitempty"`
}

func (x *Round1Msg) Reset() {
	*x = Round1Msg{}
	if protoimpl.UnsafeEnabled {
		mi := &file_github_com_getamis_alice_crypto_cggmp_sign_message_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Round1Msg) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Round1Msg) ProtoMessage() {}

func (x *Round1Msg) ProtoReflect() protoreflect.Message {
	mi := &file_github_com_getamis_alice_crypto_cggmp_sign_message_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Round1Msg.ProtoReflect.Descriptor instead.
func (*Round1Msg) Descriptor() ([]byte, []int) {
	return file_github_com_getamis_alice_crypto_cggmp_sign_message_proto_rawDescGZIP(), []int{1}
}

func (x *Round1Msg) GetKCiphertext() []byte {
	if x != nil {
		return x.KCiphertext
	}
	return nil
}

func (x *Round1Msg) GetGammaCiphertext() []byte {
	if x != nil {
		return x.GammaCiphertext
	}
	return nil
}

func (x *Round1Msg) GetPsi() *paillier.EncryptRangeMessage {
	if x != nil {
		return x.Psi
	}
	return nil
}

type Round2Msg struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	D      []byte                                    `protobuf:"bytes,1,opt,name=D,proto3" json:"D,omitempty"`
	F      []byte                                    `protobuf:"bytes,2,opt,name=F,proto3" json:"F,omitempty"`
	Dhat   []byte                                    `protobuf:"bytes,3,opt,name=Dhat,proto3" json:"Dhat,omitempty"`
	Fhat   []byte                                    `protobuf:"bytes,4,opt,name=Fhat,proto3" json:"Fhat,omitempty"`
	Psi    *paillier.PaillierAffAndGroupRangeMessage `protobuf:"bytes,5,opt,name=psi,proto3" json:"psi,omitempty"`
	Psihat *paillier.PaillierAffAndGroupRangeMessage `protobuf:"bytes,6,opt,name=psihat,proto3" json:"psihat,omitempty"`
	Psipai *paillier.LogStarMessage                  `protobuf:"bytes,7,opt,name=psipai,proto3" json:"psipai,omitempty"`
	Gamma  *ecpointgrouplaw.EcPointMessage           `protobuf:"bytes,8,opt,name=Gamma,proto3" json:"Gamma,omitempty"`
}

func (x *Round2Msg) Reset() {
	*x = Round2Msg{}
	if protoimpl.UnsafeEnabled {
		mi := &file_github_com_getamis_alice_crypto_cggmp_sign_message_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Round2Msg) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Round2Msg) ProtoMessage() {}

func (x *Round2Msg) ProtoReflect() protoreflect.Message {
	mi := &file_github_com_getamis_alice_crypto_cggmp_sign_message_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Round2Msg.ProtoReflect.Descriptor instead.
func (*Round2Msg) Descriptor() ([]byte, []int) {
	return file_github_com_getamis_alice_crypto_cggmp_sign_message_proto_rawDescGZIP(), []int{2}
}

func (x *Round2Msg) GetD() []byte {
	if x != nil {
		return x.D
	}
	return nil
}

func (x *Round2Msg) GetF() []byte {
	if x != nil {
		return x.F
	}
	return nil
}

func (x *Round2Msg) GetDhat() []byte {
	if x != nil {
		return x.Dhat
	}
	return nil
}

func (x *Round2Msg) GetFhat() []byte {
	if x != nil {
		return x.Fhat
	}
	return nil
}

func (x *Round2Msg) GetPsi() *paillier.PaillierAffAndGroupRangeMessage {
	if x != nil {
		return x.Psi
	}
	return nil
}

func (x *Round2Msg) GetPsihat() *paillier.PaillierAffAndGroupRangeMessage {
	if x != nil {
		return x.Psihat
	}
	return nil
}

func (x *Round2Msg) GetPsipai() *paillier.LogStarMessage {
	if x != nil {
		return x.Psipai
	}
	return nil
}

func (x *Round2Msg) GetGamma() *ecpointgrouplaw.EcPointMessage {
	if x != nil {
		return x.Gamma
	}
	return nil
}

type Round3Msg struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Delta        string                          `protobuf:"bytes,1,opt,name=delta,proto3" json:"delta,omitempty"`
	BigDelta     *ecpointgrouplaw.EcPointMessage `protobuf:"bytes,2,opt,name=bigDelta,proto3" json:"bigDelta,omitempty"`
	Psidoublepai *paillier.LogStarMessage        `protobuf:"bytes,3,opt,name=psidoublepai,proto3" json:"psidoublepai,omitempty"`
}

func (x *Round3Msg) Reset() {
	*x = Round3Msg{}
	if protoimpl.UnsafeEnabled {
		mi := &file_github_com_getamis_alice_crypto_cggmp_sign_message_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Round3Msg) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Round3Msg) ProtoMessage() {}

func (x *Round3Msg) ProtoReflect() protoreflect.Message {
	mi := &file_github_com_getamis_alice_crypto_cggmp_sign_message_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Round3Msg.ProtoReflect.Descriptor instead.
func (*Round3Msg) Descriptor() ([]byte, []int) {
	return file_github_com_getamis_alice_crypto_cggmp_sign_message_proto_rawDescGZIP(), []int{3}
}

func (x *Round3Msg) GetDelta() string {
	if x != nil {
		return x.Delta
	}
	return ""
}

func (x *Round3Msg) GetBigDelta() *ecpointgrouplaw.EcPointMessage {
	if x != nil {
		return x.BigDelta
	}
	return nil
}

func (x *Round3Msg) GetPsidoublepai() *paillier.LogStarMessage {
	if x != nil {
		return x.Psidoublepai
	}
	return nil
}

type Round4Msg struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Sigmai []byte `protobuf:"bytes,1,opt,name=sigmai,proto3" json:"sigmai,omitempty"`
}

func (x *Round4Msg) Reset() {
	*x = Round4Msg{}
	if protoimpl.UnsafeEnabled {
		mi := &file_github_com_getamis_alice_crypto_cggmp_sign_message_proto_msgTypes[4]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Round4Msg) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Round4Msg) ProtoMessage() {}

func (x *Round4Msg) ProtoReflect() protoreflect.Message {
	mi := &file_github_com_getamis_alice_crypto_cggmp_sign_message_proto_msgTypes[4]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Round4Msg.ProtoReflect.Descriptor instead.
func (*Round4Msg) Descriptor() ([]byte, []int) {
	return file_github_com_getamis_alice_crypto_cggmp_sign_message_proto_rawDescGZIP(), []int{4}
}

func (x *Round4Msg) GetSigmai() []byte {
	if x != nil {
		return x.Sigmai
	}
	return nil
}

var File_github_com_getamis_alice_crypto_cggmp_sign_message_proto protoreflect.FileDescriptor

var file_github_com_getamis_alice_crypto_cggmp_sign_message_proto_rawDesc = []byte{
	0x0a, 0x38, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x67, 0x65, 0x74,
	0x61, 0x6d, 0x69, 0x73, 0x2f, 0x61, 0x6c, 0x69, 0x63, 0x65, 0x2f, 0x63, 0x72, 0x79, 0x70, 0x74,
	0x6f, 0x2f, 0x63, 0x67, 0x67, 0x6d, 0x70, 0x2f, 0x73, 0x69, 0x67, 0x6e, 0x2f, 0x6d, 0x65, 0x73,
	0x73, 0x61, 0x67, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x04, 0x73, 0x69, 0x67, 0x6e,
	0x1a, 0x3b, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x67, 0x65, 0x74,
	0x61, 0x6d, 0x69, 0x73, 0x2f, 0x61, 0x6c, 0x69, 0x63, 0x65, 0x2f, 0x63, 0x72, 0x79, 0x70, 0x74,
	0x6f, 0x2f, 0x65, 0x63, 0x70, 0x6f, 0x69, 0x6e, 0x74, 0x67, 0x72, 0x6f, 0x75, 0x70, 0x6c, 0x61,
	0x77, 0x2f, 0x70, 0x6f, 0x69, 0x6e, 0x74, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x3e, 0x67,
	0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x67, 0x65, 0x74, 0x61, 0x6d, 0x69,
	0x73, 0x2f, 0x61, 0x6c, 0x69, 0x63, 0x65, 0x2f, 0x63, 0x72, 0x79, 0x70, 0x74, 0x6f, 0x2f, 0x7a,
	0x6b, 0x70, 0x72, 0x6f, 0x6f, 0x66, 0x2f, 0x70, 0x61, 0x69, 0x6c, 0x6c, 0x69, 0x65, 0x72, 0x2f,
	0x6d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0xed, 0x01,
	0x0a, 0x07, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x12, 0x1e, 0x0a, 0x04, 0x74, 0x79, 0x70,
	0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0e, 0x32, 0x0a, 0x2e, 0x73, 0x69, 0x67, 0x6e, 0x2e, 0x54,
	0x79, 0x70, 0x65, 0x52, 0x04, 0x74, 0x79, 0x70, 0x65, 0x12, 0x0e, 0x0a, 0x02, 0x69, 0x64, 0x18,
	0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x02, 0x69, 0x64, 0x12, 0x29, 0x0a, 0x06, 0x72, 0x6f, 0x75,
	0x6e, 0x64, 0x31, 0x18, 0x04, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x0f, 0x2e, 0x73, 0x69, 0x67, 0x6e,
	0x2e, 0x52, 0x6f, 0x75, 0x6e, 0x64, 0x31, 0x4d, 0x73, 0x67, 0x48, 0x00, 0x52, 0x06, 0x72, 0x6f,
	0x75, 0x6e, 0x64, 0x31, 0x12, 0x29, 0x0a, 0x06, 0x72, 0x6f, 0x75, 0x6e, 0x64, 0x32, 0x18, 0x05,
	0x20, 0x01, 0x28, 0x0b, 0x32, 0x0f, 0x2e, 0x73, 0x69, 0x67, 0x6e, 0x2e, 0x52, 0x6f, 0x75, 0x6e,
	0x64, 0x32, 0x4d, 0x73, 0x67, 0x48, 0x00, 0x52, 0x06, 0x72, 0x6f, 0x75, 0x6e, 0x64, 0x32, 0x12,
	0x29, 0x0a, 0x06, 0x72, 0x6f, 0x75, 0x6e, 0x64, 0x33, 0x18, 0x06, 0x20, 0x01, 0x28, 0x0b, 0x32,
	0x0f, 0x2e, 0x73, 0x69, 0x67, 0x6e, 0x2e, 0x52, 0x6f, 0x75, 0x6e, 0x64, 0x33, 0x4d, 0x73, 0x67,
	0x48, 0x00, 0x52, 0x06, 0x72, 0x6f, 0x75, 0x6e, 0x64, 0x33, 0x12, 0x29, 0x0a, 0x06, 0x72, 0x6f,
	0x75, 0x6e, 0x64, 0x34, 0x18, 0x07, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x0f, 0x2e, 0x73, 0x69, 0x67,
	0x6e, 0x2e, 0x52, 0x6f, 0x75, 0x6e, 0x64, 0x34, 0x4d, 0x73, 0x67, 0x48, 0x00, 0x52, 0x06, 0x72,
	0x6f, 0x75, 0x6e, 0x64, 0x34, 0x42, 0x06, 0x0a, 0x04, 0x62, 0x6f, 0x64, 0x79, 0x22, 0x88, 0x01,
	0x0a, 0x09, 0x52, 0x6f, 0x75, 0x6e, 0x64, 0x31, 0x4d, 0x73, 0x67, 0x12, 0x20, 0x0a, 0x0b, 0x6b,
	0x43, 0x69, 0x70, 0x68, 0x65, 0x72, 0x74, 0x65, 0x78, 0x74, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0c,
	0x52, 0x0b, 0x6b, 0x43, 0x69, 0x70, 0x68, 0x65, 0x72, 0x74, 0x65, 0x78, 0x74, 0x12, 0x28, 0x0a,
	0x0f, 0x67, 0x61, 0x6d, 0x6d, 0x61, 0x43, 0x69, 0x70, 0x68, 0x65, 0x72, 0x74, 0x65, 0x78, 0x74,
	0x18, 0x02, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x0f, 0x67, 0x61, 0x6d, 0x6d, 0x61, 0x43, 0x69, 0x70,
	0x68, 0x65, 0x72, 0x74, 0x65, 0x78, 0x74, 0x12, 0x2f, 0x0a, 0x03, 0x70, 0x73, 0x69, 0x18, 0x03,
	0x20, 0x01, 0x28, 0x0b, 0x32, 0x1d, 0x2e, 0x70, 0x61, 0x69, 0x6c, 0x6c, 0x69, 0x65, 0x72, 0x2e,
	0x45, 0x6e, 0x63, 0x72, 0x79, 0x70, 0x74, 0x52, 0x61, 0x6e, 0x67, 0x65, 0x4d, 0x65, 0x73, 0x73,
	0x61, 0x67, 0x65, 0x52, 0x03, 0x70, 0x73, 0x69, 0x22, 0xb8, 0x02, 0x0a, 0x09, 0x52, 0x6f, 0x75,
	0x6e, 0x64, 0x32, 0x4d, 0x73, 0x67, 0x12, 0x0c, 0x0a, 0x01, 0x44, 0x18, 0x01, 0x20, 0x01, 0x28,
	0x0c, 0x52, 0x01, 0x44, 0x12, 0x0c, 0x0a, 0x01, 0x46, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0c, 0x52,
	0x01, 0x46, 0x12, 0x12, 0x0a, 0x04, 0x44, 0x68, 0x61, 0x74, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0c,
	0x52, 0x04, 0x44, 0x68, 0x61, 0x74, 0x12, 0x12, 0x0a, 0x04, 0x46, 0x68, 0x61, 0x74, 0x18, 0x04,
	0x20, 0x01, 0x28, 0x0c, 0x52, 0x04, 0x46, 0x68, 0x61, 0x74, 0x12, 0x3b, 0x0a, 0x03, 0x70, 0x73,
	0x69, 0x18, 0x05, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x29, 0x2e, 0x70, 0x61, 0x69, 0x6c, 0x6c, 0x69,
	0x65, 0x72, 0x2e, 0x50, 0x61, 0x69, 0x6c, 0x6c, 0x69, 0x65, 0x72, 0x41, 0x66, 0x66, 0x41, 0x6e,
	0x64, 0x47, 0x72, 0x6f, 0x75, 0x70, 0x52, 0x61, 0x6e, 0x67, 0x65, 0x4d, 0x65, 0x73, 0x73, 0x61,
	0x67, 0x65, 0x52, 0x03, 0x70, 0x73, 0x69, 0x12, 0x41, 0x0a, 0x06, 0x70, 0x73, 0x69, 0x68, 0x61,
	0x74, 0x18, 0x06, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x29, 0x2e, 0x70, 0x61, 0x69, 0x6c, 0x6c, 0x69,
	0x65, 0x72, 0x2e, 0x50, 0x61, 0x69, 0x6c, 0x6c, 0x69, 0x65, 0x72, 0x41, 0x66, 0x66, 0x41, 0x6e,
	0x64, 0x47, 0x72, 0x6f, 0x75, 0x70, 0x52, 0x61, 0x6e, 0x67, 0x65, 0x4d, 0x65, 0x73, 0x73, 0x61,
	0x67, 0x65, 0x52, 0x06, 0x70, 0x73, 0x69, 0x68, 0x61, 0x74, 0x12, 0x30, 0x0a, 0x06, 0x70, 0x73,
	0x69, 0x70, 0x61, 0x69, 0x18, 0x07, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x18, 0x2e, 0x70, 0x61, 0x69,
	0x6c, 0x6c, 0x69, 0x65, 0x72, 0x2e, 0x4c, 0x6f, 0x67, 0x53, 0x74, 0x61, 0x72, 0x4d, 0x65, 0x73,
	0x73, 0x61, 0x67, 0x65, 0x52, 0x06, 0x70, 0x73, 0x69, 0x70, 0x61, 0x69, 0x12, 0x35, 0x0a, 0x05,
	0x47, 0x61, 0x6d, 0x6d, 0x61, 0x18, 0x08, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1f, 0x2e, 0x65, 0x63,
	0x70, 0x6f, 0x69, 0x6e, 0x74, 0x67, 0x72, 0x6f, 0x75, 0x70, 0x6c, 0x61, 0x77, 0x2e, 0x45, 0x63,
	0x50, 0x6f, 0x69, 0x6e, 0x74, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x52, 0x05, 0x47, 0x61,
	0x6d, 0x6d, 0x61, 0x22, 0x9c, 0x01, 0x0a, 0x09, 0x52, 0x6f, 0x75, 0x6e, 0x64, 0x33, 0x4d, 0x73,
	0x67, 0x12, 0x14, 0x0a, 0x05, 0x64, 0x65, 0x6c, 0x74, 0x61, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09,
	0x52, 0x05, 0x64, 0x65, 0x6c, 0x74, 0x61, 0x12, 0x3b, 0x0a, 0x08, 0x62, 0x69, 0x67, 0x44, 0x65,
	0x6c, 0x74, 0x61, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1f, 0x2e, 0x65, 0x63, 0x70, 0x6f,
	0x69, 0x6e, 0x74, 0x67, 0x72, 0x6f, 0x75, 0x70, 0x6c, 0x61, 0x77, 0x2e, 0x45, 0x63, 0x50, 0x6f,
	0x69, 0x6e, 0x74, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x52, 0x08, 0x62, 0x69, 0x67, 0x44,
	0x65, 0x6c, 0x74, 0x61, 0x12, 0x3c, 0x0a, 0x0c, 0x70, 0x73, 0x69, 0x64, 0x6f, 0x75, 0x62, 0x6c,
	0x65, 0x70, 0x61, 0x69, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x18, 0x2e, 0x70, 0x61, 0x69,
	0x6c, 0x6c, 0x69, 0x65, 0x72, 0x2e, 0x4c, 0x6f, 0x67, 0x53, 0x74, 0x61, 0x72, 0x4d, 0x65, 0x73,
	0x73, 0x61, 0x67, 0x65, 0x52, 0x0c, 0x70, 0x73, 0x69, 0x64, 0x6f, 0x75, 0x62, 0x6c, 0x65, 0x70,
	0x61, 0x69, 0x22, 0x23, 0x0a, 0x09, 0x52, 0x6f, 0x75, 0x6e, 0x64, 0x34, 0x4d, 0x73, 0x67, 0x12,
	0x16, 0x0a, 0x06, 0x73, 0x69, 0x67, 0x6d, 0x61, 0x69, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0c, 0x52,
	0x06, 0x73, 0x69, 0x67, 0x6d, 0x61, 0x69, 0x2a, 0x36, 0x0a, 0x04, 0x54, 0x79, 0x70, 0x65, 0x12,
	0x0a, 0x0a, 0x06, 0x52, 0x6f, 0x75, 0x6e, 0x64, 0x31, 0x10, 0x00, 0x12, 0x0a, 0x0a, 0x06, 0x52,
	0x6f, 0x75, 0x6e, 0x64, 0x32, 0x10, 0x01, 0x12, 0x0a, 0x0a, 0x06, 0x52, 0x6f, 0x75, 0x6e, 0x64,
	0x33, 0x10, 0x02, 0x12, 0x0a, 0x0a, 0x06, 0x52, 0x6f, 0x75, 0x6e, 0x64, 0x34, 0x10, 0x03, 0x42,
	0x2c, 0x5a, 0x2a, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x67, 0x65,
	0x74, 0x61, 0x6d, 0x69, 0x73, 0x2f, 0x61, 0x6c, 0x69, 0x63, 0x65, 0x2f, 0x63, 0x72, 0x79, 0x70,
	0x74, 0x6f, 0x2f, 0x63, 0x67, 0x67, 0x6d, 0x70, 0x2f, 0x73, 0x69, 0x67, 0x6e, 0x62, 0x06, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_github_com_getamis_alice_crypto_cggmp_sign_message_proto_rawDescOnce sync.Once
	file_github_com_getamis_alice_crypto_cggmp_sign_message_proto_rawDescData = file_github_com_getamis_alice_crypto_cggmp_sign_message_proto_rawDesc
)

func file_github_com_getamis_alice_crypto_cggmp_sign_message_proto_rawDescGZIP() []byte {
	file_github_com_getamis_alice_crypto_cggmp_sign_message_proto_rawDescOnce.Do(func() {
		file_github_com_getamis_alice_crypto_cggmp_sign_message_proto_rawDescData = protoimpl.X.CompressGZIP(file_github_com_getamis_alice_crypto_cggmp_sign_message_proto_rawDescData)
	})
	return file_github_com_getamis_alice_crypto_cggmp_sign_message_proto_rawDescData
}

var file_github_com_getamis_alice_crypto_cggmp_sign_message_proto_enumTypes = make([]protoimpl.EnumInfo, 1)
var file_github_com_getamis_alice_crypto_cggmp_sign_message_proto_msgTypes = make([]protoimpl.MessageInfo, 5)
var file_github_com_getamis_alice_crypto_cggmp_sign_message_proto_goTypes = []interface{}{
	(Type)(0),                            // 0: sign.Type
	(*Message)(nil),                      // 1: sign.Message
	(*Round1Msg)(nil),                    // 2: sign.Round1Msg
	(*Round2Msg)(nil),                    // 3: sign.Round2Msg
	(*Round3Msg)(nil),                    // 4: sign.Round3Msg
	(*Round4Msg)(nil),                    // 5: sign.Round4Msg
	(*paillier.EncryptRangeMessage)(nil), // 6: paillier.EncryptRangeMessage
	(*paillier.PaillierAffAndGroupRangeMessage)(nil), // 7: paillier.PaillierAffAndGroupRangeMessage
	(*paillier.LogStarMessage)(nil),                  // 8: paillier.LogStarMessage
	(*ecpointgrouplaw.EcPointMessage)(nil),           // 9: ecpointgrouplaw.EcPointMessage
}
var file_github_com_getamis_alice_crypto_cggmp_sign_message_proto_depIdxs = []int32{
	0,  // 0: sign.Message.type:type_name -> sign.Type
	2,  // 1: sign.Message.round1:type_name -> sign.Round1Msg
	3,  // 2: sign.Message.round2:type_name -> sign.Round2Msg
	4,  // 3: sign.Message.round3:type_name -> sign.Round3Msg
	5,  // 4: sign.Message.round4:type_name -> sign.Round4Msg
	6,  // 5: sign.Round1Msg.psi:type_name -> paillier.EncryptRangeMessage
	7,  // 6: sign.Round2Msg.psi:type_name -> paillier.PaillierAffAndGroupRangeMessage
	7,  // 7: sign.Round2Msg.psihat:type_name -> paillier.PaillierAffAndGroupRangeMessage
	8,  // 8: sign.Round2Msg.psipai:type_name -> paillier.LogStarMessage
	9,  // 9: sign.Round2Msg.Gamma:type_name -> ecpointgrouplaw.EcPointMessage
	9,  // 10: sign.Round3Msg.bigDelta:type_name -> ecpointgrouplaw.EcPointMessage
	8,  // 11: sign.Round3Msg.psidoublepai:type_name -> paillier.LogStarMessage
	12, // [12:12] is the sub-list for method output_type
	12, // [12:12] is the sub-list for method input_type
	12, // [12:12] is the sub-list for extension type_name
	12, // [12:12] is the sub-list for extension extendee
	0,  // [0:12] is the sub-list for field type_name
}

func init() { file_github_com_getamis_alice_crypto_cggmp_sign_message_proto_init() }
func file_github_com_getamis_alice_crypto_cggmp_sign_message_proto_init() {
	if File_github_com_getamis_alice_crypto_cggmp_sign_message_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_github_com_getamis_alice_crypto_cggmp_sign_message_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Message); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_github_com_getamis_alice_crypto_cggmp_sign_message_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Round1Msg); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_github_com_getamis_alice_crypto_cggmp_sign_message_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Round2Msg); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_github_com_getamis_alice_crypto_cggmp_sign_message_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Round3Msg); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_github_com_getamis_alice_crypto_cggmp_sign_message_proto_msgTypes[4].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Round4Msg); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	file_github_com_getamis_alice_crypto_cggmp_sign_message_proto_msgTypes[0].OneofWrappers = []interface{}{
		(*Message_Round1)(nil),
		(*Message_Round2)(nil),
		(*Message_Round3)(nil),
		(*Message_Round4)(nil),
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_github_com_getamis_alice_crypto_cggmp_sign_message_proto_rawDesc,
			NumEnums:      1,
			NumMessages:   5,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_github_com_getamis_alice_crypto_cggmp_sign_message_proto_goTypes,
		DependencyIndexes: file_github_com_getamis_alice_crypto_cggmp_sign_message_proto_depIdxs,
		EnumInfos:         file_github_com_getamis_alice_crypto_cggmp_sign_message_proto_enumTypes,
		MessageInfos:      file_github_com_getamis_alice_crypto_cggmp_sign_message_proto_msgTypes,
	}.Build()
	File_github_com_getamis_alice_crypto_cggmp_sign_message_proto = out.File
	file_github_com_getamis_alice_crypto_cggmp_sign_message_proto_rawDesc = nil
	file_github_com_getamis_alice_crypto_cggmp_sign_message_proto_goTypes = nil
	file_github_com_getamis_alice_crypto_cggmp_sign_message_proto_depIdxs = nil
}
