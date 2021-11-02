// Copyright © 2021 AMIS Technologies
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
// 	protoc        v3.14.0
// source: github.com/getamis/alice/crypto/schnorrsignature/message.proto

package schnorrsignature

import (
	ecpointgrouplaw "github.com/getamis/alice/crypto/ecpointgrouplaw"
	zkproof "github.com/getamis/alice/crypto/zkproof"
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

type CommitmentMsg struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	X  []byte                          `protobuf:"bytes,1,opt,name=x,proto3" json:"x,omitempty"`
	D  *ecpointgrouplaw.EcPointMessage `protobuf:"bytes,2,opt,name=D,proto3" json:"D,omitempty"`
	E  *ecpointgrouplaw.EcPointMessage `protobuf:"bytes,3,opt,name=E,proto3" json:"E,omitempty"`
	SG *zkproof.SchnorrProofMessage    `protobuf:"bytes,4,opt,name=sG,proto3" json:"sG,omitempty"`
}

func (x *CommitmentMsg) Reset() {
	*x = CommitmentMsg{}
	if protoimpl.UnsafeEnabled {
		mi := &file_github_com_getamis_alice_crypto_schnorrsignature_message_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *CommitmentMsg) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*CommitmentMsg) ProtoMessage() {}

func (x *CommitmentMsg) ProtoReflect() protoreflect.Message {
	mi := &file_github_com_getamis_alice_crypto_schnorrsignature_message_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use CommitmentMsg.ProtoReflect.Descriptor instead.
func (*CommitmentMsg) Descriptor() ([]byte, []int) {
	return file_github_com_getamis_alice_crypto_schnorrsignature_message_proto_rawDescGZIP(), []int{0}
}

func (x *CommitmentMsg) GetX() []byte {
	if x != nil {
		return x.X
	}
	return nil
}

func (x *CommitmentMsg) GetD() *ecpointgrouplaw.EcPointMessage {
	if x != nil {
		return x.D
	}
	return nil
}

func (x *CommitmentMsg) GetE() *ecpointgrouplaw.EcPointMessage {
	if x != nil {
		return x.E
	}
	return nil
}

func (x *CommitmentMsg) GetSG() *zkproof.SchnorrProofMessage {
	if x != nil {
		return x.SG
	}
	return nil
}

type PartialSignatureMsg struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	X  []byte `protobuf:"bytes,1,opt,name=x,proto3" json:"x,omitempty"`
	Si []byte `protobuf:"bytes,2,opt,name=si,proto3" json:"si,omitempty"`
}

func (x *PartialSignatureMsg) Reset() {
	*x = PartialSignatureMsg{}
	if protoimpl.UnsafeEnabled {
		mi := &file_github_com_getamis_alice_crypto_schnorrsignature_message_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *PartialSignatureMsg) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*PartialSignatureMsg) ProtoMessage() {}

func (x *PartialSignatureMsg) ProtoReflect() protoreflect.Message {
	mi := &file_github_com_getamis_alice_crypto_schnorrsignature_message_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use PartialSignatureMsg.ProtoReflect.Descriptor instead.
func (*PartialSignatureMsg) Descriptor() ([]byte, []int) {
	return file_github_com_getamis_alice_crypto_schnorrsignature_message_proto_rawDescGZIP(), []int{1}
}

func (x *PartialSignatureMsg) GetX() []byte {
	if x != nil {
		return x.X
	}
	return nil
}

func (x *PartialSignatureMsg) GetSi() []byte {
	if x != nil {
		return x.Si
	}
	return nil
}

var File_github_com_getamis_alice_crypto_schnorrsignature_message_proto protoreflect.FileDescriptor

var file_github_com_getamis_alice_crypto_schnorrsignature_message_proto_rawDesc = []byte{
	0x0a, 0x3e, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x67, 0x65, 0x74,
	0x61, 0x6d, 0x69, 0x73, 0x2f, 0x61, 0x6c, 0x69, 0x63, 0x65, 0x2f, 0x63, 0x72, 0x79, 0x70, 0x74,
	0x6f, 0x2f, 0x73, 0x63, 0x68, 0x6e, 0x6f, 0x72, 0x72, 0x73, 0x69, 0x67, 0x6e, 0x61, 0x74, 0x75,
	0x72, 0x65, 0x2f, 0x6d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x12, 0x10, 0x73, 0x63, 0x68, 0x6e, 0x6f, 0x72, 0x72, 0x73, 0x69, 0x67, 0x6e, 0x61, 0x74, 0x75,
	0x72, 0x65, 0x1a, 0x35, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x67,
	0x65, 0x74, 0x61, 0x6d, 0x69, 0x73, 0x2f, 0x61, 0x6c, 0x69, 0x63, 0x65, 0x2f, 0x63, 0x72, 0x79,
	0x70, 0x74, 0x6f, 0x2f, 0x7a, 0x6b, 0x70, 0x72, 0x6f, 0x6f, 0x66, 0x2f, 0x6d, 0x65, 0x73, 0x73,
	0x61, 0x67, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x3b, 0x67, 0x69, 0x74, 0x68, 0x75,
	0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x67, 0x65, 0x74, 0x61, 0x6d, 0x69, 0x73, 0x2f, 0x61, 0x6c,
	0x69, 0x63, 0x65, 0x2f, 0x63, 0x72, 0x79, 0x70, 0x74, 0x6f, 0x2f, 0x65, 0x63, 0x70, 0x6f, 0x69,
	0x6e, 0x74, 0x67, 0x72, 0x6f, 0x75, 0x70, 0x6c, 0x61, 0x77, 0x2f, 0x70, 0x6f, 0x69, 0x6e, 0x74,
	0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0xa9, 0x01, 0x0a, 0x0d, 0x43, 0x6f, 0x6d, 0x6d, 0x69,
	0x74, 0x6d, 0x65, 0x6e, 0x74, 0x4d, 0x73, 0x67, 0x12, 0x0c, 0x0a, 0x01, 0x78, 0x18, 0x01, 0x20,
	0x01, 0x28, 0x0c, 0x52, 0x01, 0x78, 0x12, 0x2d, 0x0a, 0x01, 0x44, 0x18, 0x02, 0x20, 0x01, 0x28,
	0x0b, 0x32, 0x1f, 0x2e, 0x65, 0x63, 0x70, 0x6f, 0x69, 0x6e, 0x74, 0x67, 0x72, 0x6f, 0x75, 0x70,
	0x6c, 0x61, 0x77, 0x2e, 0x45, 0x63, 0x50, 0x6f, 0x69, 0x6e, 0x74, 0x4d, 0x65, 0x73, 0x73, 0x61,
	0x67, 0x65, 0x52, 0x01, 0x44, 0x12, 0x2d, 0x0a, 0x01, 0x45, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0b,
	0x32, 0x1f, 0x2e, 0x65, 0x63, 0x70, 0x6f, 0x69, 0x6e, 0x74, 0x67, 0x72, 0x6f, 0x75, 0x70, 0x6c,
	0x61, 0x77, 0x2e, 0x45, 0x63, 0x50, 0x6f, 0x69, 0x6e, 0x74, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67,
	0x65, 0x52, 0x01, 0x45, 0x12, 0x2c, 0x0a, 0x02, 0x73, 0x47, 0x18, 0x04, 0x20, 0x01, 0x28, 0x0b,
	0x32, 0x1c, 0x2e, 0x7a, 0x6b, 0x70, 0x72, 0x6f, 0x6f, 0x66, 0x2e, 0x53, 0x63, 0x68, 0x6e, 0x6f,
	0x72, 0x72, 0x50, 0x72, 0x6f, 0x6f, 0x66, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x52, 0x02,
	0x73, 0x47, 0x22, 0x33, 0x0a, 0x13, 0x50, 0x61, 0x72, 0x74, 0x69, 0x61, 0x6c, 0x53, 0x69, 0x67,
	0x6e, 0x61, 0x74, 0x75, 0x72, 0x65, 0x4d, 0x73, 0x67, 0x12, 0x0c, 0x0a, 0x01, 0x78, 0x18, 0x01,
	0x20, 0x01, 0x28, 0x0c, 0x52, 0x01, 0x78, 0x12, 0x0e, 0x0a, 0x02, 0x73, 0x69, 0x18, 0x02, 0x20,
	0x01, 0x28, 0x0c, 0x52, 0x02, 0x73, 0x69, 0x42, 0x32, 0x5a, 0x30, 0x67, 0x69, 0x74, 0x68, 0x75,
	0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x67, 0x65, 0x74, 0x61, 0x6d, 0x69, 0x73, 0x2f, 0x61, 0x6c,
	0x69, 0x63, 0x65, 0x2f, 0x63, 0x72, 0x79, 0x70, 0x74, 0x6f, 0x2f, 0x73, 0x63, 0x68, 0x6e, 0x6f,
	0x72, 0x72, 0x73, 0x69, 0x67, 0x6e, 0x61, 0x74, 0x75, 0x72, 0x65, 0x62, 0x06, 0x70, 0x72, 0x6f,
	0x74, 0x6f, 0x33,
}

var (
	file_github_com_getamis_alice_crypto_schnorrsignature_message_proto_rawDescOnce sync.Once
	file_github_com_getamis_alice_crypto_schnorrsignature_message_proto_rawDescData = file_github_com_getamis_alice_crypto_schnorrsignature_message_proto_rawDesc
)

func file_github_com_getamis_alice_crypto_schnorrsignature_message_proto_rawDescGZIP() []byte {
	file_github_com_getamis_alice_crypto_schnorrsignature_message_proto_rawDescOnce.Do(func() {
		file_github_com_getamis_alice_crypto_schnorrsignature_message_proto_rawDescData = protoimpl.X.CompressGZIP(file_github_com_getamis_alice_crypto_schnorrsignature_message_proto_rawDescData)
	})
	return file_github_com_getamis_alice_crypto_schnorrsignature_message_proto_rawDescData
}

var file_github_com_getamis_alice_crypto_schnorrsignature_message_proto_msgTypes = make([]protoimpl.MessageInfo, 2)
var file_github_com_getamis_alice_crypto_schnorrsignature_message_proto_goTypes = []interface{}{
	(*CommitmentMsg)(nil),                  // 0: schnorrsignature.CommitmentMsg
	(*PartialSignatureMsg)(nil),            // 1: schnorrsignature.PartialSignatureMsg
	(*ecpointgrouplaw.EcPointMessage)(nil), // 2: ecpointgrouplaw.EcPointMessage
	(*zkproof.SchnorrProofMessage)(nil),    // 3: zkproof.SchnorrProofMessage
}
var file_github_com_getamis_alice_crypto_schnorrsignature_message_proto_depIdxs = []int32{
	2, // 0: schnorrsignature.CommitmentMsg.D:type_name -> ecpointgrouplaw.EcPointMessage
	2, // 1: schnorrsignature.CommitmentMsg.E:type_name -> ecpointgrouplaw.EcPointMessage
	3, // 2: schnorrsignature.CommitmentMsg.sG:type_name -> zkproof.SchnorrProofMessage
	3, // [3:3] is the sub-list for method output_type
	3, // [3:3] is the sub-list for method input_type
	3, // [3:3] is the sub-list for extension type_name
	3, // [3:3] is the sub-list for extension extendee
	0, // [0:3] is the sub-list for field type_name
}

func init() { file_github_com_getamis_alice_crypto_schnorrsignature_message_proto_init() }
func file_github_com_getamis_alice_crypto_schnorrsignature_message_proto_init() {
	if File_github_com_getamis_alice_crypto_schnorrsignature_message_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_github_com_getamis_alice_crypto_schnorrsignature_message_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*CommitmentMsg); i {
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
		file_github_com_getamis_alice_crypto_schnorrsignature_message_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*PartialSignatureMsg); i {
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
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_github_com_getamis_alice_crypto_schnorrsignature_message_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   2,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_github_com_getamis_alice_crypto_schnorrsignature_message_proto_goTypes,
		DependencyIndexes: file_github_com_getamis_alice_crypto_schnorrsignature_message_proto_depIdxs,
		MessageInfos:      file_github_com_getamis_alice_crypto_schnorrsignature_message_proto_msgTypes,
	}.Build()
	File_github_com_getamis_alice_crypto_schnorrsignature_message_proto = out.File
	file_github_com_getamis_alice_crypto_schnorrsignature_message_proto_rawDesc = nil
	file_github_com_getamis_alice_crypto_schnorrsignature_message_proto_goTypes = nil
	file_github_com_getamis_alice_crypto_schnorrsignature_message_proto_depIdxs = nil
}