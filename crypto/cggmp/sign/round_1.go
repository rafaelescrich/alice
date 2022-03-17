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

package sign

import (
	"errors"
	"math/big"

	"github.com/getamis/alice/crypto/birkhoffinterpolation"
	pt "github.com/getamis/alice/crypto/ecpointgrouplaw"
	"github.com/getamis/alice/crypto/homo/paillier"
	"github.com/getamis/alice/crypto/tss"
	"github.com/getamis/alice/crypto/utils"
	paillierzkproof "github.com/getamis/alice/crypto/zkproof/paillier"
	"github.com/getamis/alice/internal/message/types"
	"github.com/getamis/sirius/log"
)

const (
	BYTELENGTHKAPPA = 32
)

var (
	ErrNotEnoughRanks = errors.New("not enough ranks")

	big1      = big.NewInt(1)
	big2      = big.NewInt(2)
	parameter = paillierzkproof.NewS256()
)

type round1Data struct {
	countDelta *big.Int
	beta       *big.Int
	s          *big.Int
	r          *big.Int
	D          []byte
	F          *big.Int
	// allGammaPoint *pt.ECPoint
	// psiProof      *paillierzkproof.PaillierAffAndGroupRangeMessage
	// psihatProoof  *paillierzkproof.PaillierAffAndGroupRangeMessage

	countSigma           *big.Int
	betahat              *big.Int
	shat                 *big.Int
	rhat                 *big.Int
	Dhat                 []byte
	Fhat                 *big.Int
	gammaOtherCiphertext *big.Int
	kOtherCiphertext     *big.Int
}

type round1Handler struct {
	ssid            []byte
	bkMulShare      *big.Int
	pubKey          *pt.ECPoint
	allY            map[string]*pt.ECPoint
	paillierKey     *paillier.Paillier
	partialPubKey   map[string]*pt.ECPoint
	bkpartialPubKey *pt.ECPoint
	msg             []byte

	delta    *big.Int
	chi      *big.Int
	BigDelta *pt.ECPoint

	k           *big.Int
	rho         *big.Int
	kCiphertext *big.Int

	gamma           *big.Int
	mu              *big.Int
	gammaCiphertext *big.Int
	sumMTAAlpha     *big.Int

	Gamma    *pt.EcPointMessage
	sumGamma *pt.ECPoint

	bks     map[string]*birkhoffinterpolation.BkParameter
	bkShare *big.Int

	peerManager types.PeerManager
	peerNum     uint32
	peers       map[string]*peer
	own         *peer
}

func newRound1Handler(threshold uint32, ssid []byte, share *big.Int, pubKey *pt.ECPoint, partialPubKey, allY map[string]*pt.ECPoint, paillierKey *paillier.Paillier, ped map[string]*paillier.PederssenOpenParameter, bks map[string]*birkhoffinterpolation.BkParameter, msg []byte, peerManager types.PeerManager) (*round1Handler, error) {
	curveN := pubKey.GetCurve().Params().N
	// Establish BK Coefficient:
	selfId := peerManager.SelfID()
	ownBK := bks[peerManager.SelfID()]
	bkss := birkhoffinterpolation.BkParameters{
		ownBK,
	}
	ids := []string{
		selfId,
	}
	for id, bk := range bks {
		if id == selfId {
			continue
		}
		bkss = append(bkss, bk)
		ids = append(ids, id)
	}
	err := bkss.CheckValid(threshold, curveN)
	if err != nil {
		return nil, err
	}

	// Build peers
	bkcoefficient, err := bkss.ComputeBkCoefficient(threshold, curveN)
	if err != nil {
		return nil, err
	}
	peers := make(map[string]*peer, peerManager.NumPeers())
	for i, id := range ids {
		peers[id] = newPeer(id, ssid, bks[id], bkcoefficient[i], ped[id], partialPubKey[id], allY[id])
	}
	bkShare := new(big.Int).Mul(share, bkcoefficient[0])
	bkShare.Mod(bkShare, curveN)

	p := &round1Handler{
		ssid:          ssid,
		bkMulShare:    bkShare,
		pubKey:        pubKey,
		allY:          allY,
		paillierKey:   paillierKey,
		partialPubKey: partialPubKey,
		msg:           msg,

		bks:     bks,
		bkShare: bkShare,

		peerManager: peerManager,
		peerNum:     peerManager.NumPeers(),
		peers:       peers,
		own:         newPeer(selfId, ssid, ownBK, bkcoefficient[0], ped[selfId], partialPubKey[selfId], allY[selfId]),
	}

	// Build and send round1 message
	// k, γ in F_q
	k, err := utils.RandomInt(curveN)
	if err != nil {
		return nil, err
	}
	gamma, err := utils.RandomInt(curveN)
	if err != nil {
		return nil, err
	}
	// Gi = enc_i(γ, mu), and Ki = enc(k, ρ)
	kCiphertext, rho, err := p.paillierKey.EncryptWithOutputSalt(k)
	if err != nil {
		return nil, err
	}
	gammaCiphertext, mu, err := p.paillierKey.EncryptWithOutputSalt(gamma)
	if err != nil {
		return nil, err
	}
	n := p.paillierKey.GetN()
	for id, peer := range peers {
		ped := peer.para
		pedN := ped.Getn()
		peds := ped.Gets()
		pedt := ped.Gett()
		// Compute proof psi_{j,i}^0
		psi, err := paillierzkproof.NewEncryptRangeMessage(parameter, peer.ssidWithBk, kCiphertext, n, k, rho, pedN, peds, pedt)
		if err != nil {
			return nil, err
		}
		peerManager.MustSend(id, &Message{
			Id:   selfId,
			Type: Type_Round1,
			Body: &Message_Round1{
				Round1: &Round1Msg{
					KCiphertext:     kCiphertext.Bytes(),
					GammaCiphertext: gammaCiphertext.Bytes(),
					Psi:             psi,
				},
			},
		})
	}

	// Set data
	p.k = k
	p.rho = rho
	p.kCiphertext = kCiphertext
	p.gamma = gamma
	p.mu = mu
	p.gammaCiphertext = gammaCiphertext
	return p, nil
}

func (p *round1Handler) MessageType() types.MessageType {
	return types.MessageType(Type_Round1)
}

func (p *round1Handler) GetRequiredMessageCount() uint32 {
	return p.peerNum
}

func (p *round1Handler) IsHandled(logger log.Logger, id string) bool {
	peer, ok := p.peers[id]
	if !ok {
		logger.Warn("Peer not found")
		return false
	}
	return peer.Messages[p.MessageType()] != nil
}

func (p *round1Handler) HandleMessage(logger log.Logger, message types.Message) error {
	msg := getMessage(message)
	id := msg.GetId()
	peer, ok := p.peers[id]
	if !ok {
		logger.Warn("Peer not found")
		return tss.ErrPeerNotFound
	}

	curve := p.pubKey.GetCurve()
	// Compute Gamma = gamma*G
	Gamma := pt.ScalarBaseMult(curve, p.gamma)
	msgGamma, err := Gamma.ToEcPointMessage()
	if err != nil {
		return err
	}

	round1 := msg.GetRound1()
	ownPed := p.own.para
	peerPed := peer.para
	n := peerPed.Getn()

	// verify Proof_enc
	err = round1.Psi.Verify(parameter, p.own.ssidWithBk, round1.KCiphertext, n, ownPed.Getn(), ownPed.Gets(), ownPed.Gett())
	if err != nil {
		return err
	}
	negBeta, countDelta, r, s, D, F, phiProof, err := mtaWithProofAff_g(peer, p.paillierKey, round1.KCiphertext, p.gamma, Gamma)
	if err != nil {
		return err
	}
	// psihat share proof: M(prove,Πaff-g,(sid,i),(Iε,Jε,Dˆj,i,Kj,Fˆj,i,Xi);(xi,βˆi,j,sˆi,j,rˆi,j)).
	p.bkpartialPubKey = p.own.partialPubKey.ScalarMult(peer.bkcoefficient)

	negBetahat, countSigma, rhat, shat, Dhat, Fhat, psihatProof, err := mtaWithProofAff_g(peer, p.paillierKey, round1.KCiphertext, p.bkMulShare, p.bkpartialPubKey)
	if err != nil {
		return err
	}

	peer.round1Data = &round1Data{
		countDelta:           countDelta,
		beta:                 negBeta,
		r:                    r,
		s:                    s,
		D:                    D,
		F:                    F,
		gammaOtherCiphertext: new(big.Int).SetBytes(round1.GammaCiphertext),
		kOtherCiphertext:     new(big.Int).SetBytes(round1.KCiphertext),

		countSigma: countSigma,
		betahat:    negBetahat,
		rhat:       rhat,
		shat:       shat,
		Dhat:       Dhat,
		Fhat:       Fhat,
	}

	// logstar proof for the secret gamma, mu: M(prove,Πlog,(sid,i),(Iε,Gi,Γi,g);(γi,νi)).
	G := pt.NewBase(curve)
	psipaiProof, err := paillierzkproof.NewKnowExponentAndPaillierEncryption(parameter, peer.ssidWithBk, p.gamma, p.mu, p.gammaCiphertext, p.paillierKey.GetN(), peerPed.Getn(), peerPed.Gets(), peerPed.Gett(), Gamma, G)
	if err != nil {
		return err
	}
	p.peerManager.MustSend(id, &Message{
		Id:   p.own.Id,
		Type: Type_Round2,
		Body: &Message_Round2{
			Round2: &Round2Msg{
				D:      D,
				F:      F.Bytes(),
				Dhat:   Dhat,
				Fhat:   Fhat.Bytes(),
				Psi:    phiProof,
				Psihat: psihatProof,
				Psipai: psipaiProof,
				Gamma:  msgGamma,
			},
		},
	})
	return peer.AddMessage(msg)
}

func (p *round1Handler) Finalize(logger log.Logger) (types.Handler, error) {
	return newRound2Handler(p)
}

func getMessage(messsage types.Message) *Message {
	return messsage.(*Message)
}

func mtaWithProofAff_g(peer *peer, paillierKey *paillier.Paillier, msgCipher []byte, x *big.Int, ecPoint *pt.ECPoint) (*big.Int, *big.Int, *big.Int, *big.Int, []byte, *big.Int, *paillierzkproof.PaillierAffAndGroupRangeMessage, error) {
	beta, s, r, D, F, err := performMTA(peer, paillierKey, msgCipher, x)
	if err != nil {
		return nil, nil, nil, nil, nil, nil, nil, err
	}
	otherPed := peer.para
	otherPeoplePaillierKey := otherPed.ToPaillierPubKeyWithSpecialG()
	proof, err := paillierzkproof.NewPaillierAffAndGroupRangeMessage(parameter, peer.ssidWithBk, x, beta, s, r, otherPed.Getn(), paillierKey.GetN(), new(big.Int).SetBytes(msgCipher), D, F, otherPed.Getn(), otherPed.Gets(), otherPed.Gett(), ecPoint)
	if err != nil {
		return nil, nil, nil, nil, nil, nil, nil, err
	}
	adjustBeat, count := computeBeta(beta, otherPeoplePaillierKey.GetN(), ecPoint.GetCurve().Params().N, big.NewInt(0))
	return adjustBeat, count, r, s, D.Bytes(), F, proof, nil
}

func performMTA(peer *peer, paillierKey *paillier.Paillier, msgCipher []byte, x *big.Int) (*big.Int, *big.Int, *big.Int, *big.Int, *big.Int, error) {
	beta, err := utils.RandomAbsoluteRangeInt(new(big.Int).Lsh(big2, parameter.Lpai))
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}

	// Use other people pubKey: Dj,i = (γi ⊙ Kj) ⊕ encj(−βi,j , si,j) and Fj,i = enci(βi,j , ri,j).
	ped := peer.para
	peoplePaillierKey := ped.ToPaillierPubKeyWithSpecialG()
	D := new(big.Int).Exp(new(big.Int).SetBytes(msgCipher), x, peoplePaillierKey.GetNSquare())
	tempEnc, s, err := peoplePaillierKey.EncryptWithOutputSalt(beta)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}
	D.Mul(D, tempEnc)
	D.Mod(D, peoplePaillierKey.GetNSquare())

	F, r, err := paillierKey.EncryptWithOutputSalt(beta)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}
	return beta, s, r, D, F, nil
}

// If k*\gamma + beta < 0, we should change beta value.
func computeBeta(beta *big.Int, paillierN *big.Int, fieldOrder *big.Int, count *big.Int) (*big.Int, *big.Int) {
	result := new(big.Int).Neg(beta)
	if beta.Cmp(new(big.Int).Mul(fieldOrder, fieldOrder)) < 0 {
		result.Sub(result, paillierN)
		count.Add(count, big1)
	}
	return result, count
}
