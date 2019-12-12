#include "idniks.hpp"

// using namespace mcl::bn256;
using namespace mcl::bn384;

namespace IDNIKS{
  KGCParams::KGCParams(const G1 P, const G2 Q, const G2 lQ){
    this->P = P;
    this->Q = Q;
    this->lQ = lQ;
  }

  bool KGCParams::operator==(const KGCParams &params) const{
    return this->Q==params.Q && this->lQ==params.lQ && this->P==params.P;
  }

  KGCMasterKey::KGCMasterKey(const Fr l){
    this->l = l;
  }

  UserKey::UserKey(const G1 Ku){
    this->Ku = Ku;
  }

  Cipher::Cipher(const G2 C1, const std::vector<unsigned char> C2){
    this->C1 = C1;
    this->C2 = C2;
  }

  Signature::Signature(const G1 S, const G2 R){
    this->S = S;
    this->R = R;
  }

  void initIDNIKS(){
    // initPairing(mcl::BN462);
    initPairing(mcl::BN381_1);
    // initPairing(mcl::BN381_2);
    // initPairing(mcl::BN254);
  }
}
