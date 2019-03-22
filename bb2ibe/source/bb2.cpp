#include "bb2.hpp"

using namespace mcl::bn256;

namespace BB2{
  KGCParams::KGCParams(const G1 G, const G1 X, const G1 Y, const Fp12 v){
    this->G = G;
    this->X = X;
    this->Y = Y;
    this->v = v;
  }

  bool KGCParams::operator==(const KGCParams &params) const{
    return this->G==params.G && this->X==params.X && this->Y==params.Y && this->v==params.v;
  }

  KGCMasterKey::KGCMasterKey(const Fr x, const Fr y, const G2 H){
    this->x = x;
    this->y = y;
    this->H = H;
  }

  UserKey::UserKey(const Fr r, const G2 K){
    this->r = r;
    this->K = K;
  }

  Cipher::Cipher(const std::vector<unsigned char> a, const G1 B, const G1 C){
    this->a = a;
    this->B = B;
    this->C = C;
  }

  void initBB2(){
    mcl::bn256::initPairing();
  }
}
