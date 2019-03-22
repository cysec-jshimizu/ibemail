#include "bb2.hpp"
#include <mpz_util.hpp>
#include <vector>
#include <random>
#include <string>
#include <openssl/sha.h>

using namespace mcl::bn256;

namespace BB2{
  KGC::KGC(bool set){
    if(set){
      setup();
    } else {
      this->set = false;
      this->params = KGCParams();
      this->masterKey = KGCMasterKey();
    }
  }

  KGC::KGC(const KGCParams params, const KGCMasterKey masterKey){
    this->set = true;
    this->params = params;
    this->masterKey = masterKey;
  }

  void KGC::setup(){
    this->set = true;

    G1 G;
    mpz_class rndG_mpz;
    mpz_class modG1(G1::BaseFp::getModulo());
    mpzUtil::mpzRandDevice(rndG_mpz, modG1);
    Fp rndG(rndG_mpz.get_str());
    mapToG1(G, rndG);

    G2 H;
    mpz_class rndH_mpz1;
    mpz_class rndH_mpz2;
    mpz_class modG2(G2::BaseFp::BaseFp::getModulo());
    mpzUtil::mpzRandDevice(rndH_mpz1, modG2);
    mpzUtil::mpzRandDevice(rndH_mpz2, modG2);
    Fp2 rndH(rndH_mpz1.get_str(), rndH_mpz2.get_str());
    mapToG2(H, rndH);

    Fr x;
    Fr y;
    x.setRand();
    y.setRand();

    G1 X;
    G1::mul(X, G, x);
    G1 Y;
    G1::mul(Y, G, y);

    Fp12 v;
    pairing(v, G, H);

    this->params = {G, X, Y, v};
    this->masterKey = {x, y, H};
  }

  UserKey KGC::genUserKey(const std::string &id) const{
    if(!set) throw std::runtime_error("BB2::KGC::genUserKey: KGC not setup");

    //hash(id)
    std::vector<unsigned char> id_hash(SHA256_DIGEST_LENGTH, 0);
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, id.data(), id.size());
    SHA256_Final(id_hash.data(), &sha256);

    //id: bytes to Fr
    mpz_class id_mpz;
    mpzUtil::bytesToMpz(id_mpz, id_hash);
    mpz_class mod(Fr::getModulo());
    id_mpz %= mod;
    Fr id_fp(id_mpz.get_str());

    Fr r;
    Fr x = this->masterKey.x;
    Fr y = this->masterKey.y;
    G2 H = this->masterKey.H;

    //choice r random where x+ry+id != 0
    Fr tmp(x+id_fp);
    do {
      mpz_class rndr;
      mpz_class modFr(Fr::getModulo());
      mpzUtil::mpzRandDevice(rndr, modFr);
      r.setMpz(rndr);
    }while(tmp + r*y == 0);

    //K = H^(1/(x+ry+id))
    Fr inv;
    Fr::inv(inv, tmp + r*y);
    G2 K;
    G2::mul(K, H, inv);

    return {r, K};
  }
}
