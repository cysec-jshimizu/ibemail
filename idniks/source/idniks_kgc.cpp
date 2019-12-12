#include "idniks.hpp"
#include <mpz_util.hpp>
#include <vector>
#include <random>
#include <string>
#include <openssl/sha.h>

// using namespace mcl::bn256;
using namespace mcl::bn384;

namespace IDNIKS{
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

    G1 P;
    mpz_class rndP_mpz;
    mpz_class modG1(G1::BaseFp::getModulo());
    mpzUtil::mpzRandDevice(rndP_mpz, modG1);
    Fp rndP(rndP_mpz.get_str());
    mapToG1(P, rndP);

    G2 Q;
    mpz_class rndQ_mpz1;
    mpz_class rndQ_mpz2;
    mpz_class modG2(G2::BaseFp::BaseFp::getModulo());
    mpzUtil::mpzRandDevice(rndQ_mpz1, modG2);
    mpzUtil::mpzRandDevice(rndQ_mpz2, modG2);
    Fp2 rndQ(rndQ_mpz1.get_str(), rndQ_mpz2.get_str());
    mapToG2(Q, rndQ);

    Fr l;
    l.setRand();

    G2 lQ;
    G2::mul(lQ, Q, l);

    this->params = {P, Q, lQ};
    this->masterKey = {l};
  }

  UserKey KGC::genUserKey(const std::string &id) const{
    if(!set) throw std::runtime_error("IDNIKS::KGC::genUserKey: KGC not setup");

    G1 P = this->params.P;
    Fr l = this->masterKey.l;

    // Pu : h(id)P
    G1 Pu;

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

    G1::mul(Pu, P, id_fp);

    // Ku : lPu
    // l : MasterSecretKey
    G1 Ku;
    G1::mul(Ku, Pu, l);

    return {Ku};
  }
}
