#include "idniks.hpp"
#include <mpz_util.hpp>
#include <string>
#include <stdexcept>
#include <openssl/sha.h>

#define EMBEDDED_DEGREE 12

using namespace mcl::bn256;
// using namespace mcl::bn384;

namespace IDNIKS{
  //Fp12 -> bytes
  void canonical(std::vector<unsigned char> &s, const Fp12 &v, int o){
    mpz_class p(Fp::getModulo());
    size_t l = (mpz_sizeinbase(p.get_mpz_t(), 2) + CHAR_BIT - 1) / CHAR_BIT;

    Fp6 va = v.a;
    Fp6 vb = v.b;

    int n = EMBEDDED_DEGREE / 2;
    Fp2 v2[n];
    v2[0] = va.a;
    v2[1] = va.b;
    v2[2] = va.c;
    v2[3] = vb.a;
    v2[4] = vb.b;
    v2[5] = vb.c;

    //s = reduce(add , v)
    s.resize(l * EMBEDDED_DEGREE, 0);
    if(!s.empty()) s.clear();

    if(o != -1){
      for(int i = 0; i < n; i++){
        std::vector<unsigned char> a;
        std::vector<unsigned char> b;
        mpzUtil::mpzToBytes(a, v2[i].a.getMpz(), l, o);
        mpzUtil::mpzToBytes(b, v2[i].b.getMpz(), l, o);

        std::copy(a.begin(), a.end(), std::back_inserter(s));
        std::copy(b.begin(), b.end(), std::back_inserter(s));
      }
    } else {
      for(int i = n-1; i >= 0; i--){
        std::vector<unsigned char> a;
        std::vector<unsigned char> b;
        mpzUtil::mpzToBytes(a, v2[i].a.getMpz(), l, o);
        mpzUtil::mpzToBytes(b, v2[i].b.getMpz(), l, o);

        std::copy(b.begin(), b.end(), std::back_inserter(s));
        std::copy(a.begin(), a.end(), std::back_inserter(s));
      }
    }
  }

  //{0,1}^* -> Zn
  void hashToRange(mpz_class &v, const std::vector<unsigned char> &s, mpz_class &n){
    mpz_set_ui(v.get_mpz_t(), 0);
    std::vector<unsigned char> h(SHA256_DIGEST_LENGTH, 0);
    mpz_class bit256;
    mpz_ui_pow_ui(bit256.get_mpz_t(), UCHAR_MAX+1, SHA256_DIGEST_LENGTH);

    size_t l = std::max((size_t)2, (mpz_sizeinbase(n.get_mpz_t(), UCHAR_MAX+1) + SHA256_DIGEST_LENGTH - 1) / SHA256_DIGEST_LENGTH);
    for(unsigned int i = 0; i < l; i++){
      //h = h+s
      std::copy(s.begin(), s.end(), std::back_inserter(h));

      //hash = sha256(h)
      std::vector<unsigned char> hash(SHA256_DIGEST_LENGTH, 0);
      SHA256_CTX sha256;
      SHA256_Init(&sha256);
      SHA256_Update(&sha256, h.data(), h.size());
      h.resize(SHA256_DIGEST_LENGTH, 0);
      SHA256_Final(h.data(), &sha256);

      mpz_class a;
      mpzUtil::bytesToMpz(a, h);

      v = (bit256*v + a) % n;
    }
  }


  User::User(){
    this->belong = false;
    this->id = "";
    this->decKey = UserKey();
  }

  User::User(const std::string id, const KGCParams params){
    this->belong = false;
    this->id = id;
    this->params = params;
    this->decKey = UserKey();
  }

  User::User(const std::string id, const KGCParams params, const UserKey decKey){
    this->belong = true;
    this->id = id;
    this->params = params;
    this->decKey = decKey;
  }

  void User::belongKGC(const std::string id, const KGCParams params, const UserKey decKey){
    this->belong = true;
    this->id = id;
    this->params = params;
    this->decKey = decKey;
  }

  Cipher User::encrypt(const std::vector<unsigned char> &msg, const std::string &id, const KGCParams &params, size_t n, bool withPadding){
    if(n < msg.size()) throw std::invalid_argument("IDNIKS::User::encrypt: n less than sizeof msg");

    //padding
    unsigned int pad = 0;
    if(withPadding){
      pad = n - msg.size();
      if(pad > UCHAR_MAX || (pad == 0 && n > UCHAR_MAX)) throw std::runtime_error("IDNIKS::User::encrypt: too large padding");
      if(pad == 0){
        pad = n;
        n *= 2;
      }
    }
    std::vector<unsigned char> m(n, pad);
    std::copy(msg.begin(), msg.end(), m.begin());

    //m: bytes to mpz_class
    mpz_class m_mpz;
    mpzUtil::bytesToMpz(m_mpz, m);

    //choice r random
    mpz_class rndr;
    mpz_class modFr(Fr::getModulo());
    mpzUtil::mpzRandDevice(rndr, modFr);
    Fr r(rndr.get_str());

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
    Fr id_fr(id_mpz.get_str());

    //encrypt
    // C1 = rQ
    G2 C1;
    G2::mul(C1, params.Q, r);

    // C2 = m `xor` e(Pu, r*lQ)
    //    = m `xor` e(Pu, Q)^rl
    std::vector<unsigned char> C2;
    // Pu : h(id)P
    G1 Pu;
    G1::mul(Pu, params.P, id_fr);
    // rlQ
    G2 rlQ;
    G2::mul(rlQ, params.lQ, r);
    // pairing
    Fp12 e;
    pairing(e, Pu, rlQ);
    // canonical e
    std::vector<unsigned char> can;
    canonical(can, e, 0);
    mpz_class hash;
    mpz_class bytelen;
    mpz_ui_pow_ui(bytelen.get_mpz_t(), UCHAR_MAX+1, n);
    hashToRange(hash, can, bytelen);
    mpz_class cipher = m_mpz ^ hash;
    // C2
    mpzUtil::mpzToBytes(C2, cipher, n);


    return {C1, C2};
  }

  Cipher User::encrypt(const std::vector<unsigned char> &msg, const std::string &id, const KGCParams &params, bool withPadding){
    return encrypt(msg, id, params, msg.size(), withPadding);
  }

  Cipher User::encrypt(const std::vector<unsigned char> &msg, const std::string &id, size_t n, bool withPadding) const{
    if(!belong) throw std::runtime_error("IDNIKS::User::encrypt: user don't belong to any KGC");
    return encrypt(msg, id, this->params, n, withPadding);
  }

  Cipher User::encrypt(const std::vector<unsigned char> &msg, const std::string &id, bool withPadding) const{
    if(!belong) throw std::runtime_error("IDNIKS::User::encrypt: user don't belong to any KGC");
    return encrypt(msg, id, this->params, msg.size(), withPadding);
  }

  std::vector<unsigned char> User::decrypt(const Cipher &c, size_t n, bool withPadding) const{
    if(!belong) throw std::runtime_error("IDNIKS::User::decrypt: user don't have key");

    // decrypto
    // m = C2 `xor` e(Ku,C1)
    //   = C2 `xor` e(Pu,Q)^lr `xor` e(l*Pu, r*Q)
    G2 C1 = c.C1;
    std::vector<unsigned char> C2 = c.C2;

    G1 Ku = this->decKey.Ku;
    // pairing
    Fp12 e;
    pairing(e, Ku, C1);

    //C2 `xor` e = m
    std::vector<unsigned char> can;
    canonical(can, e);
    mpz_class hash;
    mpz_class bytelen;
    mpz_ui_pow_ui(bytelen.get_mpz_t(), UCHAR_MAX+1, n);
    hashToRange(hash, can, bytelen);
    mpz_class C2_mpz;
    mpzUtil::bytesToMpz(C2_mpz, C2);
    mpz_class p_mpz = C2_mpz ^ hash;
    std::vector<unsigned char> p;
    mpzUtil::mpzToBytes(p, p_mpz, n);

    //check padding
    if(withPadding){
     unsigned char pad = p.back();
      for(int i = 0; i < pad; i++){
        if(p.back() != pad) return p;
        p.pop_back();
      }
    }

    return p;
  }

  std::vector<unsigned char> User::decrypt(const Cipher &c, bool withPadding) const{
    return decrypt(c, c.C2.size(), withPadding);
  }

  Signature User::signature(const std::vector<unsigned char> &msg) const{
    if(!belong) throw std::runtime_error("IDNIKS::User::signature: user don't have key");

    //hash(id)
    std::vector<unsigned char> id_hash(SHA256_DIGEST_LENGTH, 0);
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, this->id.data(), this->id.size());
    SHA256_Final(id_hash.data(), &sha256);
    //id: bytes to Fr
    mpz_class id_mpz;
    mpzUtil::bytesToMpz(id_mpz, id_hash);
    mpz_class mod(Fr::getModulo());
    id_mpz %= mod;
    Fr id_fp(id_mpz.get_str());
    // Pu : h(id)P
    G1 Pu;
    G1::mul(Pu, params.P, id_fp);

    //choice k random
    mpz_class rndk;
    mpz_class modFr(Fr::getModulo());
    mpzUtil::mpzRandDevice(rndk, modFr);
    Fr k(rndk.get_str());

    // R = k*Q
    G2 R;
    G2::mul(R, this->params.Q, k);

    //hash(msg)
    std::vector<unsigned char> msg_hash(SHA256_DIGEST_LENGTH, 0);
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, msg.data(), msg.size());
    SHA256_Final(msg_hash.data(), &sha256);
    //msg: bytes to Fr
    mpz_class msg_mpz;
    mpzUtil::bytesToMpz(msg_mpz, msg_hash);
    msg_mpz %= mod;
    Fr msg_fr(msg_mpz.get_str());
    // h(m)/k
    Fr a;
    Fr::div(a, msg_fr, k);  
    // a*Pu
    G1 aPu;
    G1::mul(aPu, Pu, a);
    
    // R.x/k
    Fr x(R.x.getStr());
    Fr b;
    Fr::div(b, x, k);
    // b*Ku
    G1 bKu;
    G1::mul(bKu, this->decKey.Ku, b);

    // S = aPu - bKu
    G1 S;
    // G1::sub(S, aPu, bKu);
    G1::add(S, aPu, bKu);

    return {S, R};
  }

  bool User::verification(const std::vector<unsigned char> &msg, const std::string &id, const KGCParams &params, Signature &sign){
    // verification
    // e(S, R) == e(Pu, Q)^h(m) * e(Pu, lQ)^x
    // x = R.x
    // sign_fp12 == verify_fp12
    // verify_fp12 = verify_fp12_a * verify_fp12_b

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
    // Pu : h(id)P
    G1 Pu;
    G1::mul(Pu, params.P, id_fp);

    // e(S, R)
    Fp12 sign_fp12;
    pairing(sign_fp12, sign.S, sign.R);

    // e(Pu, Q)^h(msg) * e(Pu, lQ)^x
    // verify_fp12_a * verify_fp12_b = verify_fp12
    Fp12 verify_fp12;
    Fp12 verify_fp12_a;
    Fp12 verify_fp12_b;

    // verify_fp12_a = e(Pu, Q)^h(msg)
    //               = e(Pu, h(msg)*Q)
    // hash(msg)
    std::vector<unsigned char> msg_hash(SHA256_DIGEST_LENGTH, 0);
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, msg.data(), msg.size());
    SHA256_Final(msg_hash.data(), &sha256);
    //msg: bytes to Fr
    mpz_class msg_mpz;
    mpzUtil::bytesToMpz(msg_mpz, msg_hash);
    msg_mpz %= mod;
    Fr msg_fr(msg_mpz.get_str());
    // hQ : h(msg)Q
    G2 hQ;
    G2::mul(hQ, params.Q, msg_fr);
    // pairing (Pu, Q^h(msg))
    pairing(verify_fp12_a, Pu, hQ);

    // verify_fp12_b = e(Pu, lQ)^x
    //               = e(Pu, x*lQ)
    // xlQ : x*lQ
    // x = R.x
    Fr x(sign.R.x.getStr());
    G2 xlQ;
    G2::mul(xlQ, params.lQ, x);
    // pairing (Pu, xlQ)
    pairing(verify_fp12_b, Pu, xlQ);

    // verify_fp12 = verify_fp12_a * verify_fp12_b
    Fp12::mul(verify_fp12, verify_fp12_a, verify_fp12_b);

    // if(e(S, R) == e(Pu, Q)^h(m) * e(Pu, lQ)^x) ? true : false
    return (sign_fp12 == verify_fp12);
  }
}
