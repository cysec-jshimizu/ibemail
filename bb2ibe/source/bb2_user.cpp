#include "bb2.hpp"
#include <mpz_util.hpp>
#include <string>
#include <stdexcept>
#include <openssl/sha.h>

#define EMBEDDED_DEGREE 12

using namespace mcl::bn256;

namespace BB2{
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
    if(n < msg.size()) throw std::invalid_argument("BB2::User::encrypt: n less than sizeof msg");

    //padding
    unsigned int pad = 0;
    if(withPadding){
      pad = n - msg.size();
      if(pad > UCHAR_MAX || (pad == 0 && n > UCHAR_MAX)) throw std::runtime_error("BB2::User::encrypt: too large padding");
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

    //hash(id)
    std::vector<unsigned char> id_hash(SHA256_DIGEST_LENGTH, 0);
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, id.data(), id.size());
    SHA256_Final(id_hash.data(), &sha256);
    //id: bytes to mpz_class
    mpz_class id_mpz;
    mpzUtil::bytesToMpz(id_mpz, id_hash);
    //id: mpz_class to Fr
    mpz_class mod(Fr::getModulo());
    id_mpz %= mod;
    Fr id_fp(id_mpz.get_str());

    //choice s random
    mpz_class rnds;
    mpz_class modFr(Fr::getModulo());
    mpzUtil::mpzRandDevice(rnds, modFr);
    Fr s(rnds.get_str());

    //encrypt
    //a = m `xor` hash(canonical(v^s))
    Fp12 vs;
    Fp12::pow(vs, params.v, s);
    std::vector<unsigned char> can;
    canonical(can, vs, 0);
    mpz_class hash;
    mpz_class bytelen;
    mpz_ui_pow_ui(bytelen.get_mpz_t(), UCHAR_MAX+1, n);
    hashToRange(hash, can, bytelen);
    mpz_class cipher = m_mpz ^ hash;
    std::vector<unsigned char> a;
    mpzUtil::mpzToBytes(a, cipher, n);

    //B = sY
    G1 B;
    G1::mul(B, params.Y, s);

    //C = sX + (s*id)G
    Fr sid;
    Fr::mul(sid, s, id_fp);
    G1 sX;
    G1::mul(sX, params.X, s);
    G1 sidG;
    G1::mul(sidG, params.G, sid);
    G1 C;
    G1::add(C, sX, sidG);

    return {a, B, C};
  }

  Cipher User::encrypt(const std::vector<unsigned char> &msg, const std::string &id, const KGCParams &params, bool withPadding){
    return encrypt(msg, id, params, msg.size(), withPadding);
  }

  Cipher User::encrypt(const std::vector<unsigned char> &msg, const std::string &id, size_t n, bool withPadding) const{
    if(!belong) throw std::runtime_error("BB2::User::encrypt: user don't belong to any KGC");
    return encrypt(msg, id, this->params, n, withPadding);
  }

  Cipher User::encrypt(const std::vector<unsigned char> &msg, const std::string &id, bool withPadding) const{
    if(!belong) throw std::runtime_error("BB2::User::encrypt: user don't belong to any KGC");
    return encrypt(msg, id, this->params, msg.size(), withPadding);
  }

  std::vector<unsigned char> User::decrypt(const Cipher &c, size_t n, bool withPadding) const{
    if(!belong) throw std::runtime_error("BB2::User::decrypt: user don't have key");

    std::vector<unsigned char> a = c.a;
    G1 B = c.B;
    G1 C = c.C;

    Fr r = this->decKey.r;
    G2 K = this->decKey.K;

    //e(rB + C, K) = v^s
    G1 left;
    G1::mul(left, B, r);
    G1::add(left, left, C);
    Fp12 vs;
    pairing(vs, left, K);

    //a `xor` hash(canonical(v^s)) = m
    std::vector<unsigned char> can;
    canonical(can, vs);
    mpz_class bytelen;
    mpz_ui_pow_ui(bytelen.get_mpz_t(), UCHAR_MAX+1, n);
    mpz_class hash;
    hashToRange(hash, can, bytelen);
    mpz_class a_mpz;
    mpzUtil::bytesToMpz(a_mpz, a);
    mpz_class p_mpz = a_mpz ^ hash;
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
    return decrypt(c, c.a.size(), withPadding);
  }
}
