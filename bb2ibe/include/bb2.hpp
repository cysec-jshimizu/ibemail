#ifndef _INC_BB2
#define _INC_BB2

#include <mcl/bn256.hpp>

namespace BB2{
  struct KGCParams{
    mcl::bn256::G1 G;
    mcl::bn256::G1 X;
    mcl::bn256::G1 Y;
    mcl::bn256::Fp12 v;

    KGCParams() = default;
    KGCParams(const mcl::bn256::G1 G, const mcl::bn256::G1 X, const mcl::bn256::G1 Y, const mcl::bn256::Fp12 v);

    bool operator==(const KGCParams &params) const;
  };

  struct KGCMasterKey{
    mcl::bn256::Fr x;
    mcl::bn256::Fr y;
    mcl::bn256::G2 H;

    KGCMasterKey() = default;
    KGCMasterKey(const mcl::bn256::Fr x, const mcl::bn256::Fr y, const mcl::bn256::G2 H);
  };

  struct UserKey{
    mcl::bn256::Fr r;
    mcl::bn256::G2 K;

    UserKey() = default;
    UserKey(const mcl::bn256::Fr r, const mcl::bn256::G2 K);
  };

  struct Cipher{
    std::vector<unsigned char> a;
    mcl::bn256::G1 B;
    mcl::bn256::G1 C;

    Cipher() = default;
    Cipher(const std::vector<unsigned char> a, const mcl::bn256::G1 B, const mcl::bn256::G1 C);
  };

  class KGC{
    private:
      KGCParams params;
      KGCMasterKey masterKey;
      bool set;

    public:
      KGC(bool set=true);
      KGC(const KGCParams params, const KGCMasterKey masterKey);
      void setup();
      UserKey genUserKey(const std::string &id) const;
      void setParams(KGCParams params){ this->params = params; };
      void setMasterKey(KGCMasterKey masterKey){ this->masterKey = masterKey; };
      KGCParams getParams() const{ return params; };
      KGCMasterKey getMasterKey() const{ return masterKey; };
      bool isSet() const{ return set; }
  };

  class User{
    private:
      std::string id;
      KGCParams params;
      UserKey decKey;
      bool belong;
    public:
      User();
      User(const std::string id, const KGCParams params);
      User(const std::string id, const KGCParams params, const UserKey decKey);
      void belongKGC(const std::string id, const KGCParams params, const UserKey decKey);
      static Cipher encrypt(const std::vector<unsigned char> &msg, const std::string &id, const KGCParams &params, size_t n, bool withPadding=true);
      static Cipher encrypt(const std::vector<unsigned char> &msg, const std::string &id, const KGCParams &params, bool withPadding=false);
      Cipher encrypt(const std::vector<unsigned char> &msg, const std::string &id, size_t n, bool withPadding=true) const;
      Cipher encrypt(const std::vector<unsigned char> &msg, const std::string &id, bool withPadding=false) const;
      std::vector<unsigned char> decrypt(const Cipher &c, size_t n, bool withPadding=true) const;
      std::vector<unsigned char> decrypt(const Cipher &c, bool withPadding=false) const;
      std::string getId() const{ return id; };
      UserKey getUserKey() const{ return decKey; };
      bool isBelong() const{ return belong; };
  };

  void initBB2();

  void canonical(std::vector<unsigned char>& s, const mcl::bn256::Fp12 &v, int o=0);

  void hashToRange(mpz_class& v, const std::vector<unsigned char> &s, const mpz_class &n);
}

#endif
