#ifndef _INC_IDNIKS
#define _INC_IDNIKS

#include <mcl/bn384.hpp>
#include <openssl/sha.h>

namespace IDNIKS{
  struct KGCParams{
    mcl::bn384::G1 P;
    mcl::bn384::G2 Q;
    mcl::bn384::G2 lQ;

    KGCParams() = default;
    KGCParams(const mcl::bn384::G1 P, const mcl::bn384::G2 Q, const mcl::bn384::G2 lQ);

    bool operator==(const KGCParams &params) const;
  };

  struct KGCMasterKey{
    mcl::bn384::Fr l;

    KGCMasterKey() = default;
    KGCMasterKey(const mcl::bn384::Fr l);
  };

  struct UserKey{
    mcl::bn384::G1 Ku;

    UserKey() = default;
    UserKey(const mcl::bn384::G1 Ku);
  };

  struct Cipher{
    mcl::bn384::G2 C1;
    std::vector<unsigned char> C2;

    Cipher() = default;
    Cipher(const mcl::bn384::G2 C1, const std::vector<unsigned char> C2);
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

  void initIDNIKS();

  void canonical(std::vector<unsigned char>& s, const mcl::bn384::Fp12 &v, int o=0);

  void hashToRange(mpz_class& v, const std::vector<unsigned char> &s, const mpz_class &n);
}

#endif
