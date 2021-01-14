#ifndef _INC_IBEMAIL
#define _INC_IBEMAIL

#include <idniks.hpp>
#include <openssl/evp.h>
#include <openssl/bio.h>


namespace IBEMail{
  const std::string VERSION = "1.0";
  const std::string ALGOLITHM = "IDNIKS";
  const std::string CURVE = "bn254";
  const int n = 1;
  // 256 -> 32 ; 384 -> 48;
  const size_t FP_SIZE = 32;

  struct IBEParams : public IDNIKS::KGCParams{
    IBEParams() = default;
    IBEParams(const IDNIKS::KGCParams params) : IDNIKS::KGCParams(params){};
    IBEParams(const G1 P, const G2 Q, const G2 lQ) : IDNIKS::KGCParams(P, Q, lQ){};

    std::string getRecode(int num=1) const;
    int setRecode(const std::string &recode);
    int fromDNS(const std::string &domain);
  };

  struct IBEMasterKey : public IDNIKS::KGCMasterKey{
    IBEMasterKey() = default;
    IBEMasterKey(const IDNIKS::KGCMasterKey masterKey) : IDNIKS::KGCMasterKey(masterKey){};
    IBEMasterKey(const Fr l) : IDNIKS::KGCMasterKey(l){};

    std::string getBase64() const;
    int setBase64(const std::string b64);
  };

  struct IBEUserKey : public IDNIKS::UserKey{
    IBEUserKey() = default;
    IBEUserKey(const IDNIKS::UserKey userKey) : IDNIKS::UserKey(userKey){};
    IBEUserKey(const G1 Ku) : IDNIKS::UserKey(Ku){};

    std::string getBase64() const;
    int setBase64(const std::string b64);
  };

  struct IBECipher : public IDNIKS::Cipher{
    IBECipher() = default;
    IBECipher(const IDNIKS::Cipher cipher) : IDNIKS::Cipher(cipher){};
    IBECipher(const G2 C1, const std::vector<unsigned char> C2) : IDNIKS::Cipher(C1, C2){};

    std::string getBase64() const;
    int setBase64(const std::string b64);
  };

  struct IBESignature : public IDNIKS::Signature{
    IBESignature() = default;
    IBESignature(const IDNIKS::Signature signature) : IDNIKS::Signature(signature){};
    IBESignature(const G1 S, const G2 R) : IDNIKS::Signature(S, R){};

    std::string getBase64() const;
    int setBase64(const std::string b64);
  };

  class MailKGC : public IDNIKS::KGC{
    private:

    public:
      MailKGC(bool set=true) : IDNIKS::KGC(set){};
      MailKGC(const IBEParams params, const IBEMasterKey masterKey) : IDNIKS::KGC(params, masterKey){};
  };

  class MailUser : public IDNIKS::User{
    private:
      static std::vector<unsigned char> genIV(size_t len=12);

    public:
      MailUser() : IDNIKS::User(){};
      MailUser(const std::string id, const IBEParams params) : IDNIKS::User(id, params){};
      MailUser(const std::string id, const IBEParams params, const IBEUserKey decKey) : IDNIKS::User(id, params, decKey){};

      static int encryptAEAD(const EVP_CIPHER *cipher, const std::vector<unsigned char> &key, const std::vector<unsigned char> &iv,
          const std::vector<unsigned char> &aad, std::ostream &dst, std::istream &src);
      static int encryptAEAD(const EVP_CIPHER *cipher, const std::vector<unsigned char> &key,
          const std::vector<unsigned char> &aad, std::ostream &dst, std::istream &src);
      //static int encryptAEAD(const EVP_CIPHER *cipher, const std::vector<unsigned char> &key, const std::vector<unsigned char> &iv,
      //    const std::vector<unsigned char> &aad, BIO *dst, BIO *src);
      static int decryptAEAD(const EVP_CIPHER *cipher, const std::vector<unsigned char> &key, const std::vector<unsigned char> &iv,
          const std::vector<unsigned char> &aad, std::ostream &dst, std::istream &src);
      //static int decryptAEAD(const EVP_CIPHER *cipher, const std::vector<unsigned char> &key, const std::vector<unsigned char> &iv,
      //    const std::vector<unsigned char> &aad, BIO *dst, BIO *src);

      static int encryptHybrid(const std::string &id, const IBEParams &params, const EVP_CIPHER *cipher, const std::vector<unsigned char> &key,
          const std::vector<unsigned char> &iv, const std::vector<unsigned char> &aad, std::ostream &dst, std::istream &src);
      static int encryptHybrid(const std::string &id, const IBEParams &params, const EVP_CIPHER *cipher, const std::vector<unsigned char> &key,
          const std::vector<unsigned char> &aad, std::ostream &dst, std::istream &src);
      //static int encryptHybrid(const std::string &id, const IBEParams &params, const EVP_CIPHER *cipher, const std::vector<unsigned char> &key,
      //    const std::vector<unsigned char> &iv, const std::vector<unsigned char> &aad, BIO *dst, BIO *src);
      //int decryptHybrid(const EVP_CIPHER *cipher, BIO *dst, BIO *src) const;
      int decryptHybrid(const EVP_CIPHER *cipher, std::ostream &dst, std::istream &src) const;

      static int encryptMail(const std::string &id, const IBEParams &params, const EVP_CIPHER *cipher, const std::vector<unsigned char> &key,
          const std::vector<unsigned char> &iv, const std::vector<unsigned char> &aad, std::ostream &dst, std::istream &src);
      static int encryptMail(const std::string &id, const IBEParams &params, const EVP_CIPHER *cipher, const std::vector<unsigned char> &key,
          const std::vector<unsigned char> &aad, std::ostream &dst, std::istream &src);
      static int encryptMail(const EVP_CIPHER *cipher, const std::vector<unsigned char> &key, const std::vector<unsigned char> &iv,
          const std::vector<unsigned char> &aad, std::ostream &dst, std::istream &src);
      static int encryptMail(const EVP_CIPHER *cipher, const std::vector<unsigned char> &key,
          const std::vector<unsigned char> &aad, std::ostream &dst, std::istream &src);
      int decryptMail(const EVP_CIPHER *cipher, std::ostream &dst, std::istream &src) const;

      std::string sign(const std::vector<unsigned char> &msg) const;
      int signMail(std::ostream &dst, std::istream &src);
      static bool verify(const std::vector<unsigned char> &msg, const std::string &address, const std::string &domain, const std::string &sign);
      static int verifyMail(std::ostream &dst, std::istream &src);
  };

  void initIBEMail();

  void G1ToBytes(std::vector<unsigned char> &bytes, const G1 &g1);
  void G2ToBytes(std::vector<unsigned char> &bytes, const G2 &g2);
  void Fp12ToBytes(std::vector<unsigned char> &bytes, const Fp12 &fp12);

  void G1FromBytes(G1 &g1, const std::vector<unsigned char> &bytes);
  void G2FromBytes(G2 &g2, const std::vector<unsigned char> &bytes);
  void Fp12FromBytes(Fp12 &fp12, const std::vector<unsigned char> &bytes);

  void G1EncodeBase64(std::string &enc, const G1 &g1);
  void G2EncodeBase64(std::string &enc, const G2 &g2);
  void Fp12EncodeBase64(std::string &enc, const Fp12 &fp12);

  void G1DecodeBase64(G1 &g1, const std::string &enc);
  void G2DecodeBase64(G2 &g2, const std::string &enc);
  void Fp12DecodeBase64(Fp12 &fp12, const std::string &enc);
}

#endif
