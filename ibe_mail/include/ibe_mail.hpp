#ifndef _INC_IBEMAIL
#define _INC_IBEMAIL

#include <bb2.hpp>
#include <openssl/evp.h>
#include <openssl/bio.h>


namespace IBEMail{
  const std::string VERSION = "1.0";
  const std::string ALGOLITHM = "bb2";
  const std::string CURVE = "bn381";
  const size_t FP_SIZE = 32;

  struct IBEParams : public BB2::KGCParams{
    IBEParams() = default;
    IBEParams(const BB2::KGCParams params) : BB2::KGCParams(params){};
    IBEParams(const mcl::bn384::G1 G, const mcl::bn384::G1 X, const mcl::bn384::G1 Y, mcl::bn384::Fp12 v) : BB2::KGCParams(G, X, Y, v){};

    std::string getRecode(int num=1) const;
    int setRecode(const std::string &recode);
    int fromDNS(const std::string &domain);
  };

  struct IBEMasterKey : public BB2::KGCMasterKey{
    IBEMasterKey() = default;
    IBEMasterKey(const BB2::KGCMasterKey masterKey) : BB2::KGCMasterKey(masterKey){};
    IBEMasterKey(const mcl::bn384::Fr x, const mcl::bn384::Fr y, const mcl::bn384::G2 H) : BB2::KGCMasterKey(x, y, H){};

    std::string getBase64() const;
    int setBase64(const std::string b64);
  };

  struct IBEUserKey : public BB2::UserKey{
    IBEUserKey() = default;
    IBEUserKey(const BB2::UserKey userKey) : BB2::UserKey(userKey){};
    IBEUserKey(const mcl::bn384::Fr r, const mcl::bn384::G2 K) : BB2::UserKey(r, K){};

    std::string getBase64() const;
    int setBase64(const std::string b64);
  };

  struct IBECipher : public BB2::Cipher{
    IBECipher() = default;
    IBECipher(const BB2::Cipher cipher) : BB2::Cipher(cipher){};
    IBECipher(const std::vector<unsigned char> a, const mcl::bn384::G1 B, const mcl::bn384::G1 C) : BB2::Cipher(a, B, C){};

    std::string getBase64() const;
    int setBase64(const std::string b64);
  };


  class MailKGC : public BB2::KGC{
    private:

    public:
      MailKGC(bool set=true) : BB2::KGC(set){};
      MailKGC(const IBEParams params, const IBEMasterKey masterKey) : BB2::KGC(params, masterKey){};
  };

  class MailUser : public BB2::User{
    private:
      static std::vector<unsigned char> genIV(size_t len=12);

    public:
      MailUser() : BB2::User(){};
      MailUser(const std::string id, const IBEParams params) : BB2::User(id, params){};
      MailUser(const std::string id, const IBEParams params, const IBEUserKey decKey) : BB2::User(id, params, decKey){};

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

  };

  void initIBEMail();

  void G1ToBytes(std::vector<unsigned char> &bytes, const mcl::bn384::G1 &g1);
  void G2ToBytes(std::vector<unsigned char> &bytes, const mcl::bn384::G2 &g2);
  void Fp12ToBytes(std::vector<unsigned char> &bytes, const mcl::bn384::Fp12 &fp12);

  void G1FromBytes(mcl::bn384::G1 &g1, const std::vector<unsigned char> &bytes);
  void G2FromBytes(mcl::bn384::G2 &g2, const std::vector<unsigned char> &bytes);
  void Fp12FromBytes(mcl::bn384::Fp12 &fp12, const std::vector<unsigned char> &bytes);

  void G1EncodeBase64(std::string &enc, const mcl::bn384::G1 &g1);
  void G2EncodeBase64(std::string &enc, const mcl::bn384::G2 &g2);
  void Fp12EncodeBase64(std::string &enc, const mcl::bn384::Fp12 &fp12);

  void G1DecodeBase64(mcl::bn384::G1 &g1, const std::string &enc);
  void G2DecodeBase64(mcl::bn384::G2 &g2, const std::string &enc);
  void Fp12DecodeBase64(mcl::bn384::Fp12 &fp12, const std::string &enc);
}

#endif
