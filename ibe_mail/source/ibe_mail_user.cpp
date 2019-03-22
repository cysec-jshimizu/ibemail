#include "ibe_mail.hpp"
#include <mpz_util.hpp>
#include <base64.hpp>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <iostream>
#include <fstream>
#include <stdexcept>
#include <time.h>
#include <random>

#include <mimetic/mimetic.h>
#include <mimetic/utils.h>

using namespace mcl::bn256;
using namespace std;

namespace IBEMail{
  const int tag_len = 16;

  //generate IV
  vector<unsigned char> MailUser::genIV(size_t len){
    vector<unsigned char> iv(len, 0);
    time_t now;
    now = time(NULL);
    memcpy(&iv[0], &now, min(len, sizeof(time_t)));

    if(len <= sizeof(time_t)){
      return iv;
    }

    size_t pos = sizeof(time_t);
    random_device rng;
    while(pos < len){
      unsigned int rand = rng();
      int l = min(len-pos, sizeof(int));
      memcpy(&iv[pos], &rand, l);
      pos += l;
    }

    return iv;
  }


  //encrypt AEAD return write length
  int MailUser::encryptAEAD(const EVP_CIPHER *cipher, const vector<unsigned char> &key, const vector<unsigned char> &iv, const vector<unsigned char> &aad, ostream &dst, istream &src){
    EVP_CIPHER_CTX *ctx;

    if(!(ctx = EVP_CIPHER_CTX_new())) throw runtime_error("IBEMail::MailUser::encryptAEAD: EVP_CIPHER_CTX_new");

    if(1 != EVP_EncryptInit_ex(ctx, cipher, NULL, NULL, NULL)) throw runtime_error("IBEMail::MailUser::encryptAEAD: EVP_EncryptInit_ex");

    if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, iv.size(), NULL)) throw runtime_error("IBEMail::MailUser::encryptAEAD: EVP_CIPHER_CTX_ctrl set iv_len");

    if(1 != EVP_EncryptInit_ex(ctx, NULL, NULL, key.data(), iv.data())) throw runtime_error("IBEMail::MailUser::encryptAEAD: EVP_EncryptInit_ex");

    int ciphertext_len = 0;
    int len = 0;
    if(1 != EVP_EncryptUpdate(ctx, NULL, &len, aad.data(), aad.size())) throw runtime_error("IBEMail::MailUser::encryptAEAD: EVP_EncryptUpdate");

    int c_size_pos = dst.tellp();
    dst.write((const char*)&ciphertext_len, sizeof(ciphertext_len));

    //encrypt symmetric encryption
    unsigned char enc[EVP_MAX_BLOCK_LENGTH];
    unsigned char buf[EVP_MAX_BLOCK_LENGTH];
    int buf_size;
    while(!src.eof()){
      src.read((char*)buf, EVP_MAX_BLOCK_LENGTH);
      buf_size = src.gcount();

      if(1 != EVP_EncryptUpdate(ctx, enc, &len, buf, buf_size)) throw runtime_error("IBEMail::MailUser::encryptAEAD: EVP_EncryptUpdate");
      dst.write((char*)enc, len);
      ciphertext_len += len;
    }
    if(1 != EVP_EncryptFinal_ex(ctx, enc, &len)) throw runtime_error("IBEMail::MailUser::encryptAEAD: EVP_EncryptFinal_ex");
    dst.write((char*)enc, len);
    ciphertext_len += len;

    //get tag
    unsigned char tag[tag_len];
    if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, tag_len, tag)) throw runtime_error("IBEMail::MailUser::encryptAEAD: EVP_CIPHER_CTX_ctrl get tag");
    dst.write((char*)tag, tag_len);

    //clean up
    EVP_CIPHER_CTX_free(ctx);

    int end_pos = dst.tellp();
    dst.seekp(c_size_pos);
    //write ciphertext cize
    dst.write((const char*)&ciphertext_len, sizeof(ciphertext_len));
    dst.seekp(end_pos);

    return sizeof(ciphertext_len) + ciphertext_len + tag_len;
  }

  int MailUser::encryptAEAD(const EVP_CIPHER *cipher, const vector<unsigned char> &key, const vector<unsigned char> &aad, ostream &dst, istream &src){
    return encryptAEAD(cipher, key, genIV(EVP_CIPHER_iv_length(cipher)), aad, dst, src);
  }


  //encrypt AEAD return write length
  //int MailUser::encryptAEAD(const EVP_CIPHER *cipher, const vector<unsigned char> &key, const vector<unsigned char> &iv, const vector<unsigned char> &aad, BIO *dst, BIO *src){
  //  EVP_CIPHER_CTX *ctx;

  //  if(!(ctx = EVP_CIPHER_CTX_new())) throw runtime_error("IBEMail::MailUser::encryptAEAD: EVP_CIPHER_CTX_new");

  //  if(1 != EVP_EncryptInit_ex(ctx, cipher, NULL, NULL, NULL)) throw runtime_error("IBEMail::MailUser::encryptAEAD: EVP_EncryptInit_ex");

  //  if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, iv.size(), NULL)) throw runtime_error("IBEMail::MailUser::encryptAEAD: EVP_CIPHER_CTX_ctrl set iv_len");

  //  if(1 != EVP_EncryptInit_ex(ctx, NULL, NULL, key.data(), iv.data())) throw runtime_error("IBEMail::MailUser::encryptAEAD: EVP_EncryptInit_ex");

  //  int ciphertext_len = 0;
  //  int len = 0;
  //  if(1 != EVP_EncryptUpdate(ctx, NULL, &len, aad.data(), aad.size())) throw runtime_error("IBEMail::MailUser::encryptAEAD: EVP_EncryptUpdate");

  //  int c_size_pos = BIO_tell(dst);
  //  BIO_write(dst, &ciphertext_len, sizeof(ciphertext_len));

  //  //encrypt symmetric encryption
  //  unsigned char enc[EVP_MAX_BLOCK_LENGTH];
  //  unsigned char buf[EVP_MAX_BLOCK_LENGTH];
  //  while(!BIO_eof(src)){
  //    int buf_size = BIO_read(src, buf, EVP_MAX_BLOCK_LENGTH);

  //    if(1 != EVP_EncryptUpdate(ctx, enc, &len, buf, buf_size)) throw runtime_error("IBEMail::MailUser::encryptAEAD: EVP_EncryptUpdate");
  //    BIO_write(dst, enc, len);
  //    ciphertext_len += len;
  //  }
  //  if(1 != EVP_EncryptFinal_ex(ctx, enc, &len)) throw runtime_error("IBEMail::MailUser::encryptAEAD: EVP_EncryptFinal_ex");
  //  BIO_write(dst, enc, len);
  //  ciphertext_len += len;

  //  //get tag
  //  unsigned char tag[tag_len];
  //  if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, tag_len, tag)) throw runtime_error("IBEMail::MailUser::encryptAEAD: EVP_CIPHER_CTX_ctrl get tag");
  //  BIO_write(dst, tag, tag_len);

  //  //clean up
  //  EVP_CIPHER_CTX_free(ctx);

  //  int end_pos = BIO_tell(dst);
  //  BIO_seek(dst, c_size_pos);
  //  //write ciphertext cize
  //  BIO_write(dst, &ciphertext_len, sizeof(ciphertext_len));
  //  BIO_seek(dst, end_pos);

  //  return sizeof(ciphertext_len) + ciphertext_len + tag_len;
  //}


  //decrypt AEAD return write length
  int MailUser::decryptAEAD(const EVP_CIPHER *cipher, const vector<unsigned char> &key, const vector<unsigned char> &iv, const vector<unsigned char> &aad, ostream &dst, istream &src){
    EVP_CIPHER_CTX *ctx;

    if(!(ctx = EVP_CIPHER_CTX_new())) throw runtime_error("IBEMail::MailUser::decryptAEAD: EVP_CIPHER_CTX_new");

    if(!EVP_DecryptInit_ex(ctx, cipher, NULL, NULL, NULL)) throw runtime_error("IBEMail::MailUser::decryptAEAD: EVP_DecryptInit_ex");

    if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, iv.size(), NULL)) throw runtime_error("IBEMail::MailUser::decryptAEAD: EVP_CIPHER_CTX_ctrl set iv_len");

    if(!EVP_DecryptInit_ex(ctx, NULL, NULL, key.data(), iv.data())) throw runtime_error("IBEMail::MailUser::decryptAEAD: EVP_DecryptInit_ex");

    int len = 0;
    if(!EVP_DecryptUpdate(ctx, NULL, &len, aad.data(), aad.size())) throw runtime_error("IBEMail::MailUser::decryptAEAD: EVP_DecryptUpdate aad");

    int plaintext_len = 0;
    int ciphertext_len = 0;
    src.read((char*)&ciphertext_len, sizeof(ciphertext_len));

    //decrypt symmetric encryption
    int l = ciphertext_len / EVP_MAX_BLOCK_LENGTH;
    int buf_size = 0;
    unsigned char dec[EVP_MAX_BLOCK_LENGTH];
    unsigned char buf[EVP_MAX_BLOCK_LENGTH];
    for(int i = 0; i < l; i++){
      src.read((char*)buf, EVP_MAX_BLOCK_LENGTH);
      buf_size = src.gcount();

      if(!EVP_DecryptUpdate(ctx, dec, &len, buf, buf_size)) throw runtime_error("IBEMail::MailUser::decryptAEAD: EVP_DecryptUpdate decrypt");
      dst.write((const char*)dec, len);
      plaintext_len += len;
    }
    src.read((char*)buf, ciphertext_len%EVP_MAX_BLOCK_LENGTH);
    buf_size = src.gcount();
    if(!EVP_DecryptUpdate(ctx, dec, &len, buf, buf_size)) throw runtime_error("IBEMail::MailUser::decryptAEAD: EVP_DecryptUpdate decrypt");
    dst.write((const char*)dec, len);
    plaintext_len += len;

    //set tag
    unsigned char tag[tag_len];
    src.read((char*)tag, tag_len);
    if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, tag_len, tag)) throw runtime_error("IBEMail::MailUser::decryptAEAD: EVP_CIPHER_CTX_ctrl");

    int ret = EVP_DecryptFinal_ex(ctx, dec, &len);
    dst.write((const char*)dec, len);

    //clean up
    EVP_CIPHER_CTX_free(ctx);
    if(ret > 0){
      //success
      plaintext_len += len;
      return plaintext_len;
    } else {
      //verify failed
      return -1;
    }
  }

  //decrypt AEAD return write length
  //int MailUser::decryptAEAD(const EVP_CIPHER *cipher, const vector<unsigned char> &key, const vector<unsigned char> &iv, const vector<unsigned char> &aad, BIO *dst, BIO *src){
  //  EVP_CIPHER_CTX *ctx;

  //  if(!(ctx = EVP_CIPHER_CTX_new())) throw runtime_error("IBEMail::MailUser::decryptAEAD: EVP_CIPHER_CTX_new");

  //  if(!EVP_DecryptInit_ex(ctx, cipher, NULL, NULL, NULL)) throw runtime_error("IBEMail::MailUser::decryptAEAD: EVP_DecryptInit_ex");

  //  if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, iv.size(), NULL)) throw runtime_error("IBEMail::MailUser::decryptAEAD: EVP_CIPHER_CTX_ctrl set iv_len");

  //  if(!EVP_DecryptInit_ex(ctx, NULL, NULL, key.data(), iv.data())) throw runtime_error("IBEMail::MailUser::decryptAEAD: EVP_DecryptInit_ex");

  //  int len = 0;
  //  if(!EVP_DecryptUpdate(ctx, NULL, &len, aad.data(), aad.size())) throw runtime_error("IBEMail::MailUser::decryptAEAD: EVP_DecryptUpdate aad");

  //  int plaintext_len = 0;
  //  int ciphertext_len = 0;
  //  BIO_read(src, &ciphertext_len, sizeof(ciphertext_len));

  //  //decrypt symmetric encryption
  //  int l = ciphertext_len / EVP_MAX_BLOCK_LENGTH;
  //  int buf_size = 0;
  //  unsigned char dec[EVP_MAX_BLOCK_LENGTH];
  //  unsigned char buf[EVP_MAX_BLOCK_LENGTH];
  //  for(int i = 0; i < l; i++){
  //    buf_size = BIO_read(src, buf, EVP_MAX_BLOCK_LENGTH);

  //    if(!EVP_DecryptUpdate(ctx, dec, &len, buf, buf_size)) throw runtime_error("IBEMail::MailUser::decryptAEAD: EVP_DecryptUpdate decrypt");
  //    BIO_write(dst, dec, len);
  //    plaintext_len += len;
  //  }
  //  buf_size = BIO_read(src, buf, ciphertext_len%EVP_MAX_BLOCK_LENGTH);
  //  if(!EVP_DecryptUpdate(ctx, dec, &len, buf, buf_size)) throw runtime_error("IBEMail::MailUser::decryptAEAD: EVP_DecryptUpdate decrypt");
  //  BIO_write(dst, dec, len);
  //  plaintext_len += len;

  //  //set tag
  //  unsigned char tag[tag_len];
  //  BIO_read(src, tag, tag_len);
  //  if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, tag_len, tag)) throw runtime_error("IBEMail::MailUser::decryptAEAD: EVP_CIPHER_CTX_ctrl");

  //  int ret = EVP_DecryptFinal_ex(ctx, dec, &len);
  //  BIO_write(dst, dec, len);

  //  //clean up
  //  EVP_CIPHER_CTX_free(ctx);
  //  if(ret > 0){
  //    //success
  //    plaintext_len += len;
  //    return plaintext_len;
  //  } else {
  //    //verify failed
  //    return -1;
  //  }
  //}


  //hybrid encryption with AEAD return write length
  int MailUser::encryptHybrid(const string &id, const IBEParams &params , const EVP_CIPHER *cipher, const vector<unsigned char> &key,
      const vector<unsigned char> &iv, const vector<unsigned char> &aad, ostream &dst, istream &src){
    int ciphertext_len = 0;

    vector<unsigned char> buf;
    buf.reserve(key.size() + iv.size() + aad.size());
    buf.insert(buf.end(), key.begin(), key.end());
    buf.insert(buf.end(), iv.begin(), iv.end());
    buf.insert(buf.end(), aad.begin(), aad.end());

    IBECipher edKey = encrypt(buf, id, params);

    vector<unsigned char> b, c;
    G1ToBytes(b, edKey.B);
    G1ToBytes(c, edKey.C);

    int len = edKey.a.size() + b.size() + c.size();
    dst.write((const char*)&len, sizeof(len));
    ciphertext_len += sizeof(len);

    dst.write((const char*)edKey.a.data(), edKey.a.size());
    dst.write((const char*)b.data(), b.size());
    dst.write((const char*)c.data(), b.size());

    ciphertext_len += len;

    ciphertext_len += encryptAEAD(cipher, key, iv, aad, dst, src);

    return ciphertext_len;
  }

  int MailUser::encryptHybrid(const string &id, const IBEParams &params , const EVP_CIPHER *cipher, const vector<unsigned char> &key,
      const vector<unsigned char> &aad, ostream &dst, istream &src){
    return encryptHybrid(id, params, cipher, key, genIV(EVP_CIPHER_iv_length(cipher)), aad, dst, src);
  }

  //hybrid encryption with AEAD return write length
  //int MailUser::encryptHybrid(const string &id, const IBEParams &params , const EVP_CIPHER *cipher, const vector<unsigned char> &key,
  //    const vector<unsigned char> &iv, const vector<unsigned char> &aad, BIO *dst, BIO *src){
  //  int ciphertext_len = 0;

  //  vector<unsigned char> buf;
  //  buf.reserve(key.size() + iv.size() + aad.size());
  //  buf.insert(buf.end(), key.begin(), key.end());
  //  buf.insert(buf.end(), iv.begin(), iv.end());
  //  buf.insert(buf.end(), aad.begin(), aad.end());

  //  IBECipher edKey = encrypt(buf, id, params);

  //  vector<unsigned char> b, c;
  //  G1ToBytes(b, edKey.B);
  //  G1ToBytes(c, edKey.C);

  //  int len = edKey.a.size() + b.size() + c.size();
  //  BIO_write(dst, &len, sizeof(len));
  //  ciphertext_len += sizeof(len);

  //  BIO_write(dst, &edKey.a[0], edKey.a.size());
  //  BIO_write(dst, &b[0], b.size());
  //  BIO_write(dst, &c[0], b.size());

  //  ciphertext_len += len;

  //  ciphertext_len += encryptAEAD(cipher, key, iv, aad, dst, src);

  //  return ciphertext_len;
  //}


  //hybrid decryption with AEAD return plaintext length
  int MailUser::decryptHybrid(const EVP_CIPHER *cipher, ostream &dst, istream &src) const{
    const int G1_SIZE = FP_SIZE*2 + 1;
    int ciphertext_len = 0;
    src.read((char*)&ciphertext_len, sizeof(ciphertext_len));

    vector<unsigned char> edKey(ciphertext_len, 0);
    src.read((char*)&edKey[0], ciphertext_len);

    vector<unsigned char> b(edKey.end() - G1_SIZE*2, edKey.end() - G1_SIZE);
    vector<unsigned char> c(edKey.end() - G1_SIZE, edKey.end());
    edKey.resize(ciphertext_len - G1_SIZE*2);

    G1 B, C;
    G1FromBytes(B, b);
    G1FromBytes(C, c);

    IBECipher encKey(edKey, B, C);

    vector<unsigned char> key = decrypt(encKey);

    int key_len = EVP_CIPHER_key_length(cipher);
    int iv_len = EVP_CIPHER_iv_length(cipher);
    vector<unsigned char> iv(key.begin()+key_len, key.begin()+key_len+iv_len);
    vector<unsigned char> aad(key.begin()+key_len+iv_len, key.end());
    key.resize(key_len);

    int ret = decryptAEAD(cipher, key, iv, aad, dst, src);
    return ret;
  }

  //hybrid decryption with AEAD return plaintext length
  //int MailUser::decryptHybrid(const EVP_CIPHER *cipher, BIO *dst, BIO *src) const{
  //  const int G1_SIZE = FP_SIZE*2 + 1;
  //  int ciphertext_len = 0;
  //  BIO_read(src, &ciphertext_len, sizeof(ciphertext_len));

  //  vector<unsigned char> edKey(ciphertext_len, 0);
  //  BIO_read(src, &edKey[0], ciphertext_len);

  //  vector<unsigned char> b(edKey.end() - G1_SIZE*2, edKey.end() - G1_SIZE);
  //  vector<unsigned char> c(edKey.end() - G1_SIZE, edKey.end());
  //  edKey.resize(ciphertext_len - G1_SIZE*2);

  //  G1 B, C;
  //  G1FromBytes(B, b);
  //  G1FromBytes(C, c);

  //  IBECipher encKey(edKey, B, C);

  //  vector<unsigned char> key = decrypt(encKey);

  //  int key_len = EVP_CIPHER_key_length(cipher);
  //  int iv_len = EVP_CIPHER_iv_length(cipher);
  //  vector<unsigned char> iv(key.begin()+key_len, key.begin()+key_len+iv_len);
  //  vector<unsigned char> aad(key.begin()+key_len+iv_len, key.end());
  //  key.resize(key_len);

  //  int ret = decryptAEAD(cipher, key, iv, aad, dst, src);
  //  return ret;
  //}


  //encrypt mail return encrypted mail length
  int MailUser::encryptMail(const string &id, const IBEParams &params, const EVP_CIPHER *cipher, const vector<unsigned char> &key,
      const vector<unsigned char> &iv, const vector<unsigned char> &aad, ostream &dst, istream &src){
    int pos = src.tellg();
    mimetic::MimeEntity me(src);
    mimetic::Header header = me.header();
    mimetic::MimeEntity me2;
    me2.header().from(header.from());
    me2.header().to(header.to());
    me2.header().subject("encrypted mail");
    me2.header().mimeVersion(mimetic::MimeVersion("1.0"));
    me2.header().contentTransferEncoding("base64");
    me2.header().contentDisposition("attachment;\r\n\tfilename=\"ibemail.cipher\"");
    me2.header().contentType("application/ibemail-encrypted");
    int len = me2.size();
    //dst << me2;

    src.seekg(pos);
    string tmpfile = ".ibemail.tmp";
    ofstream tmp_out(tmpfile);

    len += encryptHybrid(id, params, cipher, key, iv, aad, tmp_out, src);
    if(len < 0){
      return len;
    }
    tmp_out.close();

    ifstream tmp_in(tmpfile);
    //base64::b64encode(dst, tmp_in);

    string body = "";

    const int mailRow = 76;
    const int mailRowByte = mailRow*3/4;
    unsigned char bytes[mailRowByte];
    while(!tmp_in.eof()){
      tmp_in.read((char*)bytes, mailRowByte);
      int count = tmp_in.gcount();
      string b64;
      base64::b64encode(b64, vector<unsigned char>(bytes, bytes+count));
      body = body + b64 + "\r\n";
    }

    me2.body().set(body);
    dst << me2;

    remove(tmpfile.c_str());
    return len;
  }

  int MailUser::encryptMail(const string &id, const IBEParams &params, const EVP_CIPHER *cipher, const vector<unsigned char> &key,
      const vector<unsigned char> &aad, ostream &dst, istream &src){
    return encryptMail(id, params, cipher, key, genIV(EVP_CIPHER_iv_length(cipher)), aad, dst, src);
  }

  int MailUser::encryptMail(const EVP_CIPHER *cipher, const vector<unsigned char> &key, const vector<unsigned char> &iv,
      const vector<unsigned char> &aad, ostream &dst, istream &src){
    int pos = src.tellg();
    mimetic::MimeEntity me(src);
    mimetic::Mailbox mbox = me.header().to()[0].mailbox();
    string id = mbox.mailbox();
    string domain = mbox.domain();
    IBEParams params;
    if(params.fromDNS(domain) == -1){
      return -1;
    }

    src.seekg(pos);
    return encryptMail(id, params, cipher, key, iv, aad, dst, src);
  }

  int MailUser::encryptMail(const EVP_CIPHER *cipher, const vector<unsigned char> &key,
      const vector<unsigned char> &aad, ostream &dst, istream &src){
    return encryptMail(cipher, key, genIV(EVP_CIPHER_iv_length(cipher)), aad, dst, src);
  }

  //decrypt mail return plaintext length
  int MailUser::decryptMail(const EVP_CIPHER *cipher, ostream &dst, istream &src) const{
    mimetic::MimeEntity me(src);
    if(me.header().contentType().str() != "application/ibemail-encrypted"){
      return -1;
    }

    string body = me.body();
    if(me.header().contentTransferEncoding().str() == "base64"){
      string base64 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz+/=";
      for(size_t i = body.find_first_not_of(base64); i != string::npos; i = body.find_first_not_of(base64)){
        body.erase(i, 1);
      }
    }

    istringstream body_stream(body);

    string tmpfile = ".ibemail.tmp";
    ofstream tmp_out(tmpfile);

    base64::b64decode(tmp_out, body_stream);
    tmp_out.close();

    //add decrypted header
    dst << "Ibemail-Decrypted: true" << endl;
    ifstream tmp_in(tmpfile);
    int len = decryptHybrid(cipher, dst, tmp_in);

    remove(tmpfile.c_str());

    return len;
  }
}
