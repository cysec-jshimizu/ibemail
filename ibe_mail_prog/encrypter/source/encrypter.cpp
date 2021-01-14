#include <ibe_mail_idniks.hpp>
#include <iostream>
#include <fstream>
#include <random>
#include <stdlib.h>
#include <string>
#include <mimetic/mimetic.h>

using namespace std;
using namespace IBEMail;

vector<unsigned char> getRndBytes(size_t len);
IBEUserKey getUserKey(string filename);

int main(){
  initIBEMail();

  vector<unsigned char> key = getRndBytes(32);
  vector<unsigned char> aad = getRndBytes(32);
  const EVP_CIPHER *algo = EVP_aes_256_gcm();

  // 入力から読み込み
  string tmp = "tmp";
  ofstream tmpOfs(tmp);
  size_t BUF_SIZE  = 256;
  char buf[BUF_SIZE];
  while (!cin.eof()) {
    cin.read(buf, BUF_SIZE);
    tmpOfs.write(buf, cin.gcount());
  }
  tmpOfs.close();
  ifstream ifs(tmp);

  string tmpSignFile = "ibe_mail_sign.tmp";
  ofstream ofs_sign(tmpSignFile);

  IBEParams param;

  int pos = ifs.tellg();
  mimetic::MimeEntity me(ifs);
  ifs.seekg(pos);
  string from_domain = me.header().from()[0].domain();
  string from_address = me.header().from()[0].mailbox() + "@" + me.header().from()[0].domain();

  param.fromDNS(from_domain);

  string homedir = getenv("HOME");
  // Fromのドメイン+".decrypter"
  const string keyFile = homedir + "/.ibemail/" + from_domain + ".decryptkey";
  // const string keyFile = homedir + "/.ibemail/decryptkey";
  MailUser user(from_address, param, getUserKey(keyFile));
  user.signMail(ofs_sign, ifs);
  ifs.close();
  ofs_sign.close();

  ifstream ifs_enc(tmpSignFile);
  string tmpFile = "ibe_mail_encrypter.tmp";
  ofstream ofs(tmpFile);

  MailUser::encryptMail(algo, key, aad, ofs, ifs_enc);

  string sendmail = "sendmail -it";
  system((sendmail + " < " + tmpFile).c_str());
  remove(tmpSignFile.c_str());
  remove(tmpFile.c_str());
  remove(tmp.c_str());

  return 0;
}

vector<unsigned char> getRndBytes(size_t len){
  vector<unsigned char> bytes(len, 0);

  random_device rng;
  size_t pos = 0;
  while(pos < len){
    unsigned int rnd = rng();
    size_t l = min(len - pos, sizeof(int));
    memcpy(&bytes[pos], &rnd, l);
    pos += l;
  }

  return bytes;
}

IBEUserKey getUserKey(string filename){
  ifstream keyFileStream(filename);

  string userKey_b64;
  getline(keyFileStream, userKey_b64);
  IBEUserKey userKey;
  userKey.setBase64(userKey_b64);

  return userKey;
};
