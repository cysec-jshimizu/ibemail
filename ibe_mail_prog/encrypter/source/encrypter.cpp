#include <ibe_mail_idniks.hpp>
#include <iostream>
#include <fstream>
#include <random>
#include <stdlib.h>

using namespace std;
using namespace IBEMail;

vector<unsigned char> getRndBytes(size_t len);

int main(){
  initIBEMail();

  string tmpFile = "ibe_mail_encrypter.tmp";
  ofstream ofs(tmpFile);

  vector<unsigned char> key = getRndBytes(32);
  vector<unsigned char> aad = getRndBytes(32);
  const EVP_CIPHER *algo = EVP_aes_256_gcm();
  MailUser::encryptMail(algo, key, aad, ofs, cin);

  string sendmail = "sendmail -it";
  system((sendmail + " < " + tmpFile).c_str());
  remove(tmpFile.c_str());
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
