#include <ibe_mail_idniks.hpp>
#include <unistd.h>
#include <iostream>
#include <fstream>

#include <openssl/sha.h>

using namespace std;
using namespace IBEMail;

void setup();
void genUserKey(string id);

static string paramFileName = "ibemail.param";

int main(int argc, char *argv[]){
  int opt = getopt(argc, argv, "sg:");

  switch(opt){
    // setup
    case 's':
      setup();
      break;

    //generate userkey
    case 'g':
      genUserKey(optarg);
      break;

    default:
      printf("Usage: %s [-s] [-g hoge@fuga.com]\n", argv[0]);
      break;
  }
}

void setup(){
  initIBEMail();

  MailKGC kgc;
  kgc.setup();

  ofstream paramFile(paramFileName);

  IBEParams params = kgc.getParams();
  paramFile << params.getRecode() << endl;

  IBEMasterKey mkey = kgc.getMasterKey();
  paramFile << mkey.getBase64() << endl;
}

void genUserKey(string id){
  initIBEMail();

  //open paramfile
  ifstream paramFile(paramFileName);
  if(!paramFile.is_open()){
    cout << "can't open parameter file." << endl;
    return;
  }

  string paramStr;
  getline(paramFile, paramStr);
  IBEParams param;
  param.setRecode(paramStr);

  string mkeyStr;
  getline(paramFile, mkeyStr);
  IBEMasterKey mkey;
  mkey.setBase64(mkeyStr);

  string ukeyFileName = id + ".userkey";
  ofstream ukeyFile(ukeyFileName);

  MailKGC kgc(param, mkey);
  IBEUserKey ukey = kgc.genUserKey(id);
  ukeyFile << ukey.getBase64() << endl;
}

/* コンパイルエラー回避
 * libibe_mailがlibcryptoを使用するものの
 * ここのコードでは使われないため，リンカが不要と見てリンクしないっぽい？？
 * libcryptoの関数を呼び出すことで回避できる
 * ちゃんとした解決方法が見つかれば消す */
void avoid_error(){
  SHA256_Init(NULL);
}
