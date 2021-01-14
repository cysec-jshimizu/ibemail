#include <ibe_mail_idniks.hpp>
#include <fstream>
#include <random>
#include <iostream>
#include <stdlib.h>
#include <string>
#include <mimetic/mimetic.h>
#include <mimetic/utils.h>
#include <boost/algorithm/string.hpp>

using namespace std;
using namespace IBEMail;

vector<unsigned char> getRndBytes(size_t len);

int main(){
  initIBEMail();

  // procmailでメールが渡される
  const size_t BUF_SIZE = 256;
  string home = getenv("HOME");
  string ibemailDir = home + "/.ibemail";

  string tmpFile = ibemailDir + "/.ibe_proc";
  ofstream tmpOut(tmpFile);
  char buf[BUF_SIZE];
  while(!cin.eof()){
    cin.read(buf, BUF_SIZE);
    tmpOut.write(buf, cin.gcount());
  }
  tmpOut.close();

  // ~/.ibemail/mydomainからの使用中のドメインを読み込み
  string domFile = ibemailDir + "/mydomain";
  ifstream ifsDom(domFile);
  string myDom;
  getline(ifsDom, myDom);
  boost::trim(myDom);

  ifstream ifs(tmpFile);
  mimetic::MimeEntity me(ifs);
  ifs.close();

  string toDom = me.header().to()[0].mailbox().domain();

  if (myDom == toDom) {
    string decrypter = "decrypter";
    system((decrypter + "<" + tmpFile).c_str());
  } else {
    // エラーメール作成
    string myname = me.header().to()[0].mailbox().mailbox();
    mimetic::MimeEntity me2;
    me2.header().from("MAILER-DAEMON@" + myDom);
    string from_address = me.header().from()[0].mailbox() + "@" + me.header().from()[0].domain();
    me2.header().to(from_address);
    me2.header().subject("auto mail");
    me2.header().mimeVersion(mimetic::MimeVersion("1.0"));
    string autosub = "Auto-submitted: true";

    string body = myname + "@" + toDom + " is no longer available. You should use " + myname + "@" + myDom;
    // ボディの最後に復号した元のテキストをつけたい
    me2.body().set(body);

    string autoMail = ibemailDir + "/autoMail";
    ofstream ofsMe(autoMail);
    ofsMe << autosub << endl;
    ofsMe << me2 << endl;
    ofsMe.close();

    const EVP_CIPHER *algo = EVP_aes_256_gcm();
    vector<unsigned char> key = getRndBytes(32);
    vector<unsigned char> aad = getRndBytes(32);

    ifstream ifsEnc(autoMail);
    string tmp = ibemailDir + "/enc";
    ofstream ofsEnc(tmp);
    int len = MailUser::encryptMail(algo, key, aad, ofsEnc, ifsEnc);
    cout << len << endl;

    string sendmail = "sendmail -it";
    system((sendmail + " < " + tmp).c_str());

    remove(autoMail.c_str());
    remove(tmp.c_str());
  }
  remove(tmpFile.c_str());

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