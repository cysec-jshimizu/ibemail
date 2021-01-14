#include "ibe_mail_idniks.hpp"
#include <base64.hpp>
#include <string>
#include <iostream>
#include <fstream>
#include <chrono>
#include <openssl/bio.h>
#include <openssl/evp.h>

using namespace IBEMail;
using namespace std;

int main(){
  initPairing();

  string paramFile = "files/params.txt";
  ifstream paramIfs(paramFile);
  string storedParam;
  getline(paramIfs, storedParam);
  IBEParams sParam;
  sParam.setRecode(storedParam);

  string storedMKey(1024, '\0');
  paramIfs.read(&storedMKey[0], 1024);
  storedMKey.resize(paramIfs.gcount());
  IBEMasterKey sMKey;
  sMKey.setBase64(storedMKey);

  MailKGC kgc;
  kgc.setParams(sParam);
  kgc.setMasterKey(sMKey);
  std::cout << "KGC setup" << std::endl;
  IBEParams params = kgc.getParams();
  string recode = params.getRecode();
  std::cout << "params: " << std::endl;
  cout << recode << endl;
  IBEMasterKey mkey = kgc.getMasterKey();
  string mkey_b64 = mkey.getBase64();
  cout << "master key: " << endl;
  cout << mkey_b64 << endl;
  IBEMasterKey mkey2;
  mkey2.setBase64(mkey_b64);
  cout << mkey2.getBase64() << endl;

  IBEParams params2;
  if(-1 == params2.setRecode(recode)) cout << "setRecode error" << endl;
  if(params == params2) cout << "params: ok";
  else cout << "params: ng";
  cout << endl;

  std::string id = "hoge";
  std::cout << "id: " << id << std::endl;
  std::string msg = "It is a plaintext.";
  msg = msg + msg + msg;
  cout << msg << endl;
  std::vector<unsigned char> data(msg.begin(), msg.end());

  const EVP_CIPHER *algo = EVP_aes_256_gcm();
  string file_name = "files/len_std.jpg";
  vector<unsigned char> key(32, 16);
  vector<unsigned char> iv(12, 0);
  vector<unsigned char> aad(32, 0);
  ifstream ifs(file_name);
  ofstream ofs(file_name+".enc2");
  MailUser::encryptHybrid(id, params, algo, key, aad, ofs, ifs);
  ofs.close();
  cout << "encryptHybrid ok" << endl;

  string mail_file = "files/sample.txt";
  ifstream ifs_mail(mail_file);
  ofstream ofs_mail(mail_file+".enc2");
  MailUser::encryptMail(id, params, algo, key, aad, ofs_mail, ifs_mail);
  ofs_mail.close();
  cout << "encryptMail1 ok" << endl;

  // string mail_file_cysec = "files/sample_cysec.txt";
  string mail_file_cysec = "files/sample_jshimizu.txt";
  ifstream ifs_mail_cysec(mail_file_cysec);
  ofstream ofs_mail_cysec(mail_file_cysec+".enc2");
  chrono::system_clock::time_point start, end;
  start = chrono::system_clock::now();
  MailUser::encryptMail(algo, key, aad, ofs_mail_cysec, ifs_mail_cysec);
  end = chrono::system_clock::now();
  double elapsed = chrono::duration_cast<chrono::microseconds>(end-start).count();
  cout << "encrypt " << elapsed/1000 << " milliseconds" << endl;

  ofs_mail_cysec.close();
  cout << "encryptMail2 ok" << endl;

  IBECipher cipher = MailUser::encrypt(data, id, params);
  std::string b64_cipher = cipher.getBase64();
  cout << "cipher: " << endl;
  cout << b64_cipher << endl;
  IBECipher cipher2;
  cipher2.setBase64(b64_cipher);
  cout << cipher2.getBase64() << endl;

  IBEUserKey userKey = kgc.genUserKey(id);
  string b64_ukey = userKey.getBase64();
  cout << b64_ukey << endl;
  IBEUserKey userKey2;
  userKey2.setBase64(b64_ukey);
  cout << userKey2.getBase64() << endl;

  MailUser recipient(id, kgc.getParams(), userKey);

  ifstream ifs2(file_name+".enc2");
  ofstream ofs2(file_name+".enc2.dec2");
  int len = recipient.decryptHybrid(algo, ofs2, ifs2);
  if(len < 0){
    cout << "decrypt failed" << endl;
  } else {
    cout << "decrypt successful" << endl;
  }

  ifstream ifs_mail2(mail_file+".enc2");
  ofstream ofs_mail2(mail_file+".enc2.dec2");
  int len2 = recipient.decryptMail(algo, ofs_mail2, ifs_mail2);
  if(len2 < 0){
    cout << "decrypt failed" << endl;
  } else {
    cout << "decrypt successful" << endl;
  }

  MailKGC kgc_cysec(sParam, sMKey);
  MailUser recipient_cysec("user2@jshimizu2.cent", kgc_cysec.getParams(), kgc_cysec.genUserKey("user2@jshimizu2.cent"));
  ifstream ifs_mail_cysec2(mail_file_cysec+".enc2");
  ofstream ofs_mail_cysec2(mail_file_cysec+".enc2.dec2");
  start = chrono::system_clock::now();
  int len3 = recipient_cysec.decryptMail(algo, ofs_mail_cysec2, ifs_mail_cysec2);
  end = chrono::system_clock::now();
  elapsed = chrono::duration_cast<chrono::microseconds>(end-start).count();
  cout << "decrypt " << elapsed/1000 << " milliseconds" << endl;

  if(len3 < 0){
    cout << "decrypt failed" << endl;
  } else {
    cout << "decrypt successful" << endl;
  }

  std::vector<unsigned char> plain = recipient.decrypt(cipher);
  std::string p(plain.begin(), plain.end());
  std::cout << p << std::endl;

  // ifstream ifs_sign(file_name+".enc2");
  // ofstream ofs_sign(file_name+".enc2"+".sign");
  // int len4 = recipient.sign(ofs_sign, ifs_sign);
  // ofs_sign.close();
  // if(len4 < 0){
  //   cout << "sign1 failed" << endl;
  // } else {
  //   cout << "sign1 ok" << endl;
  // }

  // ifstream ifs_sign2(mail_file+".enc2");
  // ofstream ofs_sign2(mail_file+".enc2"+".sign");
  // int len5 = recipient.sign(ofs_sign2, ifs_sign2);
  // ofs_sign2.close();
  // if(len5 < 0){
  //   cout << "sign2 failed" << endl;
  // } else {
  //   cout << "sign2 ok" << endl;
  // }

  std::cout << std::endl;
  // std::istreambuf_iterator<char> it(ifs_mail);
  std::istreambuf_iterator<char> it(ifs_mail_cysec);
  std::istreambuf_iterator<char> last;
  vector<unsigned char> message(it, last);
  // string sign = recipient.sign(message);
  string sign = recipient_cysec.sign(message);
  cout << sign << endl;

  cout << "verify:" << endl;
  bool res = IBEMail::MailUser::verify(message, "user2@jshimizu2.cent", "jshimizu2.cent", sign);
  cout << " result:" << res << endl;
  cout << endl;

  ifstream sign_in("files/sample_jshimizu2.txt");
  ofstream sign_out("files/sample_jshimizu2.txt.sign");
  MailUser testuser("user2@jshimizu2.cent", kgc_cysec.getParams(), kgc_cysec.genUserKey("user2@jshimizu2.cent"));

  start = chrono::system_clock::now();
  testuser.signMail(sign_out, sign_in);
  end = chrono::system_clock::now();
  elapsed = chrono::duration_cast<chrono::microseconds>(end-start).count();
  cout << "sign " << elapsed/1000 << " milliseconds" << endl;

  cout << "signMail ok" << endl;
  sign_out.close();

  ifstream verify_in("files/sample_jshimizu2.txt.sign");
  ofstream verify_out("files/sample_jshimizu2.txt.sign.verify");
  start = chrono::system_clock::now();
  int result = MailUser::verifyMail(verify_out, verify_in);
  end = chrono::system_clock::now();
  elapsed = chrono::duration_cast<chrono::microseconds>(end-start).count();
  cout << "verify " << elapsed/1000 << " milliseconds" << endl;
  if (result == 0){
    cout << "verifyMail ok" << endl;
  } else {
    cout << "verifyMail failed" << endl;
  }
}
