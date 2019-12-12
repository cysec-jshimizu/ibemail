#include <ibe_mail_idniks.hpp>
#include <fstream>
#include <time.h>
#include <stdlib.h>
#include <mimetic/mimetic.h>
#include <mimetic/utils.h>

#include <stdio.h>
#include <chrono>

using namespace std;
using namespace IBEMail;

int main(){
  chrono::system_clock::time_point start, end;
  
  start = chrono::system_clock::now();
  initIBEMail();

  const size_t BUF_SIZE = 256;
  string home = getenv("HOME");
  string ibemailDir = home + "/.ibemail";

  string tmpFile = ibemailDir + "/.ibemail.tmp";
  ofstream tmpOut(tmpFile);
  char buf[BUF_SIZE];
  while(!cin.eof()){
    cin.read(buf, BUF_SIZE);
    tmpOut.write(buf, cin.gcount());
  }
  tmpOut.close();

  ifstream tmpIn(tmpFile);
  string logFile = ibemailDir + "/ibemail.log";
  ofstream logStream(logFile, ios::app);
  while(!tmpIn.eof()){
    tmpIn.read(buf, BUF_SIZE);
    logStream.write(buf, tmpIn.gcount());
  }
  logStream << endl;
  tmpIn.clear();
  tmpIn.seekg(0);

  string mailDir = home + "/MailDir/";
  time_t now = time(NULL);
  string date(32, '\0');
  size_t l = strftime(&date[0], date.size(), "%Y%m%d%H%M%S", localtime(&now));
  date.resize(l);
  ofstream mailStream(mailDir + date);

  const string keyFile = ibemailDir + "/decryptkey";
  ifstream keyFileStream(keyFile);
  if(!keyFileStream.is_open()){
    logStream << "Error: can't open keyfile." << endl << endl;
    while(!tmpIn.eof()){
      tmpIn.read(buf, BUF_SIZE);
      mailStream.write(buf, tmpIn.gcount());
    }
    remove(tmpFile.c_str());
    return -1;
  }

  string userKey_b64;
  getline(keyFileStream, userKey_b64);
  IBEUserKey userKey;
  userKey.setBase64(userKey_b64);
  IBEParams param;
  MailUser user("", param, userKey);
  const EVP_CIPHER *algo = EVP_aes_256_gcm();
  //ignore Unix-From
  tmpIn.ignore(numeric_limits<streamsize>::max(), '\n');
  int s = user.decryptMail(algo, mailStream, tmpIn);
  if(s < 0){
    logStream << "Error: decrypt failed." << endl << endl;;
    remove(tmpFile.c_str());
    return -1;
  }
  remove(tmpFile.c_str());
  end = chrono::system_clock::now();

  double time = static_cast<double>(chrono::duration_cast<chrono::microseconds>(end - start).count() / 1000.0);
  printf("total_decrypt_time: %lf[ms]\n", time);
}
