#include "idniks.hpp"
#include <mcl/bn384.hpp>
#include <string>
#include <iostream>

using namespace mcl::bn256;
// using namespace mcl::bn384;
using namespace IDNIKS;

int main(){
  initIDNIKS();
  KGC kgc;
  std::cout << "KGC setup" << std::endl;
  KGCParams params = kgc.getParams();
  std::cout << "params: " << std::endl;
  std::cout << "  P: " << params.P.getStr(16) << std::endl;
  std::cout << "  Q: " << params.Q.getStr(16) << std::endl;
  std::cout << "  lQ: " << params.lQ.getStr(16) << std::endl;

  std::string id = "k.kobayashi";
  std::cout << "id: " << id << std::endl;
  std::string msg = "plaintext";
  std::cout << msg << std::endl;

  std::cout << std::endl;
  std::cout << "encrypt: "  << std::endl;
  std::vector<unsigned char> data(msg.begin(), msg.end());

  Cipher cipher = User::encrypt(data, id, params);
  std::string C2(cipher.C2.begin(), cipher.C2.end());
  std::cout << "cipher: " << std::endl;
  std::cout << "  C1: " << cipher.C1.getStr(16) << std::endl;
  // std::cout << "  C2: " << C2 << std::endl;

  User recipient(id, kgc.getParams(), kgc.genUserKey(id));
  std::vector<unsigned char> plain = recipient.decrypt(cipher);
  std::string p(plain.begin(), plain.end());
  std::cout << p << std::endl;
  std::cout << std::endl;


  std::cout << "signature:" << std::endl;
  Signature sign = recipient.signature(data);
  std::cout << "  R: " << sign.R.getStr(16) << std::endl;
  std::cout << "  S: " << sign.S.getStr(16) << std::endl;
  std::string result = User::verification(data, id, params, sign)?"true":"false";
  std::cout << "result: " << result << std::endl;

}
