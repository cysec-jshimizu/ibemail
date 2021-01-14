#include "idniks.hpp"
#include <mpz_util.hpp>
#include <mcl/bn256.hpp>
// #include <mcl/bn384.hpp>
#include <iostream>

using namespace mcl::bn256;
// using namespace mcl::bn384;
using namespace IDNIKS;

int main(){
  initIDNIKS();
  KGC kgc;
  std::cout << "KGC setup" << std::endl;
  KGCParams params = kgc.getParams();
  std::cout << "  params: " << std::endl;
  std::cout << "    P: " << params.P.getStr(16) << std::endl;
  std::cout << "    Q: " << params.Q.getStr(16) << std::endl;
  std::cout << "    lQ: " << params.lQ.getStr(16) << std::endl;
  std::cout << std::endl;

  std::string id = "j.shimizu";
  std::cout << "id: " << id << std::endl;
  std::string msg = "plaintext";
  std::cout << "message: " << msg << std::endl;

  std::cout << std::endl;
  std::cout << "Encryption: "  << std::endl;
  std::vector<unsigned char> data(msg.begin(), msg.end());

  Cipher cipher = User::encrypt(data, id, params);
  mpz_class C2_mpz;
  mpzUtil::bytesToMpz(C2_mpz, cipher.C2);
  std::cout << "  cryptogram: " << std::endl;
  std::cout << "    C1: " << cipher.C1.getStr(16) << std::endl;
  std::cout << "    C2: " << C2_mpz.get_str(16) << std::endl;

  User recipient(id, kgc.getParams(), kgc.genUserKey(id));
  std::vector<unsigned char> plain = recipient.decrypt(cipher);
  std::string p(plain.begin(), plain.end());
  std::cout << "Dencryption: "  << std::endl;
  std::cout << "  message: " << p << std::endl;
  std::cout << std::endl;


  std::cout << "Sign:" << std::endl;
  Signature sign = recipient.signature(data);
  std::cout << "  signature:" << std::endl;
  std::cout << "    R: " << sign.R.getStr(16) << std::endl;
  std::cout << "    S: " << sign.S.getStr(16) << std::endl;
  std::string result = User::verification(data, id, params, sign)?"true":"false";
  std::cout << "Verify:" << std::endl;
  std::cout << "  result: " << result << std::endl;

}
