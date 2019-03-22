#include "bb2.hpp"
#include <mcl/bn256.hpp>
#include <string>
#include <iostream>

using namespace mcl::bn256;
using namespace BB2;

int main(){
  initBB2();
  KGC kgc;
  std::cout << "KGC setup" << std::endl;
  KGCParams params = kgc.getParams();
  std::cout << "params: " << std::endl;
  std::cout << "  G: " << params.G.getStr(16) << std::endl;
  std::cout << "  X: " << params.X.getStr(16) << std::endl;
  std::cout << "  Y: " << params.Y.getStr(16) << std::endl;
  std::cout << "  v: " << params.v.getStr(16) << std::endl;

  std::string id = "okumura";
  std::cout << "id: " << id << std::endl;
  std::string msg = "plaintext";
  std::cout << msg << std::endl;
  std::vector<unsigned char> data(msg.begin(), msg.end());

  Cipher cipher = User::encrypt(data, id, params);

  std::string a(cipher.a.begin(), cipher.a.end());
  std::cout << "cipher: " << std::endl;
  //std::cout << "  a: " << a << std::endl;
  std::cout << "  B: " << cipher.B.getStr(16) << std::endl;
  std::cout << "  C: " << cipher.C.getStr(16) << std::endl;

  User recipient(id, kgc.getParams(), kgc.genUserKey(id));
  std::vector<unsigned char> plain = recipient.decrypt(cipher);
  std::string p(plain.begin(), plain.end());
  std::cout << p << std::endl;
}
