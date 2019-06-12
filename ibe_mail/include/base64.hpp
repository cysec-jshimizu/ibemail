#ifndef _INC_BASE64
#define _INC_BASE64

#include <string>
#include <vector>
#include <iostream>

namespace base64 {
  bool b64encode(std::string &dst, const std::vector<unsigned char> &src);
  bool b64decode(std::vector<unsigned char> &dst, const std::string &src);
  bool b64encode(std::ostream &dst, std::istream &src);
  bool b64decode(std::ostream &dst, std::istream &src);
}

#endif
