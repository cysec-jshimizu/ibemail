#ifndef _INC_MPZUTIL
#define _INC_MPZUTIL

#include <gmpxx.h>
#include <vector>

namespace mpzUtil{
  int mpzToBytes(std::vector<unsigned char> &out, const mpz_t in, int o=0);
  int mpzToBytes(std::vector<unsigned char> &out, const mpz_class &in, int o=0);
  int mpzToBytes(std::vector<unsigned char> &out, const mpz_t in, size_t len, int o=0);
  int mpzToBytes(std::vector<unsigned char> &out, const mpz_class &in, size_t len, int o=0);
  int bytesToMpz(mpz_class &out, const std::vector<unsigned char> &in, int o=0);

  void mpzRandDevice(mpz_class &out, const mpz_class &max);
}

#endif
