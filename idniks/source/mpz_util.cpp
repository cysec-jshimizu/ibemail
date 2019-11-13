#include "mpz_util.hpp"
#include <gmpxx.h>
#include <vector>
#include <random>

namespace mpzUtil{
  int mpzToBytes(std::vector<unsigned char> &out, const mpz_t in, size_t len, int o){
    size_t size = (mpz_sizeinbase(in, 2) + CHAR_BIT - 1) / CHAR_BIT;

    if(!out.empty()) out.clear();
    out.resize(len, 0);
    if(len < size){
      mpz_export(&out[0], &len, 1, 1, o, 0, in);
      return 0;
    }
    mpz_export(&out[len-size], &len, 1, 1, o, 0, in);
    return 1;
  }

  int mpzToBytes(std::vector<unsigned char> &out, const mpz_class &in, size_t len, int o){
    return mpzToBytes(out, in.get_mpz_t(), len, o);
  }

  int mpzToBytes(std::vector<unsigned char> &out, const mpz_t in, int o){
    size_t size = (mpz_sizeinbase(in, 2) + CHAR_BIT - 1) / CHAR_BIT;
    int r = mpzToBytes(out, in, size, o);
    return r;
  }

  int mpzToBytes(std::vector<unsigned char> &out, const mpz_class &in, int o){
    return mpzToBytes(out, in.get_mpz_t(), o);
  }

  int bytesToMpz(mpz_class &out, const std::vector<unsigned char> &in, int o){
    mpz_import(out.get_mpz_t(), in.size(), 1, 1, o, 0, &in[0]);
    return 1;
  }


  void mpzRandDevice(mpz_class &out, const mpz_class &max){
    std::random_device rng;

    unsigned int l = mpz_sizeinbase(max.get_mpz_t(), UCHAR_MAX+1);

    out.set_str("0", 10);
    mpz_class bit32;
    mpz_ui_pow_ui(bit32.get_mpz_t(), 2, CHAR_BIT*4);
    for(unsigned int i = 0; i < l; i++){
      out = ((bit32*out) + rng()) % max;
    }
  }
}
