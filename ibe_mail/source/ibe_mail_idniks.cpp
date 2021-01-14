#include "ibe_mail_idniks.hpp"
#include <mpz_util.hpp>
#include <base64.hpp>
#include <dns_header.hpp>
#include <fstream>
#include <string>
#include <vector>
#include <boost/algorithm/string.hpp>
#include <resolv.h>
#include <unordered_map>
#include <curl/curl.h>

using namespace std;

size_t curlCallBack(char* ptr, size_t size, size_t nmemb, string* stream) {
  int retsize = size * nmemb;
  stream->append(ptr, retsize);
  return retsize;
}

void parseParam(unordered_map<string, string> &param, const string &paramStr){
  string str = paramStr;
  boost::trim(str);
  size_t i = 0;
  while(i < str.size()){
    size_t eqPos = str.find_first_of("=", i);
    string name(str.begin()+i, str.begin()+eqPos);
    boost::trim(name);
    i = eqPos + 1;
    size_t clnPos = str.find_first_of(";", i);
    if(clnPos == string::npos){
      clnPos = str.size();
    }
    string value(str.begin()+i, str.begin()+clnPos);
    boost::trim(value);
    i = clnPos + 1;
    param[name] = value;
  }
}

string fromHTTP(const std::string &domain){
  CURL *curl;
  string chunk;
  string dom = domain;
  while(true){
    chunk = "";
    string url = "http://ibemail." + dom + "/.well-known/ibemail.txt";

    curl = curl_easy_init();
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curlCallBack);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &chunk);
    curl_easy_perform(curl);
    curl_easy_cleanup(curl);

    long response_code;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);

    if(response_code == 200){
      break;
    }else{
      return "-1";
    }
  }

  string ibeparam = chunk;
  for(size_t c=ibeparam.find_first_of("\n"); c!=string::npos; c=ibeparam.find_first_of("\n")){
    ibeparam.erase(c,1);
  }
  return ibeparam;
}

namespace IBEMail{
  string IBEParams::getRecode(int num) const{
    string ver = "ver=" + VERSION + ";";
    string a = "a=" + ALGOLITHM + ";";
    string c = "c=" + CURVE + ";";
    string n = "n=" + to_string(num) + ";";

    string P;
    G1EncodeBase64(P, this->P);
    P = "P=" + P + ";";

    string Q;
    G2EncodeBase64(Q, this->Q);
    Q = "Q=" + Q + ";";

    string lQ;
    G2EncodeBase64(lQ, this->lQ);
    lQ = "lQ=" + lQ + ";";

    return ver + " " + a + " " + c + " " + n + " " + P + " " + Q + " " + lQ;
  }

  int IBEParams::setRecode(const string &recode){
    unordered_map<string, string> param;
    parseParam(param, recode);

    if(param["ver"] != VERSION || param["a"] != ALGOLITHM || param["c"] != CURVE){
      return -1;
    }

    G1DecodeBase64(this->P, param["P"]);
    G2DecodeBase64(this->Q, param["Q"]);
    G2DecodeBase64(this->lQ, param["lQ"]);
    return 0;
  }

  int IBEParams::fromDNS(const std::string &domain){
    const string subdom = "__ibemailkey.";
    string dom = domain;
    vector<unsigned char> ans(2048, 0);

    while(true){
      dom = subdom + dom;

      res_init();
      _res.options |= RES_USEVC|RES_USE_DNSSEC;
      int r = res_search(dom.c_str(), C_IN, T_TXT, &ans[0], 2048);

      if(r == -1){
        int c = count(dom.begin(), dom.end(), '.');
        if(c<2){
          return -1;
        }else{
          int pos = dom.find_first_of(".") + 1;
          dom = dom.substr(pos);
          pos = dom.find_first_of(".") + 1;
          dom = dom.substr(pos);
          continue;
        }
      }else{
        int pos = dom.find_first_of(".") + 1;
        dom = dom.substr(pos);
        break;
      }
    }

    dnsHeader::DNS_HEADER *dns = (dnsHeader::DNS_HEADER*)&ans[0];
    if(ntohs(dns->ans_count) == 0){
      return -1;
    }

    vector<dnsHeader::RES_RECORD> answers = dnsHeader::ReadAnswers(dns);
    IBEParams dnsParams;
    string ibeparamVersion = dnsHeader::ReadTxtRecord(answers[0]);
    unordered_map<string, string> mibeparamVersion;
    parseParam(mibeparamVersion, ibeparamVersion);
    for(auto i : answers){
      dnsHeader::FreeRES_RECORD(i);
    }

    const string cache_path = "/var/cache/ibemail/";
    string cache_file = cache_path + dom + ".ibepram";
    string ibeparam = "";
    string fname = "/var/cache/ibemail/" +  dom + ".ibeparam";

    ifstream ifs(fname);
    if(ifs.is_open()){
      string s;
      while(getline(ifs, s)){
        ibeparam += s;
      }
      unordered_map<string, string> mibeparam;
      parseParam(mibeparam, ibeparam);
      if(mibeparamVersion["date"] != mibeparam["date"] || mibeparamVersion["ver"] != mibeparam["ver"]){
        ibeparam = fromHTTP(dom);
        ofstream ofs(fname);
        ofs << ibeparam;
        ofs.close();
      }
    }else{
      ibeparam = fromHTTP(dom);
      ofstream ofs(fname);
      ofs << ibeparam;
      ofs.close();
    }
    return this->setRecode(ibeparam);
  }


  string IBEMasterKey::getBase64() const{
    vector<unsigned char> l_bytes;
    mpzUtil::mpzToBytes(l_bytes, this->l.getMpz());

    string l_b64;
    base64::b64encode(l_b64, l_bytes);

    return "l=" + l_b64 + ";";
  }

  int IBEMasterKey::setBase64(const string b64){
    unordered_map<string, string> param;
    parseParam(param, b64);

    vector<unsigned char> l_bytes;
    base64::b64decode(l_bytes, param["l"]);

    mpz_class l_mpz;
    mpzUtil::bytesToMpz(l_mpz, l_bytes);

    this->l.setMpz(l_mpz);

    return 0;
  }


  string IBEUserKey::getBase64() const{
    string Ku_b64;

    G1EncodeBase64(Ku_b64, this->Ku);

    return "Ku=" + Ku_b64 + ";";
  }

  int IBEUserKey::setBase64(const string b64){
    unordered_map<string, string> param;
    parseParam(param, b64);

    G1DecodeBase64(this->Ku, param["Ku"]);

    return 0;
  }


  string IBECipher::getBase64() const{
    string C1_b64, C2_b64;
    G2EncodeBase64(C1_b64, this->C1);
    base64::b64encode(C2_b64, this->C2);

    return "C1=" + C1_b64 + "; C2=" + C2_b64 + ";";
  }

  int IBECipher::setBase64(const string b64){
    unordered_map<string, string> param;
    parseParam(param, b64);

    G2DecodeBase64(this->C1, param["C1"]);
    base64::b64decode(this->C2, param["C2"]);

    return 0;
  }

  string IBESignature::getBase64() const{
    string S_b64, R_b64;
    G1EncodeBase64(S_b64, this->S);
    G2EncodeBase64(R_b64, this->R);

    return "S=" + S_b64 + "; R=" + R_b64 + ";";
  }

  int IBESignature::setBase64(const string b64){
    unordered_map<string, string> param;
    parseParam(param, b64);

    G1DecodeBase64(this->S, param["S"]);
    G2DecodeBase64(this->R, param["R"]);

    return 0;
  }


  void initIBEMail(){
    initPairing();
  }

  void G1ToBytes(vector<unsigned char> &bytes, const G1 &g1){
    vector<unsigned char> x;
    vector<unsigned char> y;

    string str = g1.getStr();
    stringstream ss{str};

    string xs, ys, zs;
    getline(ss, zs, ' ');
    getline(ss, xs, ' ');
    getline(ss, ys, ' ');

    unsigned char z = (unsigned char)zs[0] - '0';
    mpz_class x_mpz(xs), y_mpz(ys);

    mpzUtil::mpzToBytes(x, x_mpz, FP_SIZE, 0);
    mpzUtil::mpzToBytes(y, y_mpz, FP_SIZE, 0);

    bytes.reserve(FP_SIZE*2+1);
    bytes.push_back(z);
    bytes.insert(bytes.end(), x.begin(), x.end());
    bytes.insert(bytes.end(), y.begin(), y.end());
  }

  void G2ToBytes(vector<unsigned char> &bytes, const G2 &g2){
    vector<unsigned char> xa;
    vector<unsigned char> xb;
    vector<unsigned char> ya;
    vector<unsigned char> yb;

    string str = g2.getStr();
    stringstream ss{str};

    string xas, xbs, yas, ybs, zs;
    getline(ss, zs, ' ');
    getline(ss, xas, ' ');
    getline(ss, xbs, ' ');
    getline(ss, yas, ' ');
    getline(ss, ybs, ' ');

    unsigned char z = (unsigned char)zs[0] - '0';
    mpz_class xa_mpz(xas), xb_mpz(xbs), ya_mpz(yas), yb_mpz(ybs);

    mpzUtil::mpzToBytes(xa, xa_mpz, FP_SIZE, 0);
    mpzUtil::mpzToBytes(xb, xb_mpz, FP_SIZE, 0);
    mpzUtil::mpzToBytes(ya, ya_mpz, FP_SIZE, 0);
    mpzUtil::mpzToBytes(yb, yb_mpz, FP_SIZE, 0);

    bytes.reserve(FP_SIZE*4+1);
    bytes.push_back(z);
    bytes.insert(bytes.end(), xa.begin(), xa.end());
    bytes.insert(bytes.end(), xb.begin(), xb.end());
    bytes.insert(bytes.end(), ya.begin(), ya.end());
    bytes.insert(bytes.end(), yb.begin(), yb.end());
  }

  void Fp12ToBytes(vector<unsigned char> &bytes, const Fp12 &fp12){
    Fp2 fp2[6];
    fp2[0] = fp12.a.a;
    fp2[1] = fp12.a.b;
    fp2[2] = fp12.a.c;
    fp2[3] = fp12.b.a;
    fp2[4] = fp12.b.b;
    fp2[5] = fp12.b.c;

    bytes.reserve(FP_SIZE*12);
    for(int i = 0; i < 6; i++){
      vector<unsigned char> a, b;
      mpzUtil::mpzToBytes(a, fp2[i].a.getMpz(), FP_SIZE, 0);
      mpzUtil::mpzToBytes(b, fp2[i].b.getMpz(), FP_SIZE, 0);

      bytes.insert(bytes.end(), a.begin(), a.end());
      bytes.insert(bytes.end(), b.begin(), b.end());
    }
  }


  void G1FromBytes(G1 &g1, const vector<unsigned char> &bytes){
    char z = bytes[0] + '0';
    vector<unsigned char> x_bytes(bytes.begin()+1, bytes.begin()+FP_SIZE+1);
    vector<unsigned char> y_bytes(bytes.begin()+FP_SIZE+1, bytes.begin()+(FP_SIZE*2)+1);

    mpz_class x, y;
    mpzUtil::bytesToMpz(x, x_bytes);
    mpzUtil::bytesToMpz(y, y_bytes);

    string str = "";
    str.reserve(FP_SIZE*2 + 3);
    str = str + z + " " + x.get_str() + " " + y.get_str();

    g1.setStr(str);
  }

  //TODO
  void G2FromBytes(G2 &g2, const vector<unsigned char> &bytes){
    char z = bytes[0] + '0';
    vector<unsigned char> xa_bytes(bytes.begin()+1, bytes.begin()+FP_SIZE+1);
    vector<unsigned char> xb_bytes(bytes.begin()+FP_SIZE+1, bytes.begin()+(FP_SIZE*2)+1);
    vector<unsigned char> ya_bytes(bytes.begin()+(FP_SIZE*2)+1, bytes.begin()+(FP_SIZE*3)+1);
    vector<unsigned char> yb_bytes(bytes.begin()+(FP_SIZE*3)+1, bytes.begin()+(FP_SIZE*4)+1);

    mpz_class xa, xb, ya, yb;
    mpzUtil::bytesToMpz(xa, xa_bytes);
    mpzUtil::bytesToMpz(xb, xb_bytes);
    mpzUtil::bytesToMpz(ya, ya_bytes);
    mpzUtil::bytesToMpz(yb, yb_bytes);

    string str = "";
    str.reserve(FP_SIZE*4 + 5);
    str = str + z + " " + xa.get_str() + " " + xb.get_str() + " " + ya.get_str() + " " + yb.get_str();

    g2.setStr(str);
  }

  void Fp12FromBytes(Fp12 &fp12, const vector<unsigned char> &bytes){
    //Fp2 fp2[6];
    string str = "";
    for(int i = 0; i < 6; i++){
      int beg = FP_SIZE*(i*2);
      int mid = FP_SIZE*(i*2 + 1);
      int end = FP_SIZE*(i*2 + 2);

      vector<unsigned char> a_bytes(bytes.begin()+beg, bytes.begin()+mid);
      vector<unsigned char> b_bytes(bytes.begin()+mid, bytes.begin()+end);

      mpz_class a, b;
      mpzUtil::bytesToMpz(a, a_bytes);
      mpzUtil::bytesToMpz(b, b_bytes);

      //Fp a_fp, b_fp;
      //a_fp.setMpz(a);
      //b_fp.setMpz(b);
      //fp2[i].set(a_fp, b_fp);
      str = str + a.get_str() + " " + b.get_str() + " ";
    }

    //fp12.set(fp2[0], fp2[1], fp2[2], fp2[3], fp2[4], fp2[5]);
    fp12.setStr(str);
  }


  void G1EncodeBase64(string &enc, const G1 &g1){
    vector<unsigned char> x;
    vector<unsigned char> y;

    string str = g1.getStr();
    stringstream ss{str};

    string xs, ys, zs;
    getline(ss, zs, ' ');
    getline(ss, xs, ' ');
    getline(ss, ys, ' ');

    mpz_class x_mpz(xs), y_mpz(ys);

    mpzUtil::mpzToBytes(x, x_mpz);
    mpzUtil::mpzToBytes(y, y_mpz);

    string b64x;
    string b64y;

    base64::b64encode(b64x, x);
    base64::b64encode(b64y, y);

    enc = zs + " " + b64x + " " + b64y;
  }

  void G2EncodeBase64(string &enc, const G2 &g2){
    vector<unsigned char> xa, xb, ya, yb;

    string str = g2.getStr();
    stringstream ss{str};

    string xas, xbs, yas, ybs, zs;
    getline(ss, zs, ' ');
    getline(ss, xas, ' ');
    getline(ss, xbs, ' ');
    getline(ss, yas, ' ');
    getline(ss, ybs, ' ');

    mpz_class xam(xas), xbm(xbs), yam(yas), ybm(ybs);
    mpzUtil::mpzToBytes(xa, xam);
    mpzUtil::mpzToBytes(xb, xbm);
    mpzUtil::mpzToBytes(ya, yam);
    mpzUtil::mpzToBytes(yb, ybm);

    string b64xa, b64xb, b64ya, b64yb;

    base64::b64encode(b64xa, xa);
    base64::b64encode(b64xb, xb);
    base64::b64encode(b64ya, ya);
    base64::b64encode(b64yb, yb);

    enc = zs + " " + b64xa + " " + b64xb + " " + b64ya + " " + b64yb;
  }

  void Fp12EncodeBase64(string &enc, const Fp12 &fp12){
    string str = fp12.getStr();
    stringstream ss{str};

    enc = "";
    enc.reserve(((FP_SIZE*4 + 3 - 1) / 3 + 1)*12);
    for(int i = 0; i < 12; i++){
      string fps;
      getline(ss, fps, ' ');

      mpz_class fpm(fps);
      vector<unsigned char> fp;
      mpzUtil::mpzToBytes(fp, fpm);

      string b64fp;
      base64::b64encode(b64fp, fp);

      enc += b64fp;
      if(i < 11) enc += " ";
    }
  }

  void G1DecodeBase64(G1 &g1, const string &enc){
    stringstream ss{enc};

    string b64x, b64y, z;
    getline(ss, z, ' ');
    getline(ss, b64x, ' ');
    getline(ss, b64y, ' ');

    vector<unsigned char> x, y;
    base64::b64decode(x, b64x);
    base64::b64decode(y, b64y);

    mpz_class x_mpz, y_mpz;
    mpzUtil::bytesToMpz(x_mpz, x);
    mpzUtil::bytesToMpz(y_mpz, y);

    g1.setStr(z + " " + x_mpz.get_str() + " " + y_mpz.get_str());
  }

  void G2DecodeBase64(G2 &g2, const string &enc){
    stringstream ss{enc};

    string b64xa, b64xb, b64ya, b64yb, z;
    getline(ss, z, ' ');
    getline(ss, b64xa, ' ');
    getline(ss, b64xb, ' ');
    getline(ss, b64ya, ' ');
    getline(ss, b64yb, ' ');

    vector<unsigned char> xa, xb, ya, yb;
    base64::b64decode(xa, b64xa);
    base64::b64decode(xb, b64xb);
    base64::b64decode(ya, b64ya);
    base64::b64decode(yb, b64yb);

    mpz_class xa_mpz, xb_mpz, ya_mpz, yb_mpz;
    mpzUtil::bytesToMpz(xa_mpz, xa);
    mpzUtil::bytesToMpz(xb_mpz, xb);
    mpzUtil::bytesToMpz(ya_mpz, ya);
    mpzUtil::bytesToMpz(yb_mpz, yb);

    g2.setStr(z + " " + xa_mpz.get_str() + " " + xb_mpz.get_str() + " " + ya_mpz.get_str() + " " + yb_mpz.get_str());
  }

  //TODO setStr()
  void Fp12DecodeBase64(Fp12 &fp12, const string &enc){
    stringstream ss{enc};

    vector<unsigned char> bytes;
    bytes.reserve(FP_SIZE*12);

    for(int i = 0; i < 12; i++){
      string b64fp;
      getline(ss, b64fp, ' ');

      vector<unsigned char> fp;
      base64::b64decode(fp, b64fp);

      vector<unsigned char> can_fp(FP_SIZE - fp.size(), 0);
      if(fp.size() < FP_SIZE){
        can_fp.reserve(FP_SIZE);
        can_fp.insert(can_fp.end(), fp.begin(), fp.end());
        fp = can_fp;
      }

      bytes.insert(bytes.end(), fp.begin(), fp.end());
    }

    Fp12FromBytes(fp12, bytes);
  }
}
