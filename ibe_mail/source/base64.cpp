#include "base64.hpp"

// base64 エンコード
bool base64::b64encode(std::string &dst, const std::vector<unsigned char> &src)
{
    const std::string table("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/");
    std::string       cdst;

    for (std::size_t i = 0; i < src.size(); ++i) {
        switch (i % 3) {
        case 0:
            cdst.push_back(table[(src[i] & 0xFC) >> 2]);
            if (i + 1 == src.size()) {
                cdst.push_back(table[(src[i] & 0x03) << 4]);
                cdst.push_back('=');
                cdst.push_back('=');
            }

            break;
        case 1:
            cdst.push_back(table[((src[i - 1] & 0x03) << 4) | ((src[i + 0] & 0xF0) >> 4)]);
            if (i + 1 == src.size()) {
                cdst.push_back(table[(src[i] & 0x0F) << 2]);
                cdst.push_back('=');
            }

            break;
        case 2:
            cdst.push_back(table[((src[i - 1] & 0x0F) << 2) | ((src[i + 0] & 0xC0) >> 6)]);
            cdst.push_back(table[src[i] & 0x3F]);

            break;
        }
    }

    dst.swap(cdst);

    return true;
}


// base64 デコード
bool base64::b64decode(std::vector<unsigned char> &dst, const std::string &src)
{
    if (src.size() & 0x00000003) {
        return false;
    }
    else {
        const std::string table("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/");
        std::vector<unsigned char> cdst;

        for (std::size_t i = 0; i < src.size(); i += 4) {
            if (src[i + 0] == '=') {
                return false;
            }
            else if (src[i + 1] == '=') {
                return false;
            }
            else if (src[i + 2] == '=') {
                const std::string::size_type s1 = table.find(src[i + 0]);
                const std::string::size_type s2 = table.find(src[i + 1]);

                if (s1 == std::string::npos || s2 == std::string::npos) {
                    return false;
                }

                cdst.push_back(static_cast<unsigned char>(((s1 & 0x3F) << 2) | ((s2 & 0x30) >> 4)));

                break;
            }
            else if (src[i + 3] == '=') {
                const std::string::size_type s1 = table.find(src[i + 0]);
                const std::string::size_type s2 = table.find(src[i + 1]);
                const std::string::size_type s3 = table.find(src[i + 2]);

                if (s1 == std::string::npos || s2 == std::string::npos || s3 == std::string::npos) {
                    return false;
                }

                cdst.push_back(static_cast<unsigned char>(((s1 & 0x3F) << 2) | ((s2 & 0x30) >> 4)));
                cdst.push_back(static_cast<unsigned char>(((s2 & 0x0F) << 4) | ((s3 & 0x3C) >> 2)));

                break;
            }
            else {
                const std::string::size_type s1 = table.find(src[i + 0]);
                const std::string::size_type s2 = table.find(src[i + 1]);
                const std::string::size_type s3 = table.find(src[i + 2]);
                const std::string::size_type s4 = table.find(src[i + 3]);

                if (s1 == std::string::npos || s2 == std::string::npos || s3 == std::string::npos || s4 == std::string::npos) {
                    return false;
                }

                cdst.push_back(static_cast<unsigned char>(((s1 & 0x3F) << 2) | ((s2 & 0x30) >> 4)));
                cdst.push_back(static_cast<unsigned char>(((s2 & 0x0F) << 4) | ((s3 & 0x3C) >> 2)));
                cdst.push_back(static_cast<unsigned char>(((s3 & 0x03) << 6) | ((s4 & 0x3F) >> 0)));
            }
        }

        dst.swap(cdst);

        return true;
    }
}

bool base64::b64encode(std::ostream &dst, std::istream &src){
    const int BYTE_BLOCK_SIZE = 3*16;
    unsigned char buf[BYTE_BLOCK_SIZE];
    while(!src.eof()){
        src.read((char*)buf, BYTE_BLOCK_SIZE);
        int buf_size = src.gcount();
        std::string b64;
        if(!base64::b64encode(b64, std::vector<unsigned char>(buf, buf+buf_size))){
            return false;
        }
        dst.write(b64.c_str(), b64.size());
    }
    return true;
}

bool base64::b64decode(std::ostream &dst, std::istream &src){
    const int B64_BLOCK_SIZE = 4*16;
    char buf[B64_BLOCK_SIZE];
    while(!src.eof()){
        src.read(buf, B64_BLOCK_SIZE);
        int buf_size = src.gcount();
        std::vector<unsigned char> bytes;
        if(!base64::b64decode(bytes, std::string(buf, buf+buf_size))){
            return false;
        }
        dst.write((const char*)&bytes[0], bytes.size());
    }
    return true;
}
