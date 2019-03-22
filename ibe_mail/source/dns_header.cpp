#include <dns_header.hpp>
#include <vector>
#include <string>
#include <stdlib.h>
#include <cstring>
#include <arpa/inet.h>
#include <resolv.h>

using namespace std;

namespace dnsHeader{
  unsigned char* ReadName(unsigned char* reader, unsigned char* buffer, int* count){
    unsigned char *name;
    unsigned int p=0,jumped=0,offset;
    int i , j;
  
    *count = 1;
    name = (unsigned char*)malloc(256);
  
    name[0]='\0';
  
    //read the names in 3www6google3com format
    while(*reader!=0)
    {
      if(*reader>=192)
      {
        offset = (*reader)*256 + *(reader+1) - 49152; //49152 = 11000000 00000000 ;)
        reader = buffer + offset - 1;
        jumped = 1; //we have jumped to another location so counting wont go up!
      }
      else
      {
        name[p++]=*reader;
      }

      reader = reader+1;

      if(jumped==0)
      {
        *count = *count + 1; //if we havent jumped to another location then we can count up
      }
    }

    name[p]='\0'; //string complete
    if(jumped==1)
    {
      *count = *count + 1; //number of steps we actually moved forward in the packet
    }

    //now convert 3www6google3com0 to www.google.com
    for(i=0;i<(int)strlen((const char*)name);i++) 
    {
      p=name[i];
      for(j=0;j<(int)p;j++) 
      {
        name[i]=name[i+1];
        i=i+1;
      }
      name[i]='.';
    }
    name[i-1]='\0'; //remove the last dot
    return name;
  }

  vector<struct RES_RECORD> ReadAnswers(const struct DNS_HEADER *dns){
    unsigned char *reader = (unsigned char*)dns + sizeof(struct DNS_HEADER) + strlen((const char*)dns+sizeof(struct DNS_HEADER))+1 + sizeof(struct QUESTION);

    //Start reading answers
    int stop=0;
    vector<struct RES_RECORD> answers(ntohs(dns->ans_count));

    for(int i=0;i<ntohs(dns->ans_count);i++){
      answers[i].name = ReadName(reader, (unsigned char*)dns, &stop);
      reader = reader + stop;

      answers[i].resource = (struct R_DATA*)(reader);
      reader = reader + sizeof(struct R_DATA);

      if(ntohs(answers[i].resource->type) != T_AAAA) //if its an ipv4 address
      {
        answers[i].rdata = (unsigned char*)malloc(ntohs(answers[i].resource->data_len));

        for(int j=0 ; j<ntohs(answers[i].resource->data_len) ; j++)
        {
          answers[i].rdata[j]=reader[j];
        }

        answers[i].rdata[ntohs(answers[i].resource->data_len)] = '\0';

        reader = reader + ntohs(answers[i].resource->data_len);
      }
      else
      {
        answers[i].rdata = ReadName(reader, (unsigned char*)dns, &stop);
        reader = reader + stop;
      }
    }

    return answers;
  }

  string ReadTxtRecord(const struct RES_RECORD &record){
    if(ntohs(record.resource->type) != T_TXT){
      return string((const char*)record.rdata);
    }

    string txt((const char*)(record.rdata+1));

    unsigned short data_len = ntohs(record.resource->data_len) - 1;
    unsigned short txt_len = record.rdata[0];

    while(txt_len < data_len){
      unsigned char len = txt[txt_len];
      txt.erase(txt_len, 1);
      data_len -= 1;
      txt_len += len;
    }

    return txt;
  }

  void FreeRES_RECORD(struct RES_RECORD &record){
    free(record.name);
    free(record.rdata);
  }
}
