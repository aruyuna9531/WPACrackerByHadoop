#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<openssl/hmac.h>

//#define debug

char toHex(int x)
/*
转化一个数（0-15）到其十六进制数
@param x 待转化数
@return 十六进制数
*/
{
	if(x>=16 || x<0)return (char)0;
	if(x<=9)return (char)(x+48);
	else return (char)(x+87);
}

int HexToNum(char *s, int len)
/*
转化十六进制到数字
@param s 待转化的十六进制数
@param len 十六进制数位数
@return 得到的数
*/
{
	int i,tmp=0;
	for(i=0;i<len;i++){
		tmp*=16;
		if(s[i]<='9')tmp+=s[i]-48;
		else tmp+=s[i]-87;
	}
	return tmp;
}



void intToAsc(char *res, int ascii)
/*
转化数字到Ascii（-128～127）
@param res 返回结果
@param ascii 需要转化的数
*/
{
	if(ascii<0)ascii+=256;
	int S1 = ascii/16,S2=0;
	ascii-=S1*16;
	S2=ascii;
	res[0]=toHex(S1);
	res[1]=toHex(S2);
	res[2]=32;
}

void HexStrToBinary(char *bin, const char *str)
/*
转化明文十六进制到二进制字符串
@param bin 转化后结果
@param str 转化前的明文十六进制
*/
{
	int counter=0;
	char tmp[3];
	memset(tmp, 0, 3);
	for(;str[counter*2]!=0;counter++){
		tmp[0]=str[counter*2];
		tmp[1]=str[counter*2+1];
		bin[counter]=(char)HexToNum(tmp, 2);
	}
}

void ToAscii(char *res, const char *s, int Length)
/*
转化数据为明文十六进制
@param res 返回结果
@param s 需要转化的字符串
@param Length 转化的字符长度（指s内需要转化的前Leng个字符）
*/
{
	int i=0,tmp=0;
	char tpc[3];
	memset(res, 0, strlen(s)*3+1);
	for(i=0;i<Length;i++){
		#ifdef debug
		printf("Now transferring byte %d...\n",i);
		#endif
		tmp=s[i];
		intToAsc(tpc,tmp);
		res[3*i+0]=tpc[0];
		res[3*i+1]=tpc[1];
		res[3*i+2]=' ';
		#ifdef debug
		printf("Transfer res: %c%c\n",tpc[0],tpc[1]);
		#endif
	}
}

void printBy16BHex(char *s)
/*
以每行16个字节的形式输出十六进制数据
@param s 待输出数据
*/
{
	int i,counter=0;
	for(i=0;i<strlen(s);i++)
	{
		printf("%c",s[i]);
		counter++;
		if(counter>=48)
		{
			printf("\n");
			counter=0;
		}
	}
	printf("\n");
}

int isBeaconFrame(char *msg)
/*
是否Beacon帧（含SSID信息需要提取）
@return 是为1，否为0
*/
{
	if(msg[0]=='8' && msg[1]=='0' && strlen(msg)>100)return 1;	//第一个字节为"80"时为Beacon帧（暂定）
	else return 0;
}

void getSSIDFromBeacon(char *ssidN, char *macN, const char *src)
/*从Beacon帧得到SSID*/
{
	char Tmp[3], SSID[100], MAC[13];
	int i,SSIDLen;
	memset(SSID, 0, 100);
	memset(MAC, 0, 13);
	//memset(res, 0,);
	for(i=0;i<6;i++){	
		MAC[2*i]=src[(10+i)*3];
		MAC[2*i+1]=src[(10+i)*3+1];
	}
	strcpy(macN,MAC);
	Tmp[0]=src[37*3];
	Tmp[1]=src[37*3+1];
	Tmp[2]=0;
	SSIDLen=HexToNum(Tmp,2);
	//printf("SSID Length:%d\n",SSIDLen);
	for(i=0;i<SSIDLen;i++)
	{
		Tmp[0]=src[(38+i)*3];
		Tmp[1]=src[(38+i)*3+1];
		SSID[i]=(char)HexToNum(Tmp,2);
	}
	strcpy(ssidN,SSID);
}

int isEAPOL(char *msg)
/*是否EAPOL帧*/
{
	if(msg[0]=='8'&&msg[1]=='8')return 1;	//第一个字节为"88"时为EAPOL帧（暂定）
	else return 0;
}

int isHandShakeLLC(char *msg)
/*检查握手包的Logical-Link Control字段*/
{
	int i;
	char tmp[25];
	for(i=0;i<24;i++)
	{
		tmp[i]=msg[78+i];
	}
	tmp[24]=0;
	if(strcmp(tmp, "aa aa 03 00 00 00 88 8e ")==0)return 1;
	else return 0;
}

int isHandShake(char *msg)
/*是否握手包*/
{
	if(isEAPOL(msg)==0 || isHandShakeLLC==0)return 0;	//不是
	//判断第几次
	int i;
	char tmp[7];
	for(i=0;i<6;i++)
	{
		tmp[i]=msg[39*3+i];
	}
	tmp[7]=0;
	if(strcmp(tmp, "00 8a ")==0)return 1;
	if(strcmp(tmp, "01 0a ")==0)return 2;
	if(strcmp(tmp, "13 ca ")==0)return 3;
	if(strcmp(tmp, "03 0a ")==0)return 4;
	return -1;
}

void getMacs(char *src, char *dst, const char *msg)
{
	int i;
	//memset(src, 0, 13);
	//memset(dst, 0, 13);
	for(i=0;i<6;i++){
		src[2*i]=msg[3*(10+i)];
		src[2*i+1]=msg[3*(10+i)+1];
		dst[2*i]=msg[3*(4+i)];
		dst[2*i+1]=msg[3*(4+i)+1];
	}
}

void mergeMACandNonce(char *res, const char *ANonce, const char *SNonce, const char *AMac, const char *SMac)
{
	int i;
	int NonceLess=strcmp(ANonce, SNonce);
	int MacLess=strcmp(AMac,SMac);
	if(MacLess<=0){
		for(i=0;i<12;i++)res[0+i]=AMac[i];
		for(i=0;i<12;i++)res[12+i]=SMac[i];
	}else
	{
		for(i=0;i<12;i++)res[0+i]=SMac[i];
		for(i=0;i<12;i++)res[12+i]=AMac[i];
	}
	if(NonceLess<=0){
		for(i=0;i<64;i++)res[24+i]=ANonce[i];
		for(i=0;i<64;i++)res[88+i]=SNonce[i];
	}else
	{
		for(i=0;i<64;i++)res[24+i]=SNonce[i];
		for(i=0;i<64;i++)res[88+i]=ANonce[i];
	}
	res[152]=0;
}

int main(int argc, char **argv)
{
	int i,ListCount=0,packetlength=0,pointerSeek=0,packageCounter=0,hsk=0;
	char buf[10000];
	char BufTmp[30000];
	char tmpLen[9];
	char SSIDList[100][100],MACList[100][13];
	char ANonce[65],SNonce[65],AMac[13],SMac[13],MIC[33],ASS[153],Mge[77],ResultSS[100];
	char Hand2AuthMsg[256];
	char PTK[129];
	FILE *F=fopen(argv[1],"rb");
	FILE *R=fopen(argv[2],"wb");
	if(F==NULL||R==NULL){
		printf("Cannot open capture file.Exit\n");
		exit(0);
	}
	fseek(F, 24, SEEK_SET);		//cap包的前24字节为cap包格式预置字符，第25字节开始分数据帧
	pointerSeek=24;
	for(i=0;i<100;i++)memset(SSIDList[i], 0, 100);
	memset(ResultSS, 0, 100);
	for(i=0;i<100;i++)memset(MACList[i], 0, 13);
	memset(ANonce, 0, 65);
	memset(SNonce, 0, 65);
	memset(AMac, 0, 13);
	memset(SMac, 0, 13);
	memset(MIC, 0, 33);
	memset(Mge, 0, 77);
	memset(PTK, 0, 129);
	memset(Hand2AuthMsg, 0, 256);
	while(!feof(F))
	{
		packageCounter++;
		memset(buf,0,10000);
		memset(BufTmp,0,30000);

		fread(buf, 1, 16, F);
		ToAscii(BufTmp,buf,16);

		//从帧头16字节处获得帧长度。头16字节中前8为时间戳（前4为秒，后4为微秒），9-12和13-16为帧长
		tmpLen[0]=BufTmp[45];
		tmpLen[1]=BufTmp[46];
		tmpLen[2]=BufTmp[42];
		tmpLen[3]=BufTmp[43];
		tmpLen[4]=BufTmp[39];
		tmpLen[5]=BufTmp[40];
		tmpLen[6]=BufTmp[36];
		tmpLen[7]=BufTmp[37];
		tmpLen[8]=0;
		packetlength=HexToNum(tmpLen,8);
		memset(buf,0,10000);
		memset(BufTmp,0,30000);
		//fseek(F, 16, SEEK_CUR);
		fread(buf, 1, packetlength, F);
		ToAscii(BufTmp, buf, packetlength);
		if(isBeaconFrame(BufTmp)==1){
			getSSIDFromBeacon(SSIDList[ListCount], MACList[ListCount], BufTmp);
			ListCount++;
		}
		//else printf("This is not a beacon frame.\n");
		if(isEAPOL(BufTmp)==1 && isHandShakeLLC(BufTmp)==1)
		{
			int HSNum = isHandShake(BufTmp);
			if(HSNum==1)
			{
				int NPtr=0;
				for(i=0;i<96;i++)
				{
					if(BufTmp[i+51*3]!=' '){ANonce[NPtr]=BufTmp[i+51*3];NPtr++;}
				}
				NPtr=0;
				for(i=0;i<18;i++)
				{
					if(BufTmp[i+4*3]!=' '){SMac[NPtr]=BufTmp[i+4*3];NPtr++;}
				}
				NPtr=0;
				for(i=0;i<18;i++)
				{
					if(BufTmp[i+10*3]!=' '){AMac[NPtr]=BufTmp[i+10*3];NPtr++;}
				}
			}
			if(HSNum==2)
			{
				int NPtr=0;
				for(i=0;i<96;i++)
				{
					if(BufTmp[i+51*3]!=' '){SNonce[NPtr]=BufTmp[i+51*3];NPtr++;}
				}
				NPtr=0;
				for(i=0;i<48;i++)
				{
					if(BufTmp[i+3*115]!=' '){MIC[NPtr]=BufTmp[i+115*3];NPtr++;}
				}
				NPtr=0;
				for(i=0;i<3*(packetlength-34);i++)
				{
					if(BufTmp[i+3*34]!=' '){Hand2AuthMsg[NPtr]=BufTmp[i+34*3];NPtr++;}
				}
				for(i=(115-34)*2;i<(115+16-34)*2;i++){Hand2AuthMsg[i]='0';}
			}
			if(HSNum==4)
			{
				//printf("A complete handshake was detected.\n");
				for(i=0;i<ListCount;i++){
					if(strcmp(AMac, MACList[i])==0){
						strcpy(ResultSS, SSIDList[i]);
						break;
					}
				}
				hsk=1;
				break;
			}
		}
		
	}
	if(hsk==1){
	fprintf(R,"%s\n",ResultSS);
	fprintf(R,"%s\n",AMac);
	fprintf(R,"%s\n",SMac);
	fprintf(R,"%s\n",ANonce);
	fprintf(R,"%s\n",SNonce);
	fprintf(R,"%s\n",MIC);
	fprintf(R,"%s\n",Hand2AuthMsg);
	}
	else printf("No complete handshake was found.\n");
	fclose(F);
	return 0;
}
