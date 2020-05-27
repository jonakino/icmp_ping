// Adaptado de https://www.geeksforgeeks.org/ping-in-c/
#include <stdio.h> 
#include <sys/types.h> 
#include <sys/socket.h> 

#include <netinet/in.h> // define as estruturas struct sockaddr_in, e struct in_addr
#include <arpa/inet.h> 
#include <netdb.h> 
#include <unistd.h> 
#include <string.h> 
#include <stdlib.h> 
#include <netinet/ip_icmp.h> 
//#include <time.h> 
#include <fcntl.h> 
#include <signal.h> 
#include <time.h> 

#include <iostream>
#include <string>
#include <memory> 
#include <cstdio>			//Permite usar a classe template unique_ptr. smartpointer.
	
// Define the Packet Constants 
// ping packet size 
#define PING_PKT_S 64

// Automatic port number 
#define PORT_NO 0

// Automatic port number 
#define PING_SLEEP_RATE 1000000 //x //Tinha um x depois do número, acho que é erro 

// Gives the timeout delay for receiving packets 
// in seconds 
#define RECV_TIMEOUT 1 

// Define the Ping Loop 
int pingloop=1; 

// Interrupt handler 
void intHandler(int dummy) 
{ 
	pingloop=0; 
} 

// ping packet structure 
struct ping_pkt 
{ 
	struct icmphdr hdr; 
	char msg[PING_PKT_S-sizeof(struct icmphdr)]; 
}; 



using namespace std;

//origem, destino, 
class Ping{
	private:
		string hostname;
		int sockfd; 
		string ip_addr;
		string reverse_hostname; 
		struct sockaddr_in addr_con; // baseado em : https://www.modernescpp.com/index.php/c-core-guidelines-passing-smart-pointer
		//int addrlen = sizeof(addr_con); 	//Não usado
		//char net_buf[NI_MAXHOST]; 		//Não usado
	public:	
		//Métodos gets e sets
		Ping();
		~Ping();
		string getHostName();
		void   setHostName(string);
		int    getSockfd();
		void   setSockfd(int);
		string getIpAddr();
		void   setIpAddr(string);
		string getReverseHostName();
		void   setReverseHostName(string);
		struct sockaddr_in getAddrCon();
		void setAddrCon(struct sockaddr_in);
		unsigned short checksum(void *b, int len);
		void intHandler(int dummy);
		string dns_lookup(string addr_host, struct sockaddr_in &addr_con);
		string reverse_dns_lookup(string ip_addr);
		void send_ping(int ping_sockfd, struct sockaddr_in &ping_addr, string ping_dom, string ping_ip, string rev_host);

};

Ping::Ping(){
	unique_ptr<struct sockaddr_in>  addr_con(new struct sockaddr_in);
}
Ping::~Ping()=default;

//Implementação dos métodos gets e sets
string	Ping::getHostName(){ return hostname; }
void	Ping::setHostName(string hn ){ hostname = hn; }

int 	Ping::getSockfd(){ return sockfd; }
void   	Ping::setSockfd(int s ){sockfd = s;}

string 	Ping::getIpAddr(){ return ip_addr; }
void   	Ping::setIpAddr(string ia){ ip_addr = ia; }

string 	Ping::getReverseHostName(){ return reverse_hostname; }
void   	Ping::setReverseHostName(string rhn){ reverse_hostname = rhn; }

struct sockaddr_in Ping::getAddrCon(){ return addr_con; }
void 	Ping::setAddrCon(struct sockaddr_in ac ){ addr_con = ac; }



unsigned short Ping::checksum(void *b, int len){ 
	return 0;
}
void Ping::intHandler(int dummy){

}
//string dns_lookup(string addr_host, struct sockaddr_in &addr_con){
string dns_lookup(string addr_host, struct sockaddr_in &addr_con){
	
//ok Funciona	cout << "TESTE ip_addr:" << addr_host << "\n";

	//Adapta a interface da função dns_lookup
	char *addr_host_ptr =  (char*)malloc(sizeof(char)*sizeof(addr_host.size()));
	strcpy(addr_host_ptr, addr_host.c_str()); 

	printf("\nResolving DNS..\n"); 
	struct hostent *host_entity; 
	char *ip=(char*)malloc(NI_MAXHOST*sizeof(char)); 
	int i; 


	if ((host_entity = gethostbyname(addr_host_ptr)) == NULL) 
	{ 
		// No ip found for hostname 
		return NULL; 
	} 
	
	//filling up address structure 
	strcpy(ip, inet_ntoa(*(struct in_addr *) 
						host_entity->h_addr)); 

	//(*addr_con).sin_family = host_entity->h_addrtype; 
	//(*addr_con).sin_port = htons (PORT_NO); 
	//(*addr_con).sin_addr.s_addr = *(long*)host_entity->h_addr; 
	addr_con.sin_family = host_entity->h_addrtype; 
	addr_con.sin_port = htons (PORT_NO); 
	addr_con.sin_addr.s_addr = *(long*)host_entity->h_addr; 

	string ip_str(ip);

//OK funciona	cout << "saida dnl_lookup: " << ip_str << "\n";
	//return ip; 
	return ip_str;
}

string Ping::reverse_dns_lookup(string ip_addr){

	char *ip_addr_ptr = (char*) malloc(sizeof(char)*ip_addr.size());
	strcpy(ip_addr_ptr, ip_addr.c_str()); 

	struct sockaddr_in temp_addr;	 
	socklen_t len; 
	char buf[NI_MAXHOST], *ret_buf; 

	temp_addr.sin_family = AF_INET; 
	temp_addr.sin_addr.s_addr = inet_addr(ip_addr_ptr); 
	len = sizeof(struct sockaddr_in); 

	if (getnameinfo((struct sockaddr *) &temp_addr, len, buf, 
					sizeof(buf), NULL, 0, NI_NAMEREQD)) 
	{ 
		printf("Could not resolve reverse lookup of hostname\n"); 
		return NULL; 
	} 
	ret_buf = (char*)malloc((strlen(buf) +1)*sizeof(char) ); 
	strcpy(ret_buf, buf);
	string ret_buf_string = ret_buf; 

	string ret_buf_str(ret_buf);
	return ret_buf_str; ;
}


void Ping::send_ping(int ping_sockfd, struct sockaddr_in &ping_addr, string ping_dom, string ping_ip, string rev_host){
	//transforma string em array de caracter
	char *ping_dom_ptr = (char*) malloc(sizeof(char)*ping_dom.size());
	strcpy(ping_dom_ptr, ping_dom.c_str()); 

	char *ping_ip_ptr = (char*) malloc(sizeof(char)*ping_ip.size());
	strcpy(ping_ip_ptr, ping_ip.c_str()); 

	//Codigo
	int ttl_val=64, msg_count=0, i, flag=1, msg_received_count=0; 
	socklen_t addr_len;
	
	struct ping_pkt pckt; 
	struct sockaddr_in r_addr; 
	struct timespec time_start, time_end, tfs, tfe; 
	long double rtt_msec=0, total_msec=0; 
	struct timeval tv_out; 
	tv_out.tv_sec = RECV_TIMEOUT; 
	tv_out.tv_usec = 0; 

	clock_gettime(CLOCK_MONOTONIC, &tfs); 

	
	// set socket options at ip to TTL and value to 64, 
	// change to what you want by setting ttl_val 
	if (setsockopt(this->sockfd, SOL_IP, IP_TTL, &ttl_val, sizeof(ttl_val)) != 0) 
	{ 
		printf("\nSetting socket options to TTL failed!\n"); 
		return; 
	} 
	else
	{ 
		printf("\nSocket set to TTL..\n"); 
	} 

	// setting timeout of recv setting 
	setsockopt(this->sockfd, SOL_SOCKET, SO_RCVTIMEO, 
				(const char*)&tv_out, sizeof tv_out); 

	// send icmp packet in an infinite loop 
	while(pingloop) 
	{ 
		// flag is whether packet was sent or not 
		flag=1; 
	
		//filling packet 
		bzero(&pckt, sizeof(pckt)); 
		
		pckt.hdr.type = ICMP_ECHO; 
		pckt.hdr.un.echo.id = getpid(); 
		
		for ( i = 0; i < sizeof(pckt.msg)-1; i++ ) 
			pckt.msg[i] = i+'0'; 
		
		pckt.msg[i] = 0; 
		pckt.hdr.un.echo.sequence = msg_count++; 
		pckt.hdr.checksum = checksum(&pckt, sizeof(pckt)); 


		usleep(PING_SLEEP_RATE); 
		//void Ping::send_ping(int ping_sockfd, struct sockaddr_in &ping_addr, string ping_dom, string ping_ip, string rev_host){
		//send packet 
		clock_gettime(CLOCK_MONOTONIC, &time_start); 
		//if ( sendto(ping_sockfd, &pckt, sizeof(pckt), 0, (struct sockaddr*) ping_addr, sizeof(*ping_addr)) <= 0) 
		
		//obtém o ponteiro do unique_ptr
		// struct sockaddr * ping_addr_ptr;
		// ping_addr_ptr = (struct sockaddr *) &ping_addr;
		// struct sockaddr *ping_addr2;
		struct sockaddr_in *dest_addr;
		dest_addr = &(this->addr_con);

		struct socklen_t dest_addr_len = sizeof(struct sockaddr_in);

		//em C
//		int ping_sockfd;//as parameter
//		struct ping_pkt pckt; 
//		sizeof(pckt);
//		struct sockaddr_in *ping_addr
//		if ( sendto(ping_sockfd, &pckt, sizeof(pckt), 0, (struct sockaddr*) ping_addr, sizeof(*ping_addr)) <= 0) 
//		//Documentação (https://linux.die.net/man/2/sendto)	
//		ssize_t sendto(int sockfd, const void *buf, size_t len, int flags, const struct sockaddr *dest_addr, socklen_t addrlen);
		//Fim em C

		//if ( sendto(this->sockfd, &pckt, sizeof(pckt), 0, ping_addr_ptr, sizeof(ping_addr_ptr)) <= 0) 
		if   ( sendto(this->sockfd, &pckt, sizeof(pckt), 0, &dest_addr, sizeof(struct socklen_t)) <= 0) 
		{
			printf("\nPacket Sending Failed! \n"); 
			flag=0; 
		}

		//receive packet 
		addr_len= sizeof(r_addr); 


//		if ( recvfrom(ping_sockfd, &pckt, sizeof(pckt), 0, (struct sockaddr*)&r_addr, &addr_len) <= 0 && msg_count>1) 

		//addr_len = sizeof(struct sockaddr_in);
		     //recvfrom(ping_sockfd, &pckt, sizeof(pckt), 0, (struct sockaddr*)&r_addr, &addr_len)
		if ( recvfrom(this->sockfd, &pckt, sizeof(pckt), 0, (struct sockaddr*)&r_addr,  &addr_len) <= 0 && msg_count>1) 
		{ 
			printf("\nPacket receive failed! \n"); 
		} 

		else
		{ 
			clock_gettime(CLOCK_MONOTONIC, &time_end); 
			
			double timeElapsed = ((double)(time_end.tv_nsec - 	time_start.tv_nsec))/1000000.0;
			rtt_msec = (time_end.tv_sec- time_start.tv_sec) * 1000.0 + timeElapsed; 
			
			// if packet was not sent, don't receive 
			if(flag) 
			{ 
				if(!(pckt.hdr.type ==69 && pckt.hdr.code==0)) 
				{ 
					printf("Error..Packet received with ICMP type %d code %d\n", pckt.hdr.type, pckt.hdr.code); 
				} 
				else
				{ 
					printf("%d bytes from %s (h: %s) (%s) msg_seq=%d ttl=%d rtt = %Lf ms.\n", PING_PKT_S, this->reverse_hostname.c_str(), rev_host.c_str(), this->ip_addr.c_str(), msg_count, ttl_val, rtt_msec); 
					msg_received_count++; 
				} 
			} 
		}	 
	} 
	clock_gettime(CLOCK_MONOTONIC, &tfe); 
	double timeElapsed = ((double)(tfe.tv_nsec - tfs.tv_nsec))/1000000.0; 
	
	total_msec = (tfe.tv_sec-tfs.tv_sec)*1000.0+ timeElapsed ;
					
	printf("\n===%s ping statistics===\n", this->ip_addr.c_str()); 
	printf("\n%d packets sent, %d packets received, %f percent	packet loss. Total time: %Lf ms.\n\n", 	msg_count, msg_received_count, 	((msg_count - msg_received_count)/msg_count) * 100.0, total_msec); 


}


// Driver Code 
int main(int argc, char *argv[]) 
{ 
	Ping p;

//	int sockfd; 
	string ip_addr;
	//char *reverse_hostname; 
//	struct sockaddr_in addr_con; 
//	int addrlen = sizeof(p.getAddrCon());  	//  Não é na função main
//	char net_buf[NI_MAXHOST]; 			//  Também não usado na função main

	if(argc!=2) 
	{ 
		printf("\nFormat %s <address>\n", argv[0]); 
		return 0; 
	} 

	//Ponteiro: p.setIpAddr(p.dns_lookup(argv[1], &p.getAddrCon())); 
	struct sockaddr_in temp_addr;
	temp_addr = p.getAddrCon();
	p.setAddrCon(temp_addr);
	
	ip_addr = dns_lookup(argv[1], temp_addr); 

	p.setIpAddr(ip_addr);
	if(p.getIpAddr().empty()) 
	{ 
		printf("\nDNS lookup failed! Could 	not resolve hostname!\n"); 
		return 0; 
	} 

	p.setReverseHostName(p.reverse_dns_lookup(p.getIpAddr())); 
	cout << "\nTrying to connect to " << " '" << argv[1] << "' is IP' "<< p.getIpAddr() << "\n";
	cout << "\nReverse Lookup domain:" << p.getReverseHostName();

	//socket() 
	p.setSockfd(socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)); 
	if(p.getSockfd()<0) 
	{ 
		printf("\nSocket file descriptor not received!!\n"); 
		return 0; 
	} 
	else
		printf("\nSocket file descriptor %d received\n", p.getSockfd()); 

	signal(SIGINT, intHandler);//catching interrupt 



	//converte endereço em formato char array para string
	string argv_str(argv[1]);

	//send pings continuously 
	//p.send_ping(p.getSockfd(), temp_addr, p.getReverseHostName(), p.getIpAddr(), argv[1]); 

	//send_ping(int ping_sockfd, struct sockaddr_in &ping_addr, string ping_dom, string ping_ip, string rev_host){
	p.send_ping(p.getSockfd(), temp_addr, p.getReverseHostName(), p.getIpAddr(), argv_str); 
	
	return 0; 
} 
