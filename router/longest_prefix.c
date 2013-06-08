#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

// const char *ips[] = {
// 	"128.135.1.2",
// 	"128.187.1.2",
// 	"198.1.2.17",
// 	"87.135.1.2",
// 	"128.135.2.4",
// };

unsigned ips[] = {
	23948723,
	349587394,
	934857394,
	239873765,
	934879323,
	1384273487,
};

const int num_ips = sizeof(ips)/sizeof(unsigned);

int main(int argc, char const *argv[])
{
	int i, best_match = -1;
	unsigned result = 0; /* in our code, result will be a sr_rt * instead of a char * */
	char buf[INET_ADDRSTRLEN];
	if (argc < 2) return 0;
	unsigned search = atoi(argv[1]);
	printf("You entered: %u = %s\n", search, 
									inet_ntop(AF_INET, &search, buf, INET_ADDRSTRLEN));
	printf("The candidates are:\n");
	for (i=0; i<num_ips; ++i) {
		unsigned ip = ips[i];
		printf("\t%s\n", inet_ntop(AF_INET, &ips[i], buf, INET_ADDRSTRLEN));
		int j;
		for (j = 0; j < sizeof(search); ++j) {
			if (((char *)&ips[i] + j) != ((char *)&search +j)) break;
			if (j > best_match)  {
				result = ip;
				best_match = j;
			}
		}
	}
	printf("the best match is %u = %s\n", result,
									inet_ntop(AF_INET, &search, buf, INET_ADDRSTRLEN));
	return 0;
}