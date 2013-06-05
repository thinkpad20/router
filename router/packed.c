#include <stdio.h>

struct Foo1 {
	char c;
	int i;
};

struct Foo2 {
	char c;
	int i;
} __attribute__ ((packed));

int main(int argc, char const *argv[])
{
	printf("size of char: %lu, size of int: %lu, size of Foo1: %lu\n",
			sizeof(char),
			sizeof(int),
			sizeof(struct Foo1));
	printf("size of char: %lu, size of int: %lu, size of Foo2: %lu\n",
			sizeof(char),
			sizeof(int),
			sizeof(struct Foo2));
	return 0;
}