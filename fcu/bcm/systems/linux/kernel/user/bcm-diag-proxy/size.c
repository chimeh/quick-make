#include <stdio.h>
#include <stddef.h>

int main(void)
{
    char n = 2;
    size_t size;
    size = sizeof(void);
    printf("%*u: void\n", n,size);
    
    size = sizeof(void *);
    printf("%*u: voidp\n", n,size);
    
    size = sizeof(char);
    printf("%*u: char\n", n,size);

    size = sizeof(unsigned char);
    printf("%*u: unsigned char\n", n,size);

    size = sizeof(short);
    printf("%*u: short\n", n,size);

    size = sizeof(unsigned short);
    printf("%*u: unsigned short\n", n,size);

    size = sizeof(int);
    printf("%*u: int\n", n,size);

    size = sizeof(unsigned);
    printf("%*u: unsigned\n", n,size);

    size = sizeof(long);
    printf("%*u: long\n", n,size);

    size = sizeof(unsigned long);
    printf("%*u: unsigned long\n", n,size);

    size = sizeof(long long);
    printf("%*u: long long\n", n,size);

    size = sizeof(unsigned long long);
    printf("%*u: unsigned long long\n", n,size);

    size = sizeof(float);
    printf("%*u: float\n", n,size);

    size = sizeof(double);
    printf("%*u: double\n", n,size);

    size = sizeof(long double);
    printf("%*u: long double\n", n,size);
    
    size = sizeof(size_t);
    printf("%*u: size_t\n", n,size);
    
    getchar();
    return 0;
}
