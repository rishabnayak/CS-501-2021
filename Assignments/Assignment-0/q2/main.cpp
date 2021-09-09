#include <iostream>
#include <cstdlib>
using namespace std;

// Computes the nth fibonacci number (upto 47)
// int has 32 bits, so the max number represented by int is 2^31 - 1
// the 47th fibonacci number is greater than the max int, so it generates an error

// if the function Fibonacci is not defined, the compiler generates a
// warning saying that the non-void function does not return a value,
// and while the program compiles, it does not generate an output

int Fibonacci(int n)
{
	int fib1 = 0, fib2 = 1, fibsum;

	if (n == 0)
	{
		return fib1;
	}

	for (int i = 2; i <= n; ++i)
	{
		fibsum = fib1 + fib2;
		fib1 = fib2;
		fib2 = fibsum;
	}

	return fibsum;
}

int main(int argc, char *argv[])
{
	if (argc != 2)
	{
		cout << "Usage: ./main.exe <int>" << endl;
		return 0;
	}
	int n = atoi(argv[1]);
	cout << Fibonacci(n) << endl;
}