#include <windows.h>

int main(int argc, char *argv[])
{
	if (argc == 1)
	{
		MessageBoxA(0, "Hello world!", "I am a message box!", MB_OK);
	}
	if (argc == 2)
	{
		MessageBoxA(0, argv[argc - 1], "I am a message box!", MB_OK);
	}
	else if (argc == 3)
	{
		MessageBoxA(0, argv[argc - 2], argv[argc - 1], MB_OK);
	}
	else
	{
		MessageBoxA(0, "Enter no more than 2 arguments!", "Error", MB_OK);
	}
}