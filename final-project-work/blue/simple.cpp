#include <iostream>
int main()
{
    int password;
    std::cout << "Enter Password: ";
    std::cin >> password;
    if (password == 1234)
    {
        std::cout << "Welcome back king";
    }
    else
    {
        std::cout << "Access denied";
    }
    return 0;
}