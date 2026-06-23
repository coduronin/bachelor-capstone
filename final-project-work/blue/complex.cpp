#include <iostream>
#include <string>

// Phase 1: Identifier Scrambling (main function logic moved to f_8b2d1c)
int f_8b2d1c(int input_val)
{
    // Phase 2: Variable declaration & Central Dispatcher State
    unsigned int swVar = 1;

    // Phase 2: Central Dispatcher Architecture
    // Logic is flattened to destroy linear control flow
    while (swVar != 0)
    {
        switch (swVar)
        {
        case 1:
            // Phase 3: Bi-Opaque Predicate
            // The check is mathematically locked; static analysis tools cannot prune this branch
            if ((7 * (input_val * input_val) - 1) == 10659291)
            {
                swVar = 2; // Route to success
            }
            else
            {
                swVar = 3; // Route to failure
            }
            break;

        case 2:
            // Phase 4: Metamorphic/Runtime Mutation
            // "Welcome back king" properly XOR'd with 0x05
            {
                char e[] = {0x52, 0x60, 0x69, 0x66, 0x6A, 0x68, 0x60, 0x25, 0x67, 0x64, 0x66, 0x6E, 0x25, 0x6E, 0x6C, 0x6B, 0x62};
                for (int i = 0; i < 17; i++)
                {
                    std::cout << (char)(e[i] ^ 0x05);
                }
            }
            swVar = 0; // Terminate
            break;

        case 3:
            std::cout << "Access denied";
            swVar = 0; // Terminate
            break;
        }
    }
    return 0;
}

int main()
{
    int password;
    std::cout << "Enter Password: ";
    std::cin >> password;
    f_8b2d1c(password);
    return 0;
}