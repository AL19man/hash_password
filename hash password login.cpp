#include <iostream>
#include <string>
#include <cstring>
#include <openssl/sha.h>


#include <sys/prctl.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <csignal>


//anti-d

bool hasDebuggingVariables() {
    extern char** environ;

    for (int i = 0; environ[i] != nullptr; ++i) {
        std::string envVar(environ[i]);

        // Check for specific debugging variables
        if (envVar.find("LD_PRELOAD") != std::string::npos ||
            envVar.find("LD_DEBUG") != std::string::npos ||
            envVar.find("LD_AUDIT") != std::string::npos) {
            return true;
        }
    }

    return false;
}

void  handleSIGTRAP(int signal) {
    if (signal == SIGTRAP) {
        std::cout << "Debugger activity detected." << std::endl;
        signal=1;
    }
}

//anti-d


//SHA256
std::string computeSHA256(const std::string& password)
{

    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, password.c_str(), password.length());
    SHA256_Final(hash, &sha256);


    std::string hashString;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
    {
        char hex[3];
        sprintf(hex, "%02x", hash[i]);
        hashString += hex;
    }

    return hashString;
}

int main()
{
        //check core dump anti-d
    if (prctl(PR_SET_DUMPABLE, 0) == -1) {
        std::cout << "Debugger activity detected." << std::endl;
        return 0;
    }
       //check varibles for anti-d
    if (hasDebuggingVariables()) {
        std::cout << "Debugger activity detected." << std::endl;
        return 0;
    }
       //check signals for beakpoint
    signal(SIGTRAP, handleSIGTRAP);



    std::string storedHash = "c810e76f2125db71bfbdd7e29ce902f37f5b2250c48c16d241bd46c70aed1a91"; // hash of the password

    std::string password;
    std::cout << "Enter your password: ";
    std::cin >> password;

    std::string inputHash = computeSHA256(password);

    if (inputHash == storedHash)
    {

        std::cout << "Password is correct." << std::endl;
    }
    else
    {

        std::cout << "Password is incorrect." << std::endl;
    }

    return 0;
}
