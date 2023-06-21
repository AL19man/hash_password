#include <iostream>
#include <string>
#include <cstring>
#include <openssl/sha.h>


#include <sys/prctl.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <csignal>


#include <unordered_map>
#include <chrono>
#include <thread>
#include <random>




//account lock class
//
//
using namespace std;
using namespace std::chrono;

// Structure to hold user account information
struct UserAccount {
    string username;
    string password1="c810e76f2125db71bfbdd7e29ce902f37f5b2250c48c16d241bd46c70aed1a91";
    string password2="c810e76f2125db71bfbdd7e29ce902f37f5b2250c48c16d241bd46c70aed1a91";
    string password3="c810e76f2125db71bfbdd7e29ce902f37f5b2250c48c16d241bd46c70aed1a91";
    string password4;


    int failedAttempts;
    bool locked;
    time_point<system_clock> unlockTime;
};

// Class to manage user accounts and lockout mechanism
class AccountManager {
private:
    unordered_map<string, UserAccount> accounts;
    int maxFailedAttempts=3;
    int lockoutDuration;
    

public:
    // AccountManager(int maxAttempts, int duration) : maxFailedAttempts(maxAttempts), lockoutDuration(duration) {}

    // Register a new user account
    void registerAccount(const string& username, const string& password) {
        UserAccount account;
        account.username = "user1";
        account.password1 = password;
        account.failedAttempts = 0;
        account.locked = false;
        accounts[username] = account;
    }


bool validate_passphrase(const string& username,std::string input) {
    

      AccountManager manager; 
    
      UserAccount& account = accounts[username];

      if (account.locked==true  && system_clock::now() < account.unlockTime) {
                cout << "Account locked. Please try again later." << endl;
                return false;
      }
	  
	   if (system_clock::now() < account.unlockTime  ) {  // (account.password1 == password1

                account.failedAttempts = 0;  // Reset failed attempts on successful login
                return true;
      } else {
                account.failedAttempts++;
                //cout << "Incorrect password." << endl;
	  




    // Define the passwords
    std::string password1 = "password1";
    std::string password2 = "password2";
    std::string password3 = "password3";

    // Tokenize the input string into words
    std::string delimiter = " ";
    size_t startPos = 0;
    size_t endPos = input.find(delimiter);

 if (account.failedAttempts >= maxFailedAttempts) {
                    account.locked = true;
		 // AccountManager manager (2,rand_number());
                  // manager.maxFailedAttempts=2;
		   manager.lockoutDuration=rand_number();
		   account.unlockTime = system_clock::now() + seconds(lockoutDuration);
                   cout << "Account locked. Please try again after "<<endl; //<< lockoutDuration << " seconds." << endl;
      }else{

    while (endPos != std::string::npos) {
        // Extract a word from the input string
        std::string word = input.substr(startPos, endPos - startPos);

        // Compare the word with each password
        if (word == password1 && startPos == 0) {
            std::cout << "Password 1 is correct and in the first position." << std::endl;
        }
        if (word == password2 && startPos == input.find(password1) + password1.length() + delimiter.length()) {
            std::cout << "Password 2 is correct and in the expected position." << std::endl;
        }
        if (word == password3 && startPos == input.find(password2) + password2.length() + delimiter.length()) {
            std::cout << "Password 3 is correct and in the expected position." << std::endl;
        }

        // Move to the next word
        startPos = endPos + delimiter.length();
        endPos = input.find(delimiter, startPos);
    }

  
  // Compare the last word in the input string
    std::string lastWord = input.substr(startPos);
    if (lastWord == password3 && startPos == input.find(password2) + password2.length() + delimiter.length()) {
        std::cout << "Password 3 is correct and in the expected position." << std::endl;
    }

	  }
	  }
    return 0;
}



    // Validate user credentials
    bool validateCredentials(const string& username, const string& password) {




     


                return false;
      
	    }


      //rundom number between 30 -60 secund to anti-bruteforce
int rand_number() {
    std::random_device rd;  // Obtain a random seed from the hardware
    std::mt19937 gen(rd());  // Standard mersenne_twister_engine seeded with rd()

    std::uniform_int_distribution<> dis(30, 60);  // Define the range

    int randomNumber = dis(gen);  // Generate the random number

    cout<<"random number"<<randomNumber<< endl;

    return randomNumber;
}





};


//account lock class






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
std::string computeSHA256(const std::string& password){ 
	
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
//SHA256

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



  //  std::string storedHash = "c810e76f2125db71bfbdd7e29ce902f37f5b2250c48c16d241bd46c70aed1a91"; // hash of the password

    //std::string password;


    //main validation with all functions 
    AccountManager manager ;
    UserAccount account;
    while(true){
	   	     
    //std::cout << "Enter your password: ";
   // std::cin >> password;
    std::string password;
    std::cout << "Enter a string of words: ";
    std::getline(std::cin, password);
    std::cout<<"password entered : "<<password <<endl;


    std::string inputHash = computeSHA256(password);

    if ( account.locked == false)
    {

    manager.validate_passphrase( "user1",password);
        //std::cout << "Password is correct." << std::endl;
    }
    else
    {
    manager.validate_passphrase("user1", password);
    	//std::cout << "Account locked" << std::endl;
    }


    }
    return 0;
}
