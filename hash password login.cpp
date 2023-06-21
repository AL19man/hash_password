#include <iostream>
#include <string>
#include <cstring>
#include <openssl/sha.h>
#include <openssl/md5.h>


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
    string password;


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
    std::string password1 = "c810e76f2125db71bfbdd7e29ce902f37f5b2250c48c16d241bd46c70aed1a91";
    std::string password2 = "c810e76f2125db71bfbdd7e29ce902f37f5b2250c48c16d241bd46c70aed1a91";
    std::string password3 = "c810e76f2125db71bfbdd7e29ce902f37f5b2250c48c16d241bd46c70aed1a91";


public:
    // AccountManager(int maxAttempts, int duration) : maxFailedAttempts(maxAttempts), lockoutDuration(duration) {}

    // Register a new user account
    void registerAccount(const string& username, const string& word, bool locked) {
        UserAccount account;
        account.username = username;
        account.password = word;
        account.failedAttempts = 0;
        account.locked = locked;
        accounts[username] = account;
    }

    // delete user account
    void deleteAccount(const string& username, const string& word, bool locked ) {
        UserAccount account;
        account.username.clear();
        account.password.clear();
        account.failedAttempts = 0;
        account.locked = false;
        accounts[username] = account;
    }

bool validate_passphrase(const string& username,std::string line_pass,bool random_number, int start_random_sec , int end_random_sec, int not_random,std::string hash_chose) {
    

      AccountManager manager; 
      UserAccount& account = accounts[username];
      std::string input =line_sha256(line_pass,hash_chose);
      // Tokenize the input string into words
      std::string delimiter = " ";
      size_t startPos = 0;
      size_t endPos = input.find(delimiter);


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
	  

//verify random 
	if(rundom_number==true && account.failedAttempts >= maxFailedAttempts)
	{
		
		 manager.lockoutDuration=rand_number(start_random_sec ,end_random_sec);
	}
	if(rundom_number==false && account.failedAttempts >= maxFailedAttempts)
	{
		
		 manager.lockoutDuration=rand_number(not_random ,not_random);
	}
//verify random 


 if (account.failedAttempts >= maxFailedAttempts) {
           account.locked = true;
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
        if (word == password2  && startPos == input.find(password1) + password1.length() + delimiter.length()) {
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
    if (lastWord ==  password3 && startPos == input.find(password2) + password2.length() + delimiter.length()) {
        std::cout << "Password 3 is correct and in the expected position." << std::endl;
    }

	  }
	  }
    return 0;
}



//string to SHA1
std::string computeSHA(const std::string& password) {
    unsigned char hash[SHA_DIGEST_LENGTH];
    SHA_CTX sha1;
    SHA1_Init(&sha1);
    SHA1_Update(&sha1, password.c_str(), password.length());
    SHA1_Final(hash, &sha1);

    std::string hashString;
    char hex[3];
    for (int i = 0; i < SHA_DIGEST_LENGTH; ++i) {
        sprintf(hex, "%02x", hash[i]);
        hashString += hex;
    }

    return hashString;
}
//string to SHA1
//string to MD5
std::string computeMD5(const std::string& password) {
unsigned char hash[MD5_DIGEST_LENGTH];
    MD5_CTX md5;
    MD5_Init(&md5);
    MD5_Update(&md5, password.c_str(), password.length());
    MD5_Final(hash, &md5);

    std::string hashString;
    char hex[3];
    for (int i = 0; i < MD5_DIGEST_LENGTH; ++i) {
        sprintf(hex, "%02x", hash[i]);
        hashString += hex;
    }

    return hashString;
}
//string to MD5
//string to SHA256 
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
//string to SHA256

//get password sentance  change sentance to hash 
std::string line_sha256(std::string password, std::string hash_chose){


	std::string hashedPassword;
    std::string word;
    std::string::size_type start = 0;
    std::string::size_type end = password.find(' ');

    while (end != std::string::npos) {
        word = password.substr(start, end - start);
		if (hash_chose=="sha256"){hashedPassword +=computeSHA256(word)+" ";}
		if (hash_chose=="md5"){hashedPassword +=computeMD5(word)+" ";}
		if (hash_chose=="sha1"){hashedPassword +=computeSHA(word)+" ";}
		
        start = end + 1;
        end = password.find(' ', start);
    }

    if (start != password.length()) {
        word = password.substr(start);
        if (hash_chose=="sha256"){hashedPassword +=computeSHA256(word)+" ";}
		if (hash_chose=="md5"){hashedPassword +=computeMD5(word)+" ";}
		if (hash_chose=="sha1"){hashedPassword +=computeSHA(word)+" ";}
    }

    std::cout << "Hashed password: " << hashedPassword << std::endl;
	
	
	
	return hashedPassword;
}

//rundom number between start_random , end_random second to anti-bruteforce
int rand_number(int start_random_sec, int end_random_sec) {
    std::random_device rd;  // Obtain a random seed from the hardware
    std::mt19937 gen(rd());  // Standard mersenne_twister_engine seeded with rd()

    std::uniform_int_distribution<> dis(start_random_sec, end_random_sec);  // Define the range

    int randomNumber = dis(gen);  // Generate the random number

    cout<<"random number"<<randomNumber<< endl;

    return randomNumber;
}
//rundom number between start_random , end_random second to anti-bruteforce


//anti-d
bool hasDebuggingVariables() {
    extern char** environ;

    for (int i = 0; environ[i] != nullptr; ++i) {
        std::string envVar(environ[i]);

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

};
 //end of class ***************************************
   
   int main()
{
/*
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
*/


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


 //   std::string inputHash = computeSHA256(password);

    if ( account.locked == false)
    {

    manager.validate_passphrase( "user1",password,true,30,60,0,"sha256");
        //std::cout << "Password is correct." << std::endl;
    }
    else
    {
    manager.validate_passphrase("user1", password,true,30,60,0,"sha256");
    	//std::cout << "Account locked" << std::endl;
    }


    }
    return 0;
}

