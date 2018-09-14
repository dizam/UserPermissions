#ifndef ACCESS_H_
#define ACCESS_H_

void printError(int errorCode);
void printErrorDynamic(int errorCode, char* userInput);
int checkInput(int argc, char* argv[]);
void idUser(int argc, char* argv[]);
void idGroup(int argc, char* argv[]); 
void fileIDStat(int argc, char* argv[], char* userName, uid_t userID, gid_t groupID);
void printFilePermissions(char* userName, uid_t userID, char* groupName, gid_t groupID, char* fileName, int permissions, int fileType, int accessType);
void getFileInfo(char* fileName, int* fileType, int* permissions, uid_t userID, gid_t groupID);
void fileGroupStat(int argc, char* argv[], char* groupName, gid_t groupID);
#endif //ACCESS_H_
