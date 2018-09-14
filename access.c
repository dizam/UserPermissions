#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pwd.h>
#include <grp.h>
#include <ctype.h>
#include "access.h"

#define MISSING_ARGUMENTS -11
#define MISSING_GROUP -12

#define INTEGER_OVERFLOW -21
#define USERNAME_NOT_FOUND -22
#define MISSING_FILENAME -23
#define GROUP_NOT_FOUND -24

#define NOT_A_NUMBER -31
#define IS_A_NUMBER 31

#define FILE_NOT_FOUND -41

#define USER_FLAG 11
#define GROUP_FLAG 12

#define FILE_FLAG 21
#define DIRECTORY_FLAG 22

#define NO_ERROR 0

//program to get access permissions of user or group on a file
int main (int argc, char* argv[])
{
	//struct stat sb; 
	//check first part of input
	int inputStatus = checkInput(argc, argv);
	//valid input with username or user id
	if (inputStatus == USER_FLAG)
	{
		idUser(argc, argv);
	}
	//valid input with -g to specify group
	else if (inputStatus == GROUP_FLAG)
	{
		idGroup(argc, argv);
	}		
}
/*simple function to check if input string is a number by checking if each
digit is a number. Any non-number digit results in NaN*/
int isNumber(char* input)
{
	//strnlen is used because its safer than strlen with no null terminated input
	//also max integer is 2,147,483,687 so at most 10 characters must be checked
	int stringLength = strnlen(input, 11); 
	int i;
	for (i = 0; i < stringLength; i++)
	{
		if( isdigit(input[i]) == 0)
		{
			return NOT_A_NUMBER;
		}
	}
	return IS_A_NUMBER;
}
//handle identifying the user in the commmand
void idUser(int argc, char* argv[])
{
	//test for user ir overflow
	char* inputName = argv[1];
	long testOverflow = (atol(inputName));
	if (testOverflow > 0x7FFFFFFF)
	{
		printErrorDynamic(INTEGER_OVERFLOW, inputName);
	}
	//convert user input for user info into a number
	uid_t inputUID = (uid_t)(atoi(inputName));
	struct passwd *userInfo;
	char* userName = NULL;
	uid_t userID = 0;
	gid_t groupID = 0;
	int numberStatus = isNumber(inputName);
	//check if input ID is a number
	if (numberStatus == NOT_A_NUMBER)
	{
		//not a number, get user info by name
		userInfo = getpwnam(inputName);
		//no user name, print error
		if (userInfo == NULL)
		{
			printErrorDynamic(USERNAME_NOT_FOUND, inputName);
		}
		userName = userInfo->pw_name;
		userID = userInfo->pw_uid;
		groupID = userInfo->pw_gid;
	}
	if (numberStatus == IS_A_NUMBER)
	{
		//is a number, get user info by id
		userInfo = getpwuid(inputUID);
		//only set username and groupID if user was found
		if (userInfo != NULL)
		{
			userName = userInfo->pw_name;
			groupID = userInfo->pw_gid;
		}
		userID = inputUID;
	}
	//missing file name after specifying user
	if (argc < 3)
	{
		printErrorDynamic(MISSING_FILENAME, argv[0]);
	}
	//valid command, check permissions
	else
	{
		fileIDStat(argc, argv, userName, userID, groupID);
	} 
}
//handle identifying the group in the command if -g is specified
void idGroup(int argc, char* argv[])
{
	//test for group id overflow
	char* inputName = argv[2];
	long testOverflow = (atol(inputName));
	if (testOverflow > 0x7FFFFFFF)
	{	
		printErrorDynamic(INTEGER_OVERFLOW, inputName);
	}
	//convert user input for group into a number
	gid_t inputGID = (gid_t)(atoi(inputName));
	struct group *groupInfo;
	char* groupName = NULL;
	gid_t groupID = 0;
	int numberStatus = isNumber(inputName);
	//check if group was specified by id or name
	if (numberStatus == NOT_A_NUMBER)
	{
		//not a number, get group info by name
		groupInfo = getgrnam(inputName);
		//no group name, print error
		if (groupInfo == NULL)
		{
			printErrorDynamic(GROUP_NOT_FOUND, inputName);
		}
		groupName = groupInfo->gr_name;
		groupID = groupInfo->gr_gid;
	}
	if (numberStatus == IS_A_NUMBER)
	{
		//is a number, get group info by id
		groupInfo = getgrgid(inputGID);
		//only set groupname if group was found
		if (groupInfo != NULL)
		{
			groupName = groupInfo->gr_name;
		}
		groupID = inputGID;
	}
	//missing file name after specifying group
	if (argc < 4)
	{
		printErrorDynamic(MISSING_FILENAME, argv[0]);
	}
	//valid command, check permissions
	else
	{
		fileGroupStat(argc, argv, groupName, groupID);
	}
}

//gets file information and file permissions that correspond to input user or group
void getFileInfo(char* fileName, int* fileType, int* permissions, uid_t userID, gid_t groupID)
{
	struct stat fileInformation;
	//call stat to get file information by file name
	int fileStatus = stat(fileName, &fileInformation);
	//file was not found
	if (fileStatus < 0)
	{
		printErrorDynamic(FILE_NOT_FOUND, fileName);
	}
	else
	{
		uid_t userFileID = fileInformation.st_uid;
		gid_t groupFileID = fileInformation.st_gid;
		//check if directory or file using S_IFMT mask
		if ((fileInformation.st_mode & S_IFMT) == S_IFDIR)
		{
			//is a directory
			*fileType = DIRECTORY_FLAG;
		}
		else
		{
			//is a file
			*fileType = FILE_FLAG;
		}
		//get permissions of file with mask 07777
		int allPermissions = (fileInformation.st_mode & 07777);
		int maskedPermissions = 0;
		//check group user belongs to
		if (userFileID == userID)
		{
			//owner permissions with mask 00700
			maskedPermissions = (allPermissions & 00700) >> 6;
			*permissions = maskedPermissions;
			return;
		}
		if (groupFileID == groupID)
		{
			//group permissions with mask 00070
			maskedPermissions = (allPermissions & 00070) >> 3;
			*permissions = maskedPermissions;
			return;
		}
		//otherwise user is other permissions with mask 00007
		maskedPermissions = (allPermissions & 00007);	
		*permissions = maskedPermissions;
	}
}

//checks permissions that the user has on the file
void fileIDStat(int argc, char* argv[], char* userName, uid_t userID, gid_t groupID)
{
	int fileIndex;
	//loop through each filename, get file information, and print result
	for (fileIndex = 2; fileIndex < argc; fileIndex++)
	{
		char* fileName = argv[fileIndex];
		int permissions = 0;
		int fileType = 0;
		//pointers used to avoid redundancy of code for group flag stat
		getFileInfo(fileName, &fileType, &permissions, userID, groupID);
		//print permissions for a user on the file
		printFilePermissions(userName, userID, NULL, groupID, fileName, permissions, fileType, USER_FLAG);
	}
}

//function to print what the user or group can do on the file based on octal permissions of UNIX and access type
void printFilePermissions(char* userName, uid_t userID, char* groupName, gid_t groupID, char* fileName, int permissions, int fileType, int accessType)
{
	//-g was specified for group
	if (accessType == GROUP_FLAG)
	{
		//group ID with no group name
		if (groupName == NULL)
		{
			printf("Members of the group with GID %d can ", groupID);
		}
		//user id with a user name
		else
		{
			printf("Members of the group %s (GID %d) can ", groupName, groupID);
		} 
	}
	//no -g so user is specified
	else
	{	
		//user ID with no user name
		if (userName == NULL)
		{
			printf("The user with UID %d can ", userID);
		}
		//user id with a user name
		else
		{
			printf("The user %s (UID %d) can ", userName, userID);
		} 
	}
	//if file is of type directory, alter print message to list, modify, and search
	if (fileType == DIRECTORY_FLAG)
	{
		switch (permissions)
		{
			case 0:	
				printf("do nothing with the directory %s\n", fileName);
				break;
			case 1:
				printf("search the directory %s\n", fileName);
				break;
			case 2:
				printf("modify the directory %s\n", fileName);
				break;
			case 3:
				printf("modify and search the directory %s\n", fileName);
				break;
			case 4:
				printf("list the contents of the directory %s\n", fileName);
				break;
			case 5:
				printf("list the contents of and search the directory %s\n", fileName);
				break;
			case 6:
				printf("list the contents of and modify the directory %s\n", fileName);
				break;
			case 7:
				printf("list the contents of, modify, and search the directory %s\n", fileName);
				break;
		}
	}
	//if file is of type file, alter print message to read, write, and execute
	else
	{
		switch (permissions)
		{
			case 0:
				printf("do nothing with the file %s\n", fileName);
				break;
			case 1:
				printf("execute the file %s\n", fileName);
				break;
			case 2:
				printf("write the file %s\n", fileName);
				break;
			case 3:
				printf("write and execute the file %s\n", fileName);
				break;
			case 4:
				printf("read the file %s\n", fileName);
				break;
			case 5:
				printf("read and execute the file %s\n", fileName);
				break;
			case 6:
				printf("read and write the file %s\n", fileName);
				break;
			case 7:
				printf("read, write, and execute the file %s\n", fileName);
				break;
		}
	}
} 
//checks permissions that the group has on the file
void fileGroupStat(int argc, char* argv[], char* groupName, gid_t groupID)
{
	int fileIndex;
	//loop through each filename and print result
	for (fileIndex = 3; fileIndex < argc; fileIndex++)
	{
		char* fileName = argv[fileIndex];
		
		int permissions = 0;
		int fileType = 0;
		//pointers used to avoid redundancy of code for user stat
		//note -1 is used for userID since this is a group stat and -1 cannot be a valid userID
		getFileInfo(fileName, &fileType, &permissions, -1, groupID);
		//print permissions for a group on the file
		printFilePermissions(NULL, -1, groupName, groupID, fileName, permissions, fileType, GROUP_FLAG);
	}
}
 
//print static errors that are not based on variables in the command
void printError(int errorCode)
{
	switch(errorCode)
	{
		case MISSING_ARGUMENTS:
			fprintf(stderr, "usage: access [ -g ] name file1 ...\n");
			break;
	}
	exit(EXIT_FAILURE);
}
//print dynamic errors that are based on variables in the command
void printErrorDynamic(int errorCode, char* userInput)
{
	switch(errorCode)
	{
		case USERNAME_NOT_FOUND:
			fprintf(stderr, "%s: no such user\n", userInput);
			break;
		case MISSING_GROUP:
			fprintf(stderr, "Usage: %s: -g requires group name\n", userInput);
			break;
		case MISSING_FILENAME:
			fprintf(stderr, "%s: need at least one file or directory!\n", userInput);
			break;
		case GROUP_NOT_FOUND:
			fprintf(stderr, "%s: no such group\n", userInput);
			break; 
		case INTEGER_OVERFLOW:
			fprintf(stderr, "%s: number too big\n", userInput);
			break;
		case FILE_NOT_FOUND:
			fprintf(stderr, "%s: No such file or directory\n", userInput);
			break; 
	}
	exit(EXIT_FAILURE); 
}
//checks initial part of command for errors
//also parses for -g flag for group
int checkInput(int argc, char* argv[])
{
	//no arguments specified: access ""
	if (argc == 1)
	{
		printError(MISSING_ARGUMENTS); 
	}
	char groupFlag[3] = "-g";
	//only -g specified: access -g ""
	if (argc == 2 && !(strncmp(groupFlag, argv[1], 3)))
	{
		printErrorDynamic(MISSING_GROUP, argv[0]);
	}
	//valid command so far with -g flag for groups
	if (argc > 2 && !(strncmp(groupFlag, argv[1], 3)))
	{
		return GROUP_FLAG;
	}
	//valid command so far with no -g flag for users
	else
	{
		return USER_FLAG;
	}
}	
