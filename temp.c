#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_LINE_LENGTH 100
#define MAX_ID_LENGTH 20
#define MAX_PASSWORD_LENGTH 50

int main() {
    FILE *file;
    char line[MAX_LINE_LENGTH];
    char id[MAX_ID_LENGTH];
    char password[MAX_PASSWORD_LENGTH];
    int search_id;

    // Open the file
    file = fopen("securedb.txt", "r");
    if (file == NULL) {
        perror("Error opening file");
        return 1;
    }

    // Get the ID to search for
    printf("Enter ID: ");
    if (scanf("%d", &search_id) != 1) {
        printf("Invalid input\n");
        fclose(file);
        return 1;
    }

    // Search for the ID in the file
    while (fgets(line, sizeof(line), file) != NULL) {
        if (sscanf(line, "%9s %[^\n]", id, password) == 2) {
            if (atoi(id) == search_id) {
                printf("Password for ID %d: %s\n", search_id, password);
                fclose(file);
                return 0;
            }
        }
    }

    // ID not found
    printf("ID %d not found\n", search_id);
    fclose(file);
    return 0;
}

