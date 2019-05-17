#include<stdio.h>
#include<stdlib.h>

#define MAX 20

int main(){
    char i,j,k;
    int n=0;
    char command[19]="dig aaa.example.com";
    srand(time(0));
    for(i='a'+rand()%26;i<='z';i++){
        command[4]=i;
        for(j='a'+rand()%26;j<='z';j++){
            command[5]=j;
            for(k='a'+rand()%26;k<='z';k++){
                command[6]=k;
                system(command);
                if(n >= MAX)
                    return 0;
                n++;
            }
        }
    }
}