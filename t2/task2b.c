
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct virus {
    unsigned short SigSize;
    unsigned char* sig;
    char virusName[16];
} virus;

typedef struct link link;

struct link {
    link *nextVirus;
    virus *vir;
};

struct fun_desc {
    char * name;
    link * (*fun)(link*,FILE*);
};

void readVirus(virus* vir, FILE* input) {
    char SigSize[2];
    fread(SigSize, 1, 2, input);
    vir->SigSize = SigSize[0] | (SigSize[1] << 8);
    vir->sig = calloc(1,vir->SigSize);
    fread(vir->sig, 1, vir->SigSize, input);
    fread(vir->virusName, 1, 16, input);
}

void printVirus(virus* vir, FILE* output) {
    fprintf(output, "virus name: %s\n", vir->virusName);
    fprintf(output, "virus signature length: %d\n", vir->SigSize);
    fprintf(output, "virus signature:\n");
    for(size_t i=0; i < vir->SigSize; i++) {
        fprintf(output, "%02hhX ", vir->sig[i]);
    }
    fprintf(output,"\n");
}

void list_print(link *virus_list, FILE* output){
    if(virus_list==NULL){
        return;
    }
    printVirus(virus_list->vir,output);
    fprintf(output,"\n");
    list_print(virus_list->nextVirus,output);
}

link* list_append(link* virus_list, virus* to_add) {
    struct link *vList = (struct link *) (calloc(1, sizeof(struct link)));
    //vList->vir = (struct virus *) (calloc(1,sizeof(struct virus)));
    vList->vir=to_add;
    vList->nextVirus=virus_list;
    return vList;
//    struct link *indi = virus_list;
//    struct link *vList = (struct link *) (malloc(sizeof(struct link)));
//    vList->vir = (struct virus *) (malloc(sizeof(struct virus)));
//    char tmp[300] = {};
//    vList->vir->sig = tmp;
//    vList->vir->sig = to_add->sig;
//    vList->vir->SigSize = to_add->SigSize;
//    for (int i = 0; i < 16; i++) {
//        vList->vir->virusName[i] = to_add->virusName[i];
//    }
//    vList->nextVirus = NULL;
//    if(!virus_list->vir->SigSize)
//        printf("hi");
//    if (virus_list->vir!=NULL && virus_list->vir->SigSize == 0) {
//        virus_list->vir = vList->vir;
//    } else {
//        while (indi->nextVirus != NULL) {
//            indi = indi->nextVirus;
//        }
//        indi->nextVirus = vList;
//
//    }
//    return virus_list;
}


void list_free(link *virus_list) {
    if (virus_list != NULL) {
        free(virus_list->vir->sig);
        free(virus_list->vir);
        list_free(virus_list->nextVirus);
        free(virus_list);
    }
}

link * load_Signatures(link * virus_List, FILE * stream){
    if(stream == NULL){
        fprintf(stderr,"no file provided\n");
        return virus_List;
    }
    fseek(stream,0,SEEK_END);
    int length = ftell(stream);
    fseek(stream,0,SEEK_SET);
    virus* last;
    while(ftell(stream)!=length){
//        if(virus_List==NULL) {
//            virus_List = (struct link *) (malloc(sizeof(struct link)));
//            virus_List->vir = (struct virus *) (malloc(sizeof(struct virus)));
//            virus_List->nextVirus = NULL;
//        }
        last = (struct virus *) (calloc(1,sizeof(struct virus)));
        //char tmp[300] = {};
        //last->sig = tmp;
        //last->sig = calloc(1,300);
        readVirus(last,stream);
        virus_List = list_append(virus_List,last);
        //free(last->sig);
        //free(last->virusName);
        //free(last);
    }
    fclose(stream);
    return virus_List;
}

link * print_signatures(link *virus_list, FILE* output){
    list_print(virus_list,output);
    return virus_list;
}

void detect_virus(char *buffer, unsigned int size, link *virus_list){
    int k;
    link* virusListTmp;
    virusListTmp=virus_list;
    while(virusListTmp!=NULL){    //loops over all viruses in the list
        k=virusListTmp->vir->SigSize;
        for (int i=0; i <= size-k; i++){//appears in this file
            if (memcmp(buffer+i,virusListTmp->vir->sig,k) == 0){
                fprintf(stdout,"Starting byte location: %d \n",i);
                fprintf(stdout,"Virus name: %s \n",virusListTmp->vir->virusName);
                fprintf(stdout,"size of the virus signature: %d \n",k);
            }
        }
        virusListTmp=virusListTmp->nextVirus;
    }
}

link * detector(link * virus_list, FILE * stream){
    char * tmp = (char *)(calloc(1,sizeof(char)*10000));
    fseek(stream,0,SEEK_END);
    unsigned int toRead = ftell(stream);
    fseek(stream,0,SEEK_SET);
    fread(tmp,sizeof(char),toRead,stream);
    detect_virus(tmp,toRead,virus_list);
    free(tmp);
    fclose(stream);
    return virus_list;
}

link * fix_file(link * virus_list, FILE * stream){
    return virus_list;
}

void cleanList(link** virusList){
    if (*virusList!=NULL){
        list_free(*virusList);
        *virusList=NULL;
    }
}

void kill_virus(char *fileName, int signatureOffset, int signatureSize){
    FILE * stream = fopen(fileName,"r+");
    if(stream == NULL){
        printf("Can't open file\n");
        exit(EXIT_SUCCESS);
    }
    fseek(stream,signatureOffset,SEEK_SET);
    char nop[signatureSize];
    for (int i=0; i < signatureSize; i++)
        nop[i]=0x90;
    fwrite(nop,1,signatureSize,stream);
    fclose(stream);
}

void quit(link * virus_list){
    list_free(virus_list);
    //free(virus_list)
    exit(EXIT_SUCCESS);
}

link * map(link * virus_List,FILE * stream,link *(*f)(link*,FILE*)){
    link * mapped_link = (*f)(virus_List, stream);
    return mapped_link;
}

struct fun_desc menu[] = { { "Load signatures", load_Signatures},
                           { "Print signatures", print_signatures},
                           {"Detect Viruses", detector},
                           {"Fix File",fix_file},
                           {"Quit", quit},
                           { NULL, NULL }};

int main(int argc, char **argv) {
//    FILE *signatures = fopen("signatures", "r");
//    virus *vir = malloc(sizeof(virus));
//    vir->sig = malloc(300);
//    while(readVirus(vir, signatures) > 0) {
//        printVirus(vir, stdout);
//    }
//    struct link * virus_list = (struct link *)(malloc(sizeof(struct link)));
//    virus_list->vir = (struct virus *)(malloc(sizeof(struct virus)));
//    virus_list->vir->sig = malloc(300);
//    load_Signatures(virus_list,signatures);


    struct link * virus_list = (struct link *)(calloc(1,sizeof(struct link)));
    virus_list->vir = (struct virus *)(calloc(1,sizeof(struct virus)));
    virus_list->vir->sig = calloc(1,300);
    int limit = sizeof(menu)/sizeof(*(menu))-1;
    int option = -1;
    char *userInput;
    FILE * stream = stdout;
    while(1){
        for(int i = 0; i < sizeof(menu)/sizeof(*(menu))-1; i++){   //prints the menu
            printf("%d) %s\n", i+1, menu[i].name);
        }
        printf("Option: ");
        //fgets(&option, 1, stdin);
        scanf("%d", &option);
        if((option <= 0) | (option > limit) ){      //check bounds
            printf("Not within bound\n");
            cleanList(&virus_list);
            exit(EXIT_SUCCESS);
        }
        if(getc(stdin)!='\n'){            //if the second char is not ENTER
            printf("Not within bound\n");
            cleanList(&virus_list);
            exit(EXIT_SUCCESS);
        }
        printf("Within bound\n");
        if(option == 1){              //load signatures
            scanf("%ms",&userInput);
            stream = fopen(userInput,"r");    //read input file
            free(userInput);
            cleanList(&virus_list);
            if(stream == NULL){
                printf("Can't open file\n");
                cleanList(&virus_list);
            }
        }
        else{
            if(option == 3 || option == 4){   //detect or fix

                if (option == 3){      // detect
                    scanf("%ms",&userInput);
                    stream = fopen(userInput,"r");    //read input file
                    free(userInput);
                    if(stream == NULL){
                        printf("Can't open file\n");
                        cleanList(&virus_list);
                        exit(EXIT_SUCCESS);
                    }
                }
                else {                             //fix
                    scanf("%ms",&userInput);
                    stream = fopen(userInput,"r");    //read input file
                    printf("Enter first byte location: ");
                    unsigned int location;
                    scanf("%d",&location);
                    printf("Enter virus size: ");
                    unsigned int length;
                    scanf("%d",&length);
                    kill_virus(userInput,location,length);
                    free(userInput);
                    fclose(stream);
                }
                if(stream == NULL){
                    printf("Can't open file\n");
                    cleanList(&virus_list);
                    exit(EXIT_SUCCESS);
                }
                //fclose(stream);
                //free(userInput);
            }
            else
                stream = stdout;
        }
        link * tmp = map(virus_list,stream,menu[option-1].fun);
        virus_list = tmp;
        printf("DONE.\n\n");
    }
    return 0;
}

