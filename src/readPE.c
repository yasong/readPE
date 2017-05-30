/* 
* @Author: Xiaokang Yin
* @Date:   2017-05-30 10:03:36
* @Last Modified by:   xiaokang
* @Last Modified time: 2017-05-30 13:52:36
*/

#include <stdio.h>
#include <string.h>
#include "readELF.h"
#define MAX_LEN     60*1024*1024
const char software_name[] = "readELF";


u_char buf[MAX_LEN];

void show_usage();
void show_header(const u_char *data);
void show_program_header(const u_char *data);
void show_section_header(const u_char *data);
void show_section_name(const u_char *data);
void show_all(const u_char *data);
void show_version();

void show_usage()
{
    printf("Usage: ./%s [options] <elf file>\n\n", software_name);

    printf("Available options:\n"
           "  -H : show the usage information\n\n"
           "  -h <elf file> : display the header information\n\n"
           "  -a <elf file> : display all the information\n\n"
           "  -S <elf file> : display the section  header information\n\n"
           "  -s <elf file>  : display symbol table\n\n"
           "  -v : Displaye the version number of readELF\n\n"
        );
    printf("or\n\n");
    printf("Usage: ./%s<elf file>\n\n", software_name);
    printf("then after the 'cmd>' come\n");
    printf("you can input the command:\n"
           "  H : show the usage information\n\n"
           "  h : display the header information\n\n"
           "  a : display all the information\n\n"
           "  S : display the section  header information\n\n"
           "  s : display symbol table\n\n"
           "  v : Displaye the version number of readELF"
           "  q: quit the command shell\n\n"
        );

}
void show_header(const u_char *data)
{

}
void show_program_header(const u_char *data)
{

}
void show_section_header(const u_char *data)
{
   
}
void show_section_name(const u_char *data)
{
   

}
void show_symbol(const u_char *data)
{


}
void show_all(const u_char *data)
{
    show_header(data);
    printf("\n\n");
    show_program_header(data);
    printf("\n\n");
    show_section_header(data);
    printf("\n\n");
    show_symbol(data);
}

void show_version()
{
    printf("readPE 0.1.0, build time 2017.5.30\n");
    printf("Copyright (C) YinXiaokang\n");
}

void read_pe(const u_char *data)
{

}
int main(int argc, char *argv[]) 
{
    char *option;
    char cmd;
    //u_char buf[MAX_LEN];
    int len = 0;
    FILE  *pe;
    if (argc == 1)
    {
        show_usage();
        return 0;
    }
    if(argc > 3) return -1;
    if (argc == 2) 
    {
        if(strcmp(argv[1],"-H") == 0)
        {
            show_usage();
            return 0;
        }
        if(strcmp(argv[1],"-v") == 0)
        {
            show_version();
            return 0;
        }
        else
        {   printf("argc =  %d\n", argc);
            printf("file name %s\n",argv[1]);
            elf = fopen(argv[1], "rb+") ;
            if(elf == NULL)
            {
                printf("Open error\n");
                printf("File %s cannot be opened\n", argv[1]);
                exit(-1);
            }
            show_usage();
            len = fread(buf,1,MAX_LEN,elf);
            buf[len] = '\0';
            printf("cmd> ");
            scanf("%s",&cmd);
            while(cmd != 'q')
            {
                switch(cmd)
                {
                    case 'H':
                        show_usage();
                        break;
                    case 'h':
                        show_header(buf);
                        break;
                    case 'p':
                        show_program_header(buf);
                        break;
                    case 'S':
                        show_section_header(buf);
                        break;
                    case 's':
                        show_symbol(buf);
                        break;
                    case 'n':
                        show_section_name(buf);
                        break;
                    case 'a':
                        show_all(buf);
                        break;
                    case 'v':
                        show_version();
                        break;
                    default:
                        break;
                }
                printf("cmd> ");
                scanf("%s",&cmd);
                //scanf("%c",&cmd);
            }
            fclose(pe);
            return 0;

        }
        
    }
    option = argv[1];
    elf = fopen(argv[2], "rb+") ;
    if(elf == NULL)
    {
        printf("Open error\n");
        printf("FIle %s cannot be opened\n", argv[2]);
        exit(-1);
    }
    len = fread(buf,1,MAX_LEN,elf);
    buf[len] = '\0';
    switch(option[1])
    {
        case 'H':
            show_usage();
            break;
        case 'h':
            show_header(buf);
            break;
        case 'p':
            show_program_header(buf);
            break;
        case 'S':
            show_section_header(buf);
            break;
        case 's':
            show_symbol(buf);
            break;
        case 'n':
            show_section_name(buf);
            break;
        case 'a':
            show_all(buf);
            break;
        case 'v':
            show_version();
            break;
        default:
            break;
    }
    fclose(pe);
    return 0;
}
