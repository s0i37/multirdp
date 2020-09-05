#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>
#include <winbase.h>
#include <winnt.h>

#define PAGE 4096
#define SIGNATURE_LEN 0x10

static const unsigned char termsrv_nt5_signature1_original[SIGNATURE_LEN] = {'\x74','\x04','\x33','\xc0','\xeb','\x2c','\x8b','\x51','\x10','\x8b','\x41','\x0c','\x3b','\xd0','\x74','\x11'};
static const unsigned char termsrv_nt5_signature1_patched[SIGNATURE_LEN] = {'\x75','\x04','\x33','\xc0','\xeb','\x2c','\x8b','\x51','\x10','\x8b','\x41','\x0c','\x3b','\xd0','\x74','\x11'};
static const unsigned char termsrv_nt5_signature2_original[SIGNATURE_LEN] = {'\x7f','\x16','\x8b','\x45','\x08','\x8b','\x00','\x8b','\x80','\x08','\x34','\x00','\x00','\xc7','\x40','\x24'};
static const unsigned char termsrv_nt5_signature2_patched[SIGNATURE_LEN] = {'\x90','\x90','\x8b','\x45','\x08','\x8b','\x00','\x8b','\x80','\x08','\x34','\x00','\x00','\xc7','\x40','\x24'};

static const unsigned char termsrv_nt6_signature1_original[SIGNATURE_LEN] = {'\x03','\x00','\x00','\x3B','\x86','\x20','\x03','\x00','\x00','\x0F','\x84','\xFF','\x14','\x01','\x00','\x57'};
static const unsigned char termsrv_nt6_signature1_patched[SIGNATURE_LEN] = {'\x03','\x00','\x00','\xB8','\x00','\x01','\x00','\x00','\x90','\x89','\x86','\x20','\x03','\x00','\x00','\x57'};

typedef struct _dll_info
{
    int pid;
    byte * dll_addr;
    int dll_size;
} dll_info;

int get_nt_major_version(void)
{
     return (DWORD) LOBYTE((LOWORD( GetVersion() )));
}
char * search_signature(char * addr, char * pattern, int addr_len, int pattern_len)
{
     int addr_offset, pattern_offset;
     for( addr_offset = 0; addr_offset < addr_len; addr_offset++)
     {
           pattern_offset = 0;
           while( addr[addr_offset] == pattern[pattern_offset] )
           {
                  addr_offset++;
                  pattern_offset++;
                  if( pattern_offset >= pattern_len )
                      return (char *) addr_offset - pattern_len;
           }
     }
     return 0;
}
char search_signature_end[] = "\x00";

int registry_write(int nt_major_version)
{
     if( nt_major_version != 5 && nt_major_version != 6 )
         return 0;

     HKEY hHive;
     DWORD data;
     char * hive_1 = "SYSTEM\\CurrentControlSet\\Control\\Terminal Server";
     char * hive_2 = "SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\Licensing Core";
     char * hive_3 = "SOFTWARE\\Microsoft\\Windows NT\\CurentVersion\\Winlogon";
     char * hive_4 = "SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services";
     //char * hives[] = { hive_1, hive_2, hive_3, hive_4 };
     //DWORD data_ar[] = { 0, 1, 1, 5 };
     int ret_code = 1;
     
     if( RegCreateKeyExA(HKEY_LOCAL_MACHINE, hive_1, 0, 0, REG_OPTION_VOLATILE, KEY_ALL_ACCESS, 0, &hHive, 0) != ERROR_SUCCESS )
     {
        printf("error opening %s\n", hive_1);
        return 0;
     }
     data = 0;
     if( RegSetValueExA(hHive, "fDenyTSConnections", 0 , REG_DWORD, &data, sizeof(DWORD)) != ERROR_SUCCESS )
     {    
          printf("error writing \"fDenyTSConnections\"=%d", data);
          ret_code = 0;
     }
     if( RegSetValueExA(hHive, "fSingleSessionPerUser", 0 , REG_DWORD, &data, sizeof(DWORD)) != ERROR_SUCCESS )
     {
         printf("error writing \"fSingleSessionPerUser\"=%d", data);
         ret_code = 0;
     }
     RegCloseKey(hHive);
     
     if( nt_major_version == 6 )
         return ret_code;

     if( RegCreateKeyExA(HKEY_LOCAL_MACHINE, hive_2, 0, 0, REG_OPTION_VOLATILE, KEY_ALL_ACCESS, 0, &hHive, 0) != ERROR_SUCCESS )
     {
        printf("error opening %s\n", hive_2);
        return 0;
     }
     data = 1;
     if( RegSetValueExA(hHive, "EnableConcurrentSessions", 0 , REG_DWORD, &data, sizeof(DWORD)) != ERROR_SUCCESS )
     {
         printf("error writing \"EnableConcurrentSessions\"=%d", data);
         ret_code = 0;
     }
     RegCloseKey(hHive);
     
     if( RegCreateKeyExA(HKEY_LOCAL_MACHINE, hive_3, 0, 0, REG_OPTION_VOLATILE, KEY_ALL_ACCESS, 0, &hHive, 0) != ERROR_SUCCESS )
     {
        printf("error opening %s\n", hive_3);
        return 0;
     }
     data = 1;
     if( RegSetValueExA(hHive, "EnableConcurrentSessions", 0 , REG_DWORD, &data, sizeof(DWORD)) != ERROR_SUCCESS )
     {
         printf("error writing \"EnableConcurrentSessions\"=%d", data);
         ret_code = 0;
     }
     if( RegSetValueExA(hHive, "AllowMultipleTSSessions", 0 , REG_DWORD, &data, sizeof(DWORD)) != ERROR_SUCCESS )
     {
         printf("error writing \"AllowMultipleTSSessions\"=%d", data);
         ret_code = 0;
     }
     RegCloseKey(hHive);
     
     if( RegCreateKeyExA(HKEY_LOCAL_MACHINE, hive_3, 0, 0, REG_OPTION_VOLATILE, KEY_ALL_ACCESS, 0, &hHive, 0) != ERROR_SUCCESS )
     {
        printf("error opening %s\n", hive_3);
        return 0;
     }
     data = 5;
     if( RegSetValueExA(hHive, "MaxInstanceCount", 0 , REG_DWORD, &data, sizeof(DWORD)) != ERROR_SUCCESS )
     {
         printf("error writing \"MaxInstanceCount\"=%d", data);
         ret_code = 0;
     }
     RegCloseKey(hHive);
     return ret_code;
}
void get_privileges()
{
     HANDLE hProcessToken;
     LUID luid;
     TOKEN_PRIVILEGES priv;
     OpenProcessToken( GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hProcessToken);
     LookupPrivilegeValue(NULL, "SeDebugPrivilege", &luid);
     priv.PrivilegeCount = 1;
     priv.Privileges[0].Luid = luid;
     priv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
     AdjustTokenPrivileges( hProcessToken, FALSE, &priv, sizeof(TOKEN_PRIVILEGES), 0, 0 );
}

void print_usage(char * prog_name)
{
     printf("usage: %s [-h] [-p] [-r] [-v]\n  -h|--help\tPrint this text\n  -p|--patch\tEnable multiple sessions\n  -r|--restore\tRestore all change\n  -v|--verbose\tShow more info", prog_name);
}

void print_hex(unsigned char * bytes, int len)
{
     int i;
     for(i = 0; i < len; i++)
     {
         if( i%0x10 == 0 && i != 0 )
             printf("\n");
         else if( i%8 == 0 && i != 0 )
             printf(" ");
         printf("%02x ", *(bytes+i));
     }
}

void print_ascii(unsigned char * bytes, int len)
{
     int i;
     for(i = 0; i < len; i++)
     {
         if( i%0x10 == 0 && i != 0 )
             printf("\n");
         if( (*(unsigned char *)(bytes+i) >= 0x20) )
             printf("%c ", *(unsigned char *)(bytes+i) );
         else
             printf(".");
     }
}

dll_info * get_dll_info(char * dll_name, BOOL verbose)
{
     dll_info * dll;
     dll = malloc(sizeof(dll_info)); 
     HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
     if( hProcessSnap == INVALID_HANDLE_VALUE )
     {
         printf("error CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, ...)\n");
         return;
     }
     PROCESSENTRY32 pe32;
     pe32.dwSize = sizeof(PROCESSENTRY32);
     if(! Process32First(hProcessSnap, &pe32) )
     {
          printf("error Process32First()\n");
          return;
     }
     do
     {
         if(! strcmp("svchost.exe", pe32.szExeFile) )
         {
             if(verbose)
                 printf("%s [%d]\n", pe32.szExeFile, pe32.th32ProcessID);
             HANDLE hModuleSnap = CreateToolhelp32Snapshot( TH32CS_SNAPMODULE, pe32.th32ProcessID );
             if( hModuleSnap == INVALID_HANDLE_VALUE )
             {
                 printf("error CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, %d)\n", pe32.th32ProcessID);
                 continue;
             }
             MODULEENTRY32 me32;
             me32.dwSize = sizeof(MODULEENTRY32);
             if(! Module32First(hModuleSnap, &me32) )
             {
                 printf("error Module32First()\n");
                 continue;
             }
             do
             {
                 if(verbose)
                     printf("  [0x%08x]\t%s (%d B)\n", me32.modBaseAddr, me32.szModule, me32.modBaseSize);
                 if(! strcmp( dll_name, me32.szModule ) )
                 {
                     dll->pid = pe32.th32ProcessID;
                     dll->dll_addr = me32.modBaseAddr;
                     dll->dll_size = me32.modBaseSize;
                     CloseHandle(hModuleSnap);
                     return dll;
                 }
             }
             while( Module32Next(hModuleSnap, &me32) );
             CloseHandle(hModuleSnap);
         }
     }
     while( Process32Next(hProcessSnap, &pe32) );
     return 0;
}

int main(int argc, char * argv[])
{
    int ret_code = 0;
    if( argc < 2 || argc > 3 )
    {
        print_usage( argv[0] );
        return -1;
    }

    const unsigned char * pattern1, * pattern2;
    const unsigned char * write_data1, * write_data2;
    BOOL verbose = 0;

    if( ! (strcmp("-h", argv[1]) && strcmp("--help", argv[1])) )
    {
        print_usage( argv[0] );
        return 0;    
    }
    if(! (strcmp("-p", argv[1]) && strcmp("--patch", argv[1])) )
    {
        if( registry_write( get_nt_major_version() ) )
            printf("registry writed\n");
        else
        {
            printf("error registry writing\n");
            return 0;
        }
        switch( get_nt_major_version() )
        {
            case 5: 
                pattern1 = termsrv_nt5_signature1_original;
                pattern2 = termsrv_nt5_signature2_original;
                write_data1 = termsrv_nt5_signature1_patched;
                write_data2 = termsrv_nt5_signature2_patched;
                break;
            case 6:
                pattern1 = termsrv_nt6_signature1_original;
                write_data1 = termsrv_nt6_signature1_patched;
                break;
            default:
                printf( "unknown NT version: %d\n", get_nt_major_version() );
                return;
        }
    }
    else if(! (strcmp("-r", argv[1]) && strcmp("--restore", argv[1])) )
    {
        switch( get_nt_major_version() )
        {
            case 5:
                pattern1 = termsrv_nt5_signature1_patched;
                pattern2 = termsrv_nt5_signature2_patched;
                write_data1 = termsrv_nt5_signature1_original;
                write_data2 = termsrv_nt5_signature2_original;
                break;
            case 6:
                pattern1 = termsrv_nt6_signature1_patched;
                write_data1 = termsrv_nt6_signature1_original;
                break;
            default:
                printf( "unknown NT version: %d\n", get_nt_major_version() );
                return;
        }
    }
    else
    {
        print_usage( argv[0] );
        return -1;
    }

    if( argc == 3 )
    {
        if( ! (strcmp("-v", argv[2]) && strcmp("--verbose", argv[2])) )
        {
            verbose = 1;
        }
        else
        {
            print_usage( argv[0] );
            return -1;
        }
    }

    printf( "NT version: %d\n", get_nt_major_version() );
    get_privileges();
    dll_info * termsrv = get_dll_info( "termsrv.dll", verbose );
    if(! termsrv)
    {
        printf("termsrv.dll not found\n");
        return 0;
    }

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, 0, termsrv->pid);
    char buf[PAGE];
    int read_len = 0;
    int offset;
    char * inject_point;
    BOOL first_change;
    BOOL second_change;
    
    if(verbose)
        printf("\nsearching code:\n\n");
    for( offset = 0; offset < termsrv->dll_size; offset += read_len )
    {
        if(verbose)
            printf("  [0x%08x]", (int)termsrv->dll_addr + offset);
        ReadProcessMemory( hProcess, (PVOID)((int)termsrv->dll_addr + offset), buf, PAGE, (PDWORD)&read_len );
        
        inject_point = search_signature(buf, (char *)pattern1, read_len, SIGNATURE_LEN);
        if( inject_point )
        {
            WriteProcessMemory(hProcess, (int)termsrv->dll_addr + offset + inject_point, write_data1, SIGNATURE_LEN, 0);
            if(verbose)
            {
                printf("\n  writed code:\n [0x%08x]: ", (int)termsrv->dll_addr + offset + inject_point);
                print_hex((unsigned char *)write_data1, SIGNATURE_LEN);
                first_change = TRUE;
            }
            if( get_nt_major_version() != 5 )
            {
                printf("\nTermService was modified\n");
                ret_code = 1;
                if(second_change) break;
            }
        }
        
        inject_point = search_signature(buf, (char *)pattern2, read_len, SIGNATURE_LEN);
        if( inject_point )
        {
            WriteProcessMemory(hProcess, (int)termsrv->dll_addr + offset + inject_point, write_data2, SIGNATURE_LEN, 0);
            if(verbose)
            {
                printf("\n  writed code:\n [0x%08x]: ", (int)termsrv->dll_addr + offset + inject_point);
                print_hex((unsigned char *)write_data2, SIGNATURE_LEN);
                second_change = TRUE;
            }
            printf("\nTermService was modified\n");
            ret_code = 1;
            if(first_change) break;
        }
        
        if(verbose)
            printf(" - not found\n");
        
    }
    CloseHandle(hProcess); 

    return ret_code;  
}
