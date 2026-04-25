/*
 * Anti-Scammer Panic Button v4 — Grandma Edition + Evidence Logger
 * =================================================================
 *
 * FEATURES:
 *   - Grandma-friendly GUI with big colorful buttons
 *   - SILENT hotkeys (no popups the scammer can see)
 *   - Status updates shown only in the GUI window
 *   - Toggleable firewall protection
 *   - EVIDENCE LOGGER: captures scammer IPs, connection details,
 *     process info, timestamps — saves to a report file for police
 *   - Port scanning catches unknown/custom remote tools
 *   - Destroys tool-specific screen blankers by window class
 *   - Removes 14+ scammer registry restrictions
 *   - Network kill as nuclear option
 *
 * HOTKEYS (silent):
 *   Ctrl+Alt+P  —  Full Panic
 *   Ctrl+Alt+S  —  Fix Screen
 *   Ctrl+Alt+I  —  Fix Input
 *   Ctrl+Alt+K  —  Kill Connections
 *   Ctrl+Alt+F  —  Toggle Firewall
 *   Ctrl+Alt+N  —  Kill Network
 *   Ctrl+Alt+R  —  Restore Network
 *   Ctrl+Alt+L  —  Capture Evidence (log scammer info)
 *   Ctrl+Alt+Q  —  Quit
 *
 * BUILD (Visual Studio Developer Command Prompt):
 *   cl /EHsc /O2 anti_scammer.cpp user32.lib advapi32.lib shell32.lib ^
 *      iphlpapi.lib ws2_32.lib gdi32.lib comctl32.lib comdlg32.lib ^
 *      /Fe:AntiScammer.exe
 *
 * BUILD (MinGW / g++):
 *   g++ -O2 -mwindows anti_scammer.cpp -o AntiScammer.exe ^
 *      -luser32 -ladvapi32 -lshell32 -liphlpapi -lws2_32 -lgdi32 ^
 *      -lcomctl32 -lcomdlg32
 *
 * MUST RUN AS ADMINISTRATOR.
 * License: Public domain.
 */

#define WIN32_LEAN_AND_MEAN
#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif
#define _WIN32_WINNT 0x0600

#include <windows.h>
#include <commctrl.h>
#include <shellapi.h>
#include <tlhelp32.h>
#include <iphlpapi.h>
#include <tcpmib.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <shlobj.h>
#include <string>
#include <vector>
#include <set>
#include <ctime>
#include <cstdio>
#include <sstream>

#pragma comment(lib, "user32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "comdlg32.lib")
#pragma comment(linker, "/manifestdependency:\"type='win32' \
    name='Microsoft.Windows.Common-Controls' version='6.0.0.0' \
    processorArchitecture='*' publicKeyToken='6595b64144ccf1df' \
    language='*'\"")

// ═══════════════════════════════════════════════════════════════════════════
//  IDs
// ═══════════════════════════════════════════════════════════════════════════
#define WM_TRAYICON          (WM_USER + 1)
#define WM_APP_APPEND_STATUS  (WM_APP + 1)
#define WM_APP_ACTION_DONE    (WM_APP + 2)

#define ID_HOTKEY_PANIC       1
#define ID_HOTKEY_SCREEN      2
#define ID_HOTKEY_INPUT       3
#define ID_HOTKEY_KILL        4
#define ID_HOTKEY_FIREWALL    5
#define ID_HOTKEY_NETKILL     6
#define ID_HOTKEY_NETRESTORE  7
#define ID_HOTKEY_QUIT        8
#define ID_HOTKEY_LOG         9

#define ID_BTN_PANIC          100
#define ID_BTN_SCREEN         101
#define ID_BTN_INPUT          102
#define ID_BTN_KILL           103
#define ID_BTN_FIREWALL       104
#define ID_BTN_NETKILL        105
#define ID_BTN_NETRESTORE     106
#define ID_BTN_LOG            107
#define ID_BTN_SAVELOG        108
#define ID_BTN_QUIT           109

#define ID_TRAY_SHOW          3000
#define ID_TRAY_EXIT          3001
#define IDI_TRAY              1

// ═══════════════════════════════════════════════════════════════════════════
//  COLORS
// ═══════════════════════════════════════════════════════════════════════════
#define CLR_BG         RGB(240, 240, 245)

// ═══════════════════════════════════════════════════════════════════════════
//  GLOBALS
// ═══════════════════════════════════════════════════════════════════════════
HWND           g_msgWnd       = nullptr;   // Hidden message-only window
HWND           g_guiWnd       = nullptr;   // Main GUI window
HWND           g_statusBox    = nullptr;   // Status/log text area
HWND           g_btnFirewall  = nullptr;
HINSTANCE      g_hInst        = nullptr;
NOTIFYICONDATA g_nid          = {};
bool           g_firewallActive = false;
HFONT          g_fontBig      = nullptr;
HFONT          g_fontMed      = nullptr;
HFONT          g_fontLog      = nullptr;
HFONT          g_fontTitle    = nullptr;
HBRUSH         g_bgBrush      = nullptr;
volatile LONG   g_actionRunning = 0;


// Evidence log stored in memory
std::wstring   g_evidenceLog;

// Counters
static int g_blankersDestroyed = 0;
static int g_overlaysMinimized = 0;
static int g_killedByName = 0;
static int g_killedByPort = 0;

// ═══════════════════════════════════════════════════════════════════════════
//  KNOWN DATA
// ═══════════════════════════════════════════════════════════════════════════
static const wchar_t* REMOTE_PROCESSES[] = {
    L"AnyDesk.exe", L"ad_svc.exe",
    L"TeamViewer.exe", L"TeamViewer_Service.exe", L"TeamViewer_Desktop.exe",
    L"tv_w32.exe", L"tv_x64.exe",
    L"ScreenConnect.ClientService.exe", L"ScreenConnect.WindowsClient.exe",
    L"ConnectWiseControl.Client.exe", L"ConnectWise.exe",
    L"Supremo.exe", L"SupremoService.exe", L"SupremoHelper.exe",
    L"winvnc.exe", L"winvnc4.exe", L"tvnserver.exe", L"vncviewer.exe",
    L"UltraVnc.exe",
    L"rustdesk.exe",
    L"LogMeIn.exe", L"LogMeInSystray.exe", L"LMIGuardianSvc.exe",
    L"GoToAssist.exe", L"g2ax_start.exe", L"g2ax_comm_service.exe",
    L"ammyy_admin.exe", L"aa_v3.exe", L"AA_v3.6.exe",
    L"SRManager.exe", L"SRService.exe", L"SRFeature.exe", L"splashtop.exe",
    L"ISLLight.exe", L"ISLAlwaysOn.exe",
    L"ZohoMeeting.exe", L"ZohoURSService.exe",
    L"RemotePC.exe", L"RPCService.exe",
    L"dwagent.exe", L"dwagsvc.exe",
    L"AteraAgent.exe",
    L"bomgar-scc.exe", L"bomgar-rdp.exe",
    L"Remote Access.exe", L"simplegateway.exe",
    L"msra.exe", L"QuickAssist.exe",
    nullptr
};

static const wchar_t* BLANKER_WINDOW_CLASSES[] = {
    L"TV_OverlayWindow", L"TeamViewer_DesktopBlockWindow", L"TVBlackScreen",
    L"TV_FullScreenOverlay", L"TeamViewerBlankScreen",
    L"AnyDesk.PrivacyOverlay", L"AnythingWindow",
    L"ScreenConnect.CurtainForm", L"CurtainWindow",
    L"ScreenConnect.BlackCurtainForm",
    L"SplashtopBlankScreen", L"SRBlankScreen",
    L"VNCBlackWindow", L"vaborern",
    L"ISLBlankScreen", L"BomgarCurtain", L"SupremoBlackScreen",
    nullptr
};

static const DWORD REMOTE_PORTS[] = {
    5800, 5900, 5901, 5902, 5903, 3389, 5938, 7070,
    9991, 9992, 6783, 6784, 8040, 8041, 2002, 5931,
    21115, 21116, 21117, 21118, 21119, 7615, 7950, 22,
    0
};

static const wchar_t* SAFE_PROCESSES[] = {
    L"explorer.exe", L"svchost.exe", L"lsass.exe", L"csrss.exe",
    L"services.exe", L"smss.exe", L"wininit.exe", L"winlogon.exe",
    L"dwm.exe", L"System", L"chrome.exe", L"firefox.exe",
    L"msedge.exe", L"brave.exe", L"opera.exe", L"AntiScammer.exe",
    nullptr
};


// ═══════════════════════════════════════════════════════════════════════════
//  UTILITIES
// ═══════════════════════════════════════════════════════════════════════════
static bool RunCommand(const std::wstring& cmd, DWORD timeoutMs = 3000) {
    STARTUPINFOW si = {};
    PROCESS_INFORMATION pi = {};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    std::wstring mc = cmd;
    BOOL ok = CreateProcessW(nullptr, &mc[0], nullptr, nullptr, FALSE,
        CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi);
    if (!ok) return false;

    DWORD wait = WaitForSingleObject(pi.hProcess, timeoutMs);
    bool completed = (wait == WAIT_OBJECT_0);

    if (!completed) {
        TerminateProcess(pi.hProcess, 1);
        WaitForSingleObject(pi.hProcess, 500);
    }

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return completed;
}

static std::wstring GetTimestamp() {
    SYSTEMTIME st;
    GetLocalTime(&st);
    wchar_t buf[64];
    swprintf(buf, 64, L"%04d-%02d-%02d %02d:%02d:%02d",
        st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
    return buf;
}

static void AppendStatusOnGuiThread(const std::wstring& line) {
    if (!g_statusBox) return;
    int len = GetWindowTextLengthW(g_statusBox);
    SendMessageW(g_statusBox, EM_SETSEL, len, len);
    std::wstring text = std::wstring(len > 0 ? L"\r\n" : L"") + L"[" + GetTimestamp() + L"] " + line;
    SendMessageW(g_statusBox, EM_REPLACESEL, FALSE, (LPARAM)text.c_str());
    SendMessageW(g_statusBox, EM_SCROLLCARET, 0, 0);
}

static void AppendStatus(const std::wstring& line) {
    if (!g_guiWnd) return;
    auto* msg = new std::wstring(line);
    if (!PostMessageW(g_guiWnd, WM_APP_APPEND_STATUS, 0, reinterpret_cast<LPARAM>(msg))) {
        delete msg;
    }
}

static void AppendEvidence(const std::wstring& line) {
    g_evidenceLog += L"[" + GetTimestamp() + L"] " + line + L"\r\n";
}

static bool IsSafeProcess(const wchar_t* name) {
    for (int i = 0; SAFE_PROCESSES[i]; ++i) {
        if (_wcsicmp(name, SAFE_PROCESSES[i]) == 0) return true;
    }
    return false;
}

static std::wstring IPToString(DWORD ip) {
    struct in_addr addr;
    addr.S_un.S_addr = ip;
    char buf[32];
    inet_ntop(AF_INET, &addr, buf, sizeof(buf));
    wchar_t wbuf[32];
    MultiByteToWideChar(CP_ACP, 0, buf, -1, wbuf, 32);
    return wbuf;
}

static std::wstring GetProcessName(DWORD pid) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return L"<unknown>";
    PROCESSENTRY32W pe = {};
    pe.dwSize = sizeof(pe);
    std::wstring name = L"<unknown>";
    if (Process32FirstW(snap, &pe)) {
        do {
            if (pe.th32ProcessID == pid) {
                name = pe.szExeFile;
                break;
            }
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return name;
}

static std::wstring GetProcessPath(DWORD pid) {
    HANDLE proc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!proc) return L"<access denied>";
    wchar_t path[MAX_PATH] = {};
    DWORD sz = MAX_PATH;
    if (QueryFullProcessImageNameW(proc, 0, path, &sz)) {
        CloseHandle(proc);
        return path;
    }
    CloseHandle(proc);
    return L"<unknown path>";
}


// ═══════════════════════════════════════════════════════════════════════════
//  EVIDENCE LOGGER — Captures everything about the scammer
// ═══════════════════════════════════════════════════════════════════════════
static void LogEvidenceHeader() {
    AppendEvidence(L"═══════════════════════════════════════════════════");
    AppendEvidence(L"  SCAM EVIDENCE REPORT");
    AppendEvidence(L"  Generated by Anti-Scammer v4");
    AppendEvidence(L"  Date: " + GetTimestamp());
    AppendEvidence(L"═══════════════════════════════════════════════════");
    AppendEvidence(L"");

    // Get computer name
    wchar_t compName[256] = {};
    DWORD compSize = 256;
    GetComputerNameW(compName, &compSize);
    AppendEvidence(L"Computer Name: " + std::wstring(compName));

    // Get username
    wchar_t userName[256] = {};
    DWORD userSize = 256;
    GetUserNameW(userName, &userSize);
    AppendEvidence(L"Logged-in User: " + std::wstring(userName));
    AppendEvidence(L"");
}

static void LogRemoteConnections() {
    AppendEvidence(L"─── ACTIVE NETWORK CONNECTIONS (Remote Access) ───");

    std::set<DWORD> remotePorts;
    for (int i = 0; REMOTE_PORTS[i]; ++i) remotePorts.insert(REMOTE_PORTS[i]);

    DWORD size = 0;
    GetExtendedTcpTable(nullptr, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
    if (size == 0) {
        AppendEvidence(L"  (Could not read TCP table)");
        return;
    }

    std::vector<BYTE> buffer(size);
    if (GetExtendedTcpTable(buffer.data(), &size, FALSE, AF_INET,
            TCP_TABLE_OWNER_PID_ALL, 0) != NO_ERROR) {
        AppendEvidence(L"  (Could not read TCP table)");
        return;
    }

    auto* table = reinterpret_cast<MIB_TCPTABLE_OWNER_PID*>(buffer.data());
    int found = 0;

    for (DWORD i = 0; i < table->dwNumEntries; ++i) {
        auto& row = table->table[i];
        DWORD lp = ntohs((u_short)row.dwLocalPort);
        DWORD rp = ntohs((u_short)row.dwRemotePort);
        DWORD pid = row.dwOwningPid;

        if (pid == 0 || pid == 4 || pid == GetCurrentProcessId()) continue;

        bool isRemotePort = remotePorts.count(lp) || remotePorts.count(rp);
        if (!isRemotePort) continue;
        if (row.dwState != MIB_TCP_STATE_ESTAB && row.dwState != MIB_TCP_STATE_LISTEN) continue;

        std::wstring localIP  = IPToString(row.dwLocalAddr);
        std::wstring remoteIP = IPToString(row.dwRemoteAddr);
        std::wstring procName = GetProcessName(pid);
        std::wstring procPath = GetProcessPath(pid);

        std::wstring state = (row.dwState == MIB_TCP_STATE_ESTAB) ? L"ESTABLISHED" : L"LISTENING";

        AppendEvidence(L"");
        AppendEvidence(L"  *** SUSPICIOUS CONNECTION ***");
        AppendEvidence(L"  Process: " + procName + L" (PID " + std::to_wstring(pid) + L")");
        AppendEvidence(L"  Process Path: " + procPath);
        AppendEvidence(L"  State: " + state);
        AppendEvidence(L"  Local:  " + localIP + L":" + std::to_wstring(lp));
        AppendEvidence(L"  Remote: " + remoteIP + L":" + std::to_wstring(rp));
        AppendEvidence(L"  >>> SCAMMER IP: " + remoteIP + L" <<<");

        found++;
    }

    if (found == 0) {
        AppendEvidence(L"  No active remote-access connections found on known ports.");
    } else {
        AppendEvidence(L"");
        AppendEvidence(L"  Total suspicious connections: " + std::to_wstring(found));
    }
    AppendEvidence(L"");
}

static void LogAllRemoteProcesses() {
    AppendEvidence(L"─── REMOTE-ACCESS PROGRAMS RUNNING ────────────────");

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) {
        AppendEvidence(L"  (Could not enumerate processes)");
        return;
    }

    PROCESSENTRY32W pe = {};
    pe.dwSize = sizeof(pe);
    int found = 0;

    if (Process32FirstW(snap, &pe)) {
        do {
            for (int i = 0; REMOTE_PROCESSES[i]; ++i) {
                if (_wcsicmp(pe.szExeFile, REMOTE_PROCESSES[i]) == 0) {
                    std::wstring path = GetProcessPath(pe.th32ProcessID);
                    AppendEvidence(L"  FOUND: " + std::wstring(pe.szExeFile) +
                        L" (PID " + std::to_wstring(pe.th32ProcessID) + L")");
                    AppendEvidence(L"    Path: " + path);
                    found++;
                }
            }
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);

    if (found == 0) {
        AppendEvidence(L"  No known remote-access programs found running.");
    }
    AppendEvidence(L"");
}

static void LogAllTcpConnections() {
    AppendEvidence(L"─── ALL ESTABLISHED TCP CONNECTIONS ───────────────");
    AppendEvidence(L"  (Full list for investigators)");

    DWORD size = 0;
    GetExtendedTcpTable(nullptr, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
    if (size == 0) return;

    std::vector<BYTE> buffer(size);
    if (GetExtendedTcpTable(buffer.data(), &size, FALSE, AF_INET,
            TCP_TABLE_OWNER_PID_ALL, 0) != NO_ERROR) return;

    auto* table = reinterpret_cast<MIB_TCPTABLE_OWNER_PID*>(buffer.data());

    for (DWORD i = 0; i < table->dwNumEntries; ++i) {
        auto& row = table->table[i];
        if (row.dwState != MIB_TCP_STATE_ESTAB) continue;
        if (row.dwOwningPid == 0 || row.dwOwningPid == 4) continue;

        std::wstring localIP  = IPToString(row.dwLocalAddr);
        std::wstring remoteIP = IPToString(row.dwRemoteAddr);
        DWORD lp = ntohs((u_short)row.dwLocalPort);
        DWORD rp = ntohs((u_short)row.dwRemotePort);
        std::wstring proc = GetProcessName(row.dwOwningPid);

        AppendEvidence(L"  " + proc + L" | " +
            localIP + L":" + std::to_wstring(lp) + L" -> " +
            remoteIP + L":" + std::to_wstring(rp));
    }
    AppendEvidence(L"");
}

static void LogNetworkAdapters() {
    AppendEvidence(L"─── NETWORK ADAPTERS ──────────────────────────────");

    ULONG bufLen = 0;
    GetAdaptersInfo(nullptr, &bufLen);
    if (bufLen == 0) {
        AppendEvidence(L"  (Could not enumerate adapters)");
        return;
    }

    std::vector<BYTE> buf(bufLen);
    auto* adapters = reinterpret_cast<IP_ADAPTER_INFO*>(buf.data());
    if (GetAdaptersInfo(adapters, &bufLen) == NO_ERROR) {
        for (auto* a = adapters; a; a = a->Next) {
            wchar_t wName[256] = {};
            MultiByteToWideChar(CP_ACP, 0, a->Description, -1, wName, 256);
            wchar_t wIP[64] = {};
            MultiByteToWideChar(CP_ACP, 0, a->IpAddressList.IpAddress.String, -1, wIP, 64);
            wchar_t wGW[64] = {};
            MultiByteToWideChar(CP_ACP, 0, a->GatewayList.IpAddress.String, -1, wGW, 64);

            // MAC address
            wchar_t mac[32] = {};
            swprintf(mac, 32, L"%02X:%02X:%02X:%02X:%02X:%02X",
                a->Address[0], a->Address[1], a->Address[2],
                a->Address[3], a->Address[4], a->Address[5]);

            AppendEvidence(L"  Adapter: " + std::wstring(wName));
            AppendEvidence(L"    IP:      " + std::wstring(wIP));
            AppendEvidence(L"    Gateway: " + std::wstring(wGW));
            AppendEvidence(L"    MAC:     " + std::wstring(mac));
        }
    }
    AppendEvidence(L"");
}

static void LogRecentEventLog() {
    AppendEvidence(L"─── RECENT SECURITY EVENTS (last 10) ──────────────");
    AppendEvidence(L"  (Check Windows Event Viewer for full audit trail)");
    AppendEvidence(L"  Event log parsing requires elevated access;");
    AppendEvidence(L"  investigators should check:");
    AppendEvidence(L"    - Security log: logon events (Event ID 4624, 4625)");
    AppendEvidence(L"    - System log: service start/stop");
    AppendEvidence(L"    - Application log: remote tool activity");
    AppendEvidence(L"");
}

static void ActionCaptureEvidence() {
    g_evidenceLog.clear();

    AppendStatus(L"Capturing scammer evidence...");

    LogEvidenceHeader();
    LogRemoteConnections();
    LogAllRemoteProcesses();
    LogAllTcpConnections();
    LogNetworkAdapters();
    LogRecentEventLog();

    AppendEvidence(L"═══════════════════════════════════════════════════");
    AppendEvidence(L"  END OF EVIDENCE REPORT");
    AppendEvidence(L"  Save this file and provide it to:");
    AppendEvidence(L"    - Local police");
    AppendEvidence(L"    - FTC: reportfraud.ftc.gov");
    AppendEvidence(L"    - FBI IC3: ic3.gov");
    AppendEvidence(L"    - Your bank (if money was sent)");
    AppendEvidence(L"═══════════════════════════════════════════════════");

    AppendStatus(L"Evidence captured! Click 'Save Evidence Report' to save to a file.");
}

static void ActionSaveEvidence() {
    if (g_evidenceLog.empty()) {
        AppendStatus(L"No evidence captured yet. Click 'Capture Evidence' first.");
        return;
    }

    // Build default filename with timestamp
    SYSTEMTIME st;
    GetLocalTime(&st);
    wchar_t defaultName[128];
    swprintf(defaultName, 128, L"ScamReport_%04d%02d%02d_%02d%02d%02d.txt",
        st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);

    // Get Desktop path
    wchar_t desktopPath[MAX_PATH] = {};
    SHGetFolderPathW(nullptr, 0x0010 /* CSIDL_DESKTOPDIRECTORY */, nullptr, 0, desktopPath);

    std::wstring fullPath = std::wstring(desktopPath) + L"\\" + defaultName;

    // Write the file
    HANDLE hFile = CreateFileW(fullPath.c_str(), GENERIC_WRITE, 0, nullptr,
        CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);

    if (hFile != INVALID_HANDLE_VALUE) {
        // Write UTF-8 BOM
        BYTE bom[] = { 0xEF, 0xBB, 0xBF };
        DWORD written;
        WriteFile(hFile, bom, 3, &written, nullptr);

        // Convert to UTF-8
        int utf8Len = WideCharToMultiByte(CP_UTF8, 0, g_evidenceLog.c_str(),
            (int)g_evidenceLog.length(), nullptr, 0, nullptr, nullptr);
        std::vector<char> utf8(utf8Len);
        WideCharToMultiByte(CP_UTF8, 0, g_evidenceLog.c_str(),
            (int)g_evidenceLog.length(), utf8.data(), utf8Len, nullptr, nullptr);

        WriteFile(hFile, utf8.data(), utf8Len, &written, nullptr);
        CloseHandle(hFile);

        AppendStatus(L"Evidence saved to Desktop: " + std::wstring(defaultName));
        AppendStatus(L"Give this file to the police or report at reportfraud.ftc.gov");
    } else {
        AppendStatus(L"Could not save file. Try running as Administrator.");
    }
}


// ═══════════════════════════════════════════════════════════════════════════
//  ACTION: RESTORE SCREEN (silent)
// ═══════════════════════════════════════════════════════════════════════════
static bool WindowClassMatches(HWND hwnd, const wchar_t* wantedClass) {
    wchar_t cls[256] = {};
    GetClassNameW(hwnd, cls, 256);
    return _wcsicmp(cls, wantedClass) == 0;
}

static void HideOneBlankerWindow(HWND hwnd, int* count) {
    if (!hwnd || !IsWindow(hwnd)) return;

    // Do not move windows off-screen. Hiding/closing is enough and avoids
    // the "all my windows got pushed away" side effect.
    PostMessageW(hwnd, WM_CLOSE, 0, 0);
    Sleep(25);
    if (IsWindow(hwnd)) ShowWindow(hwnd, SW_HIDE);
    if (count) (*count)++;
}

// ═══════════════════════════════════════════════════════════════════════════
//  ACTION: RESTORE SCREEN (silent)
// ═══════════════════════════════════════════════════════════════════════════
static void ActionRestoreScreen() {
    g_blankersDestroyed = 0;
    g_overlaysMinimized = 0;

    // Target only known black-screen/privacy/curtain window classes.
    // The previous fullscreen fallback was too broad and could affect Chrome,
    // browsers, video players, games, or normal maximized windows.
    struct ClassCtx { const wchar_t* cls; int* count; };

    for (int i = 0; BLANKER_WINDOW_CLASSES[i]; ++i) {
        ClassCtx ctx = { BLANKER_WINDOW_CLASSES[i], &g_blankersDestroyed };
        EnumWindows([](HWND hwnd, LPARAM lp) -> BOOL {
            auto* c = reinterpret_cast<ClassCtx*>(lp);
            if (WindowClassMatches(hwnd, c->cls)) {
                HideOneBlankerWindow(hwnd, c->count);
            }
            return TRUE;
        }, reinterpret_cast<LPARAM>(&ctx));
    }

    // Target only highly specific black-screen/privacy titles. No generic
    // fullscreen scanning, and no SetWindowPos off-screen movement.
    const wchar_t* titles[] = {
        L"Black Screen", L"Privacy Mode", L"Blank Screen",
        L"Screen Blanked", L"Curtain", nullptr
    };
    for (int i = 0; titles[i]; ++i) {
        EnumWindows([](HWND hwnd, LPARAM lp) -> BOOL {
            const wchar_t* wanted = reinterpret_cast<const wchar_t*>(lp);
            wchar_t title[256] = {};
            GetWindowTextW(hwnd, title, 256);
            if (_wcsicmp(title, wanted) == 0) {
                HideOneBlankerWindow(hwnd, &g_blankersDestroyed);
            }
            return TRUE;
        }, reinterpret_cast<LPARAM>(titles[i]));
    }

    HWND hShell = FindWindowW(L"Shell_TrayWnd", nullptr);
    if (hShell) ShowWindow(hShell, SW_SHOW);

    while (ShowCursor(TRUE) < 0) {}

    // Avoid SendMessage(HWND_BROADCAST), which can hang if another app is stuck.
    SendMessageTimeoutW(HWND_BROADCAST, WM_SYSCOMMAND, SC_MONITORPOWER, (LPARAM)-1,
        SMTO_ABORTIFHUNG | SMTO_NORMAL, 250, nullptr);

    INPUT inp = {}; inp.type = INPUT_MOUSE; inp.mi.dwFlags = MOUSEEVENTF_MOVE;
    inp.mi.dx = 1; inp.mi.dy = 1; SendInput(1, &inp, sizeof(INPUT));
    SystemParametersInfoW(SPI_SETSCREENSAVEACTIVE, FALSE, nullptr, 0);
    InvalidateRect(nullptr, nullptr, TRUE);

    AppendStatus(L"Screen fixed. Removed " + std::to_wstring(g_blankersDestroyed) +
        L" known blanker/curtain window(s). Generic fullscreen windows were left alone.");
}


// ═══════════════════════════════════════════════════════════════════════════
//  ACTION: RESTORE INPUT (silent)
// ═══════════════════════════════════════════════════════════════════════════
static void ActionRestoreInput() {
    BlockInput(FALSE);

    HKEY hKey = nullptr;
    const wchar_t* pol[][2] = {
        { L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", L"DisableTaskMgr" },
        { L"Software\\Policies\\Microsoft\\Windows\\System", L"DisableCMD" },
        { L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", L"DisableRegistryTools" },
        { L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", L"DisableLockWorkstation" },
        { L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", L"DisableChangePassword" },
        { L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer", L"NoClose" },
        { L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer", L"NoLogoff" },
        { L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer", L"NoWinKeys" },
        { L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer", L"RestrictRun" },
        { L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer", L"DisallowRun" },
        { L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer", L"NoRun" },
        { L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer", L"NoDesktop" },
        { L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer", L"NoControlPanel" },
        { L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer", L"NoFind" },
        { nullptr, nullptr }
    };
    for (int i = 0; pol[i][0]; ++i) {
        if (RegOpenKeyExW(HKEY_CURRENT_USER, pol[i][0], 0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS)
            { RegDeleteValueW(hKey, pol[i][1]); RegCloseKey(hKey); }
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, pol[i][0], 0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS)
            { RegDeleteValueW(hKey, pol[i][1]); RegCloseKey(hKey); }
    }

    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
            L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
            0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
        DWORD v = 1;
        RegSetValueExW(hKey, L"SoftwareSASGeneration", 0, REG_DWORD, (BYTE*)&v, sizeof(v));
        RegCloseKey(hKey);
    }

    const wchar_t* blockers[] = {
        L"InputBlocker.exe", L"LockInput.exe", L"BlockInput.exe",
        L"DesktopShield.exe", L"syskey.exe", nullptr
    };
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32W pe = {}; pe.dwSize = sizeof(pe);
        if (Process32FirstW(snap, &pe)) {
            do {
                for (int i = 0; blockers[i]; ++i)
                    if (_wcsicmp(pe.szExeFile, blockers[i]) == 0) {
                        HANDLE p = OpenProcess(PROCESS_TERMINATE, FALSE, pe.th32ProcessID);
                        if (p) { TerminateProcess(p, 1); CloseHandle(p); }
                    }
            } while (Process32NextW(snap, &pe));
        }
        CloseHandle(snap);
    }

    BlockInput(FALSE);
    RunCommand(L"cmd.exe /c gpupdate /force");
    AppendStatus(L"Input restored. Keyboard, mouse, and all system tools re-enabled.");
}


// ═══════════════════════════════════════════════════════════════════════════
//  ACTION: KILL CONNECTIONS (silent)
// ═══════════════════════════════════════════════════════════════════════════
static std::set<DWORD> GetSuspiciousPIDs() {
    std::set<DWORD> pids;
    std::set<DWORD> rp;
    for (int i = 0; REMOTE_PORTS[i]; ++i) rp.insert(REMOTE_PORTS[i]);
    DWORD size = 0;
    GetExtendedTcpTable(nullptr, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
    if (size == 0) return pids;
    std::vector<BYTE> buf(size);
    if (GetExtendedTcpTable(buf.data(), &size, FALSE, AF_INET,
            TCP_TABLE_OWNER_PID_ALL, 0) == NO_ERROR) {
        auto* t = reinterpret_cast<MIB_TCPTABLE_OWNER_PID*>(buf.data());
        for (DWORD i = 0; i < t->dwNumEntries; ++i) {
            auto& r = t->table[i];
            DWORD lp = ntohs((u_short)r.dwLocalPort);
            DWORD rport = ntohs((u_short)r.dwRemotePort);
            if (r.dwOwningPid == GetCurrentProcessId()) continue;
            if (r.dwOwningPid == 0 || r.dwOwningPid == 4) continue;
            if (rp.count(lp) || rp.count(rport))
                if (r.dwState == MIB_TCP_STATE_ESTAB || r.dwState == MIB_TCP_STATE_LISTEN)
                    pids.insert(r.dwOwningPid);
        }
    }
    return pids;
}

static void ActionKillConnections() {
    g_killedByName = 0;
    g_killedByPort = 0;
    std::set<DWORD> killed;

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32W pe = {}; pe.dwSize = sizeof(pe);
        if (Process32FirstW(snap, &pe)) {
            do {
                for (int i = 0; REMOTE_PROCESSES[i]; ++i)
                    if (_wcsicmp(pe.szExeFile, REMOTE_PROCESSES[i]) == 0) {
                        HANDLE p = OpenProcess(PROCESS_TERMINATE, FALSE, pe.th32ProcessID);
                        if (p) {
                            if (TerminateProcess(p, 1))
                                { g_killedByName++; killed.insert(pe.th32ProcessID); }
                            CloseHandle(p);
                        }
                    }
            } while (Process32NextW(snap, &pe));
        }
        CloseHandle(snap);
    }

    for (DWORD pid : GetSuspiciousPIDs()) {
        if (killed.count(pid)) continue;
        std::wstring name = GetProcessName(pid);
        if (IsSafeProcess(name.c_str())) continue;
        HANDLE p = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
        if (p) { if (TerminateProcess(p, 1)) g_killedByPort++; CloseHandle(p); }
    }

    AppendStatus(L"Connections killed. " + std::to_wstring(g_killedByName) +
        L" known tool(s), " + std::to_wstring(g_killedByPort) + L" unknown suspicious.");
}


// ═══════════════════════════════════════════════════════════════════════════
//  ACTION: FIREWALL TOGGLE (silent)
// ═══════════════════════════════════════════════════════════════════════════
static void UpdateFirewallButton() {
    if (g_btnFirewall) {
        SetWindowTextW(g_btnFirewall,
            g_firewallActive
                ? L"Firewall: ON\n(click to turn OFF)"
                : L"Firewall: OFF\n(click to turn ON)");
        InvalidateRect(g_btnFirewall, nullptr, TRUE);
    }
}

static void ActionToggleFirewall() {
    if (!g_firewallActive) {
        for (int i = 0; REMOTE_PORTS[i]; ++i) {
            std::wstring p = std::to_wstring(REMOTE_PORTS[i]);
            std::wstring n = L"AntiScammer_Block_" + p;
            RunCommand(L"netsh advfirewall firewall add rule name=\"" + n +
                L"_IN\" dir=in action=block protocol=TCP localport=" + p + L" enable=yes");
            RunCommand(L"netsh advfirewall firewall add rule name=\"" + n +
                L"_OUT\" dir=out action=block protocol=TCP remoteport=" + p + L" enable=yes");
        }
        g_firewallActive = true;
        AppendStatus(L"Firewall ON — All remote-access ports blocked.");
    } else {
        for (int i = 0; REMOTE_PORTS[i]; ++i) {
            std::wstring p = std::to_wstring(REMOTE_PORTS[i]);
            std::wstring n = L"AntiScammer_Block_" + p;
            RunCommand(L"netsh advfirewall firewall delete rule name=\"" + n + L"_IN\"");
            RunCommand(L"netsh advfirewall firewall delete rule name=\"" + n + L"_OUT\"");
        }
        g_firewallActive = false;
        AppendStatus(L"Firewall OFF — Remote-access ports unblocked.");
    }
    UpdateFirewallButton();
}


// ═══════════════════════════════════════════════════════════════════════════
//  ACTION: NETWORK KILL / RESTORE (silent)
// ═══════════════════════════════════════════════════════════════════════════
static void ActionNetworkKill() {
    RunCommand(L"cmd.exe /c wmic path win32_networkadapter where \"NetEnabled=true\" call disable");
    RunCommand(L"cmd.exe /c netsh interface set interface \"Wi-Fi\" disable");
    RunCommand(L"cmd.exe /c netsh interface set interface \"Ethernet\" disable");
    RunCommand(L"cmd.exe /c netsh interface set interface \"Local Area Connection\" disable");
    AppendStatus(L"NETWORK KILLED. All connections disabled. Scammer disconnected.");
    AppendStatus(L"Press 'Restore Network' or Ctrl+Alt+R when safe.");
}

static void ActionNetworkRestore() {
    RunCommand(L"cmd.exe /c wmic path win32_networkadapter where \"NetEnabled=false\" call enable");
    RunCommand(L"cmd.exe /c netsh interface set interface \"Wi-Fi\" enable");
    RunCommand(L"cmd.exe /c netsh interface set interface \"Ethernet\" enable");
    RunCommand(L"cmd.exe /c netsh interface set interface \"Local Area Connection\" enable");
    AppendStatus(L"Network restored. Internet should reconnect shortly.");
}


// ═══════════════════════════════════════════════════════════════════════════
//  FULL PANIC (silent)
// ═══════════════════════════════════════════════════════════════════════════
static void DoFullPanic() {
    AppendStatus(L"=== FULL PANIC ACTIVATED ===");
    ActionCaptureEvidence();   // Log evidence BEFORE killing everything
    ActionRestoreInput();
    ActionRestoreScreen();
    ActionKillConnections();
    if (!g_firewallActive) ActionToggleFirewall();
    ShellExecuteW(nullptr, L"open", L"taskmgr.exe", nullptr, nullptr, SW_SHOW);
    AppendStatus(L"=== FULL PANIC COMPLETE — You are safe. Hang up the phone! ===");
}

// Run slow actions off the GUI/message thread so buttons, repainting,
// and registered hotkeys remain responsive while netsh, gpupdate, wmic,
// process scans, and evidence capture are running.
typedef void (*ActionFn)();

static DWORD WINAPI ActionThreadProc(LPVOID param) {
    ActionFn fn = reinterpret_cast<ActionFn>(param);
    if (fn) fn();

    InterlockedExchange(&g_actionRunning, 0);
    if (g_guiWnd) PostMessageW(g_guiWnd, WM_APP_ACTION_DONE, 0, 0);
    return 0;
}

static void RunAsync(ActionFn fn) {
    // Do not block emergency actions behind a global busy flag.
    // The old guard could get stuck if a Windows command or window operation hung.
    InterlockedExchange(&g_actionRunning, 1);

    HANDLE hThread = CreateThread(nullptr, 0, ActionThreadProc,
        reinterpret_cast<LPVOID>(fn), 0, nullptr);
    if (!hThread) {
        InterlockedExchange(&g_actionRunning, 0);
        AppendStatus(L"Could not start background action thread.");
        return;
    }
    CloseHandle(hThread);
}


// ═══════════════════════════════════════════════════════════════════════════
//  GUI WINDOW
// ═══════════════════════════════════════════════════════════════════════════

// Owner-drawn button colors
struct BtnColor { COLORREF bg; COLORREF fg; };
static BtnColor GetBtnColor(int id) {
    switch (id) {
    case ID_BTN_PANIC:      return { RGB(220, 38, 38),  RGB(255,255,255) }; // Red
    case ID_BTN_SCREEN:     return { RGB(59, 130, 246), RGB(255,255,255) }; // Blue
    case ID_BTN_INPUT:      return { RGB(59, 130, 246), RGB(255,255,255) };
    case ID_BTN_KILL:       return { RGB(234, 88, 12),  RGB(255,255,255) }; // Orange
    case ID_BTN_FIREWALL:   return g_firewallActive
                                   ? BtnColor{ RGB(22, 163, 74),  RGB(255,255,255) }   // Green
                                   : BtnColor{ RGB(107, 114, 128), RGB(255,255,255) };  // Gray
    case ID_BTN_NETKILL:    return { RGB(127, 29, 29),  RGB(255,255,255) }; // Dark red
    case ID_BTN_NETRESTORE: return { RGB(22, 163, 74),  RGB(255,255,255) }; // Green
    case ID_BTN_LOG:        return { RGB(124, 58, 237), RGB(255,255,255) }; // Purple
    case ID_BTN_SAVELOG:    return { RGB(124, 58, 237), RGB(255,255,255) };
    case ID_BTN_QUIT:       return { RGB(107, 114, 128), RGB(255,255,255) }; // Gray
    default:                return { RGB(59, 130, 246), RGB(255,255,255) };
    }
}

static LRESULT CALLBACK GuiWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {

    case WM_CREATE: {
        int y = 15;
        int bw = 340;  // button width
        int bh = 48;   // button height
        int gap = 8;
        int x = 20;

        // Title
        HWND title = CreateWindowW(L"STATIC",
            L"Anti-Scammer Protection",
            WS_CHILD | WS_VISIBLE | SS_CENTER,
            x, y, bw, 36, hwnd, nullptr, g_hInst, nullptr);
        SendMessageW(title, WM_SETFONT, (WPARAM)g_fontTitle, TRUE);
        y += 42;

        // Subtitle
        HWND sub = CreateWindowW(L"STATIC",
            L"Press a button or use the hotkey shown",
            WS_CHILD | WS_VISIBLE | SS_CENTER,
            x, y, bw, 20, hwnd, nullptr, g_hInst, nullptr);
        SendMessageW(sub, WM_SETFONT, (WPARAM)g_fontMed, TRUE);
        y += 30;

        // ── BIG PANIC BUTTON ──
        HWND btnPanic = CreateWindowW(L"BUTTON",
            L"STOP THE SCAMMER\n(Ctrl+Alt+P)",
            WS_CHILD | WS_VISIBLE | BS_OWNERDRAW,
            x, y, bw, 70, hwnd, (HMENU)ID_BTN_PANIC, g_hInst, nullptr);
        y += 70 + gap;

        // ── Individual action buttons (2 columns) ──
        int halfW = (bw - gap) / 2;

        CreateWindowW(L"BUTTON", L"Fix Screen\n(Ctrl+Alt+S)",
            WS_CHILD | WS_VISIBLE | BS_OWNERDRAW,
            x, y, halfW, bh, hwnd, (HMENU)ID_BTN_SCREEN, g_hInst, nullptr);
        CreateWindowW(L"BUTTON", L"Fix Input\n(Ctrl+Alt+I)",
            WS_CHILD | WS_VISIBLE | BS_OWNERDRAW,
            x + halfW + gap, y, halfW, bh, hwnd, (HMENU)ID_BTN_INPUT, g_hInst, nullptr);
        y += bh + gap;

        CreateWindowW(L"BUTTON", L"Kill Connections\n(Ctrl+Alt+K)",
            WS_CHILD | WS_VISIBLE | BS_OWNERDRAW,
            x, y, halfW, bh, hwnd, (HMENU)ID_BTN_KILL, g_hInst, nullptr);

        g_btnFirewall = CreateWindowW(L"BUTTON", L"Firewall: OFF\n(Ctrl+Alt+F)",
            WS_CHILD | WS_VISIBLE | BS_OWNERDRAW,
            x + halfW + gap, y, halfW, bh, hwnd, (HMENU)ID_BTN_FIREWALL, g_hInst, nullptr);
        y += bh + gap;

        CreateWindowW(L"BUTTON", L"Kill Network\n(Ctrl+Alt+N)",
            WS_CHILD | WS_VISIBLE | BS_OWNERDRAW,
            x, y, halfW, bh, hwnd, (HMENU)ID_BTN_NETKILL, g_hInst, nullptr);
        CreateWindowW(L"BUTTON", L"Restore Network\n(Ctrl+Alt+R)",
            WS_CHILD | WS_VISIBLE | BS_OWNERDRAW,
            x + halfW + gap, y, halfW, bh, hwnd, (HMENU)ID_BTN_NETRESTORE, g_hInst, nullptr);
        y += bh + gap;

        // ── Evidence buttons ──
        CreateWindowW(L"BUTTON", L"Capture Evidence\n(Ctrl+Alt+L)",
            WS_CHILD | WS_VISIBLE | BS_OWNERDRAW,
            x, y, halfW, bh, hwnd, (HMENU)ID_BTN_LOG, g_hInst, nullptr);
        CreateWindowW(L"BUTTON", L"Save Evidence\nReport to File",
            WS_CHILD | WS_VISIBLE | BS_OWNERDRAW,
            x + halfW + gap, y, halfW, bh, hwnd, (HMENU)ID_BTN_SAVELOG, g_hInst, nullptr);
        y += bh + gap + 4;

        // ── Status log area ──
        HWND logLabel = CreateWindowW(L"STATIC", L"Activity Log:",
            WS_CHILD | WS_VISIBLE,
            x, y, bw, 18, hwnd, nullptr, g_hInst, nullptr);
        SendMessageW(logLabel, WM_SETFONT, (WPARAM)g_fontMed, TRUE);
        y += 20;

        g_statusBox = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
            WS_CHILD | WS_VISIBLE | WS_VSCROLL | ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL,
            x, y, bw, 160, hwnd, nullptr, g_hInst, nullptr);
        SendMessageW(g_statusBox, WM_SETFONT, (WPARAM)g_fontLog, TRUE);
        y += 160 + gap;

        // ── Quit button ──
        CreateWindowW(L"BUTTON", L"Close Window (keeps running in tray)",
            WS_CHILD | WS_VISIBLE | BS_OWNERDRAW,
            x, y, bw, 32, hwnd, (HMENU)ID_BTN_QUIT, g_hInst, nullptr);

        AppendStatusOnGuiThread(L"Anti-Scammer v4 ready. You are protected.");
        return 0;
    }

    case WM_APP_APPEND_STATUS: {
        auto* line = reinterpret_cast<std::wstring*>(lParam);
        if (line) {
            AppendStatusOnGuiThread(*line);
            delete line;
        }
        return 0;
    }

    case WM_APP_ACTION_DONE:
        InterlockedExchange(&g_actionRunning, 0);
        UpdateFirewallButton();
        return 0;

    case WM_DRAWITEM: {
        auto* dis = reinterpret_cast<DRAWITEMSTRUCT*>(lParam);
        if (dis->CtlType != ODT_BUTTON) break;

        BtnColor col = GetBtnColor(dis->CtlID);

        // Darken on press
        COLORREF bg = col.bg;
        if (dis->itemState & ODS_SELECTED) {
            bg = RGB(GetRValue(bg)*3/4, GetGValue(bg)*3/4, GetBValue(bg)*3/4);
        }

        // Draw rounded-ish button
        HBRUSH brush = CreateSolidBrush(bg);
        HPEN pen = CreatePen(PS_SOLID, 1, bg);
        SelectObject(dis->hDC, brush);
        SelectObject(dis->hDC, pen);
        RoundRect(dis->hDC, dis->rcItem.left, dis->rcItem.top,
            dis->rcItem.right, dis->rcItem.bottom, 12, 12);

        // Draw text
        SetBkMode(dis->hDC, TRANSPARENT);
        SetTextColor(dis->hDC, col.fg);

        HFONT font = (dis->CtlID == ID_BTN_PANIC) ? g_fontBig :
                     (dis->CtlID == ID_BTN_QUIT) ? g_fontMed : g_fontMed;
        SelectObject(dis->hDC, font);

        wchar_t text[256] = {};
        GetWindowTextW(dis->hwndItem, text, 256);

        // Handle multi-line text
        RECT rc = dis->rcItem;
        DrawTextW(dis->hDC, text, -1, &rc,
            DT_CENTER | DT_VCENTER | DT_WORDBREAK | DT_NOPREFIX);

        DeleteObject(brush);
        DeleteObject(pen);

        // Focus rect
        if (dis->itemState & ODS_FOCUS) {
            RECT fr = dis->rcItem;
            InflateRect(&fr, -3, -3);
            DrawFocusRect(dis->hDC, &fr);
        }
        return TRUE;
    }

    case WM_CTLCOLORSTATIC: {
        HDC hdc = (HDC)wParam;
        SetBkColor(hdc, CLR_BG);
        SetTextColor(hdc, RGB(30, 30, 30));
        return (LRESULT)g_bgBrush;
    }

    case WM_COMMAND:
        switch (LOWORD(wParam)) {
        case ID_BTN_PANIC:      RunAsync(DoFullPanic); break;
        case ID_BTN_SCREEN:     RunAsync(ActionRestoreScreen); break;
        case ID_BTN_INPUT:      RunAsync(ActionRestoreInput); break;
        case ID_BTN_KILL:       RunAsync(ActionKillConnections); break;
        case ID_BTN_FIREWALL:   RunAsync(ActionToggleFirewall); break;
        case ID_BTN_NETKILL:    RunAsync(ActionNetworkKill); break;
        case ID_BTN_NETRESTORE: RunAsync(ActionNetworkRestore); break;
        case ID_BTN_LOG:        RunAsync(ActionCaptureEvidence); break;
        case ID_BTN_SAVELOG:    RunAsync(ActionSaveEvidence); break;
        case ID_BTN_QUIT:       ShowWindow(hwnd, SW_HIDE); break;
        }
        return 0;

    case WM_CLOSE:
        ShowWindow(hwnd, SW_HIDE);
        return 0;

    case WM_ERASEBKGND: {
        HDC hdc = (HDC)wParam;
        RECT rc; GetClientRect(hwnd, &rc);
        FillRect(hdc, &rc, g_bgBrush);
        return 1;
    }
    }
    return DefWindowProcW(hwnd, msg, wParam, lParam);
}

static void CreateGUI() {
    // Create fonts
    g_fontBig = CreateFontW(22, 0, 0, 0, FW_BOLD, 0, 0, 0, DEFAULT_CHARSET,
        0, 0, CLEARTYPE_QUALITY, 0, L"Segoe UI");
    g_fontMed = CreateFontW(15, 0, 0, 0, FW_SEMIBOLD, 0, 0, 0, DEFAULT_CHARSET,
        0, 0, CLEARTYPE_QUALITY, 0, L"Segoe UI");
    g_fontLog = CreateFontW(13, 0, 0, 0, FW_NORMAL, 0, 0, 0, DEFAULT_CHARSET,
        0, 0, CLEARTYPE_QUALITY, 0, L"Consolas");
    g_fontTitle = CreateFontW(26, 0, 0, 0, FW_BOLD, 0, 0, 0, DEFAULT_CHARSET,
        0, 0, CLEARTYPE_QUALITY, 0, L"Segoe UI");
    g_bgBrush = CreateSolidBrush(CLR_BG);

    WNDCLASSEXW wc = {};
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = GuiWndProc;
    wc.hInstance = g_hInst;
    wc.lpszClassName = L"AntiScammerGUI";
    wc.hIcon = LoadIcon(nullptr, IDI_SHIELD);
    wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
    wc.hbrBackground = g_bgBrush;
    RegisterClassExW(&wc);

    int winW = 400;
    int winH = 720;
    int screenW = GetSystemMetrics(SM_CXSCREEN);
    int screenH = GetSystemMetrics(SM_CYSCREEN);

    g_guiWnd = CreateWindowExW(
        WS_EX_TOPMOST,
        L"AntiScammerGUI",
        L"Anti-Scammer v4",
        WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX,
        screenW - winW - 20,  // Position near right edge
        (screenH - winH) / 2,
        winW, winH,
        nullptr, nullptr, g_hInst, nullptr);

    ShowWindow(g_guiWnd, SW_SHOW);
    UpdateWindow(g_guiWnd);
}


// ═══════════════════════════════════════════════════════════════════════════
//  SYSTEM TRAY
// ═══════════════════════════════════════════════════════════════════════════
static void AddTrayIcon(HWND hwnd) {
    g_nid.cbSize = sizeof(g_nid);
    g_nid.hWnd = hwnd;
    g_nid.uID = IDI_TRAY;
    g_nid.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP;
    g_nid.uCallbackMessage = WM_TRAYICON;
    g_nid.hIcon = LoadIcon(nullptr, IDI_SHIELD);
    wcscpy_s(g_nid.szTip, L"Anti-Scammer v4 (double-click to open)");
    Shell_NotifyIconW(NIM_ADD, &g_nid);
}

static void RemoveTrayIcon() {
    Shell_NotifyIconW(NIM_DELETE, &g_nid);
}


// ═══════════════════════════════════════════════════════════════════════════
//  HIDDEN MESSAGE WINDOW (handles hotkeys + tray)
// ═══════════════════════════════════════════════════════════════════════════
static LRESULT CALLBACK MsgWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {

    case WM_HOTKEY:
        switch (wParam) {
        case ID_HOTKEY_PANIC:      RunAsync(DoFullPanic); break;
        case ID_HOTKEY_SCREEN:     RunAsync(ActionRestoreScreen); break;
        case ID_HOTKEY_INPUT:      RunAsync(ActionRestoreInput); break;
        case ID_HOTKEY_KILL:       RunAsync(ActionKillConnections); break;
        case ID_HOTKEY_FIREWALL:   RunAsync(ActionToggleFirewall); break;
        case ID_HOTKEY_NETKILL:    RunAsync(ActionNetworkKill); break;
        case ID_HOTKEY_NETRESTORE: RunAsync(ActionNetworkRestore); break;
        case ID_HOTKEY_LOG:        RunAsync(ActionCaptureEvidence); break;
        case ID_HOTKEY_QUIT:       PostQuitMessage(0); break;
        }
        return 0;

    case WM_TRAYICON:
        if (lParam == WM_RBUTTONUP) {
            POINT pt; GetCursorPos(&pt);
            HMENU hMenu = CreatePopupMenu();
            AppendMenuW(hMenu, MF_STRING, ID_TRAY_SHOW, L"Open Anti-Scammer");
            AppendMenuW(hMenu, MF_SEPARATOR, 0, nullptr);
            AppendMenuW(hMenu, MF_STRING, ID_TRAY_EXIT, L"Quit");
            SetForegroundWindow(hwnd);
            TrackPopupMenu(hMenu, TPM_BOTTOMALIGN | TPM_LEFTALIGN,
                pt.x, pt.y, 0, hwnd, nullptr);
            DestroyMenu(hMenu);
        } else if (lParam == WM_LBUTTONDBLCLK) {
            if (g_guiWnd) {
                ShowWindow(g_guiWnd, SW_SHOW);
                SetForegroundWindow(g_guiWnd);
            }
        }
        return 0;

    case WM_COMMAND:
        switch (LOWORD(wParam)) {
        case ID_TRAY_SHOW:
            if (g_guiWnd) {
                ShowWindow(g_guiWnd, SW_SHOW);
                SetForegroundWindow(g_guiWnd);
            }
            break;
        case ID_TRAY_EXIT:
            PostQuitMessage(0);
            break;
        }
        return 0;

    case WM_DESTROY:
        if (g_firewallActive) {
            for (int i = 0; REMOTE_PORTS[i]; ++i) {
                std::wstring p = std::to_wstring(REMOTE_PORTS[i]);
                std::wstring n = L"AntiScammer_Block_" + p;
                RunCommand(L"netsh advfirewall firewall delete rule name=\"" + n + L"_IN\"");
                RunCommand(L"netsh advfirewall firewall delete rule name=\"" + n + L"_OUT\"");
            }
        }
        RemoveTrayIcon();
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(hwnd, msg, wParam, lParam);
}


// ═══════════════════════════════════════════════════════════════════════════
//  ENTRY POINT
// ═══════════════════════════════════════════════════════════════════════════
int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE, LPWSTR, int) {
    g_hInst = hInstance;

    // Admin check
    BOOL isAdmin = FALSE;
    PSID adminGroup = nullptr;
    SID_IDENTIFIER_AUTHORITY ntAuth = SECURITY_NT_AUTHORITY;
    if (AllocateAndInitializeSid(&ntAuth, 2,
            SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS,
            0, 0, 0, 0, 0, 0, &adminGroup)) {
        CheckTokenMembership(nullptr, adminGroup, &isAdmin);
        FreeSid(adminGroup);
    }
    if (!isAdmin) {
        int r = MessageBoxW(nullptr,
            L"Anti-Scammer needs Administrator rights!\n\n"
            L"Right-click AntiScammer.exe and choose\n"
            L"\"Run as administrator\".\n\n"
            L"Continue with limited protection?",
            L"Anti-Scammer", MB_YESNO | MB_ICONWARNING);
        if (r == IDNO) return 0;
    }

    // Single instance
    HANDLE hMutex = CreateMutexW(nullptr, TRUE, L"AntiScammerPanicMutex");
    if (GetLastError() == ERROR_ALREADY_EXISTS) {
        MessageBoxW(nullptr, L"Anti-Scammer is already running!\nCheck your system tray.",
            L"Anti-Scammer", MB_OK | MB_ICONINFORMATION);
        return 0;
    }

    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);

    InitCommonControls();

    // Hidden message window (for hotkeys + tray)
    WNDCLASSEXW wc = {};
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = MsgWndProc;
    wc.hInstance = hInstance;
    wc.lpszClassName = L"AntiScammerClass";
    wc.hIcon = LoadIcon(nullptr, IDI_SHIELD);
    RegisterClassExW(&wc);

    g_msgWnd = CreateWindowExW(0, L"AntiScammerClass", L"AntiScammer",
        0, 0, 0, 0, 0, HWND_MESSAGE, nullptr, hInstance, nullptr);
    if (!g_msgWnd) return 1;

    // Register hotkeys
    struct HK { int id; UINT mod; UINT vk; };
    HK hotkeys[] = {
        { ID_HOTKEY_PANIC,      MOD_CONTROL | MOD_ALT, 'P' },
        { ID_HOTKEY_SCREEN,     MOD_CONTROL | MOD_ALT, 'S' },
        { ID_HOTKEY_INPUT,      MOD_CONTROL | MOD_ALT, 'I' },
        { ID_HOTKEY_KILL,       MOD_CONTROL | MOD_ALT, 'K' },
        { ID_HOTKEY_FIREWALL,   MOD_CONTROL | MOD_ALT, 'F' },
        { ID_HOTKEY_NETKILL,    MOD_CONTROL | MOD_ALT, 'N' },
        { ID_HOTKEY_NETRESTORE, MOD_CONTROL | MOD_ALT, 'R' },
        { ID_HOTKEY_LOG,        MOD_CONTROL | MOD_ALT, 'L' },
        { ID_HOTKEY_QUIT,       MOD_CONTROL | MOD_ALT, 'Q' },
    };
    for (auto& hk : hotkeys)
        RegisterHotKey(g_msgWnd, hk.id, hk.mod, hk.vk);

    AddTrayIcon(g_msgWnd);
    CreateGUI();

    MSG msg;
    while (GetMessage(&msg, nullptr, 0, 0)) {
        // Route messages to the correct window
        if (g_guiWnd && IsDialogMessage(g_guiWnd, &msg)) continue;
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    for (auto& hk : hotkeys)
        UnregisterHotKey(g_msgWnd, hk.id);
    WSACleanup();
    if (g_fontBig) DeleteObject(g_fontBig);
    if (g_fontMed) DeleteObject(g_fontMed);
    if (g_fontLog) DeleteObject(g_fontLog);
    if (g_fontTitle) DeleteObject(g_fontTitle);
    if (g_bgBrush) DeleteObject(g_bgBrush);
    ReleaseMutex(hMutex);
    CloseHandle(hMutex);
    return 0;
}
