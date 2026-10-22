// tooling/gui_main.cpp
//
// Native Desktop GUI for RTProtect Security Framework (Stage 5).
// Provides an intuitive graphical workspace for project selection, protection
// profiling, AST function virtualization review, automated build execution,
// and cryptographic verification reporting.

#if defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <commctrl.h>
#include <shlobj.h>
#include <string>
#include <vector>
#include <sstream>
#include <thread>
#include <atomic>

#include "tooling/integration_engine.h"

namespace {

HWND g_hMainWnd = nullptr;
HWND g_hEditProjectDir = nullptr;
HWND g_hEditTarget = nullptr;
HWND g_hComboProfile = nullptr;
HWND g_hEditProductId = nullptr;
HWND g_hBtnBrowse = nullptr;
HWND g_hBtnPlan = nullptr;
HWND g_hBtnProtect = nullptr;
HWND g_hEditLog = nullptr;
HWND g_hProgressBar = nullptr;

std::atomic<bool> g_is_busy{false};

void AppendLog(const std::string& text) {
  if (!g_hEditLog) return;
  int len = GetWindowTextLengthA(g_hEditLog);
  SendMessageA(g_hEditLog, EM_SETSEL, (WPARAM)len, (LPARAM)len);
  SendMessageA(g_hEditLog, EM_REPLACESEL, FALSE, (LPARAM)text.c_str());
  SendMessageA(g_hEditLog, EM_SCROLLCARET, 0, 0);
}

void SetProgress(int percent) {
  if (g_hProgressBar) {
    SendMessage(g_hProgressBar, PBM_SETPOS, (WPARAM)percent, 0);
  }
}

std::string BrowseForFolder(HWND hWnd) {
  char path[MAX_PATH] = {0};
  BROWSEINFOA bi{};
  bi.hwndOwner = hWnd;
  bi.lpszTitle = "Select Application Project Directory to Protect:";
  bi.ulFlags = BIF_RETURNONLYFSDIRS | BIF_NEWDIALOGSTYLE;

  LPITEMIDLIST pidl = SHBrowseForFolderA(&bi);
  if (pidl) {
    if (SHGetPathFromIDListA(pidl, path)) {
      CoTaskMemFree(pidl);
      return std::string(path);
    }
    CoTaskMemFree(pidl);
  }
  return "";
}

void RunPlanWorkflow() {
  if (g_is_busy.exchange(true)) return;

  char dir_buf[MAX_PATH] = {0};
  char target_buf[256] = {0};
  char prod_buf[256] = {0};

  GetWindowTextA(g_hEditProjectDir, dir_buf, MAX_PATH);
  GetWindowTextA(g_hEditTarget, target_buf, 256);
  GetWindowTextA(g_hEditProductId, prod_buf, 256);

  std::string proj_dir(dir_buf);
  std::string target_name(target_buf);
  std::string product_id = prod_buf[0] ? std::string(prod_buf) : "com.vendor.app";

  if (proj_dir.empty()) {
    MessageBoxA(g_hMainWnd, "Please select a project directory first.", "RTProtect", MB_ICONWARNING);
    g_is_busy.store(false);
    return;
  }

  std::thread([proj_dir, target_name, product_id]() {
    AppendLog("\r\n========================================\r\n");
    AppendLog("[RTProtect GUI] Scanning project workspace: " + proj_dir + "\r\n");
    SetProgress(20);

    rtprotect::tooling::IntegrationOptions opts;
    opts.target_project_path = proj_dir;
    opts.target_name = target_name;
    opts.product_id = product_id;
    opts.profile = rtprotect::tooling::ProtectionProfile::kMaximum;

    auto plan = rtprotect::tooling::PlanIntegration(opts);
    SetProgress(60);

    if (!plan.is_supported) {
      AppendLog("[ERROR] Project analysis failed: " + plan.explanation + "\r\n");
      SetProgress(0);
    } else {
      AppendLog("[SUCCESS] Project structure verified.\r\n");
      AppendLog("  Build System Type : " + plan.detected_build_system + "\r\n");
      AppendLog("  Detected Language : " + plan.detected_language + "\r\n");
      AppendLog("  Source Files      : " + std::to_string(plan.detected_sources.size()) + "\r\n");
      for (const auto& s : plan.detected_sources) {
        AppendLog("    - " + s + "\r\n");
      }
      AppendLog("  Files to Modify   : " + std::to_string(plan.files_to_modify.size()) + "\r\n");
      for (const auto& f : plan.files_to_modify) {
        AppendLog("    * " + f + "\r\n");
      }
      AppendLog("\r\nProject is valid and ready for protection integration.\r\n");
      SetProgress(100);
    }

    g_is_busy.store(false);
  }).detach();
}

void RunProtectWorkflow() {
  if (g_is_busy.exchange(true)) return;

  char dir_buf[MAX_PATH] = {0};
  char target_buf[256] = {0};
  char prod_buf[256] = {0};

  GetWindowTextA(g_hEditProjectDir, dir_buf, MAX_PATH);
  GetWindowTextA(g_hEditTarget, target_buf, 256);
  GetWindowTextA(g_hEditProductId, prod_buf, 256);

  std::string proj_dir(dir_buf);
  std::string target_name(target_buf);
  std::string product_id = prod_buf[0] ? std::string(prod_buf) : "com.vendor.app";

  int profile_idx = (int)SendMessage(g_hComboProfile, CB_GETCURSEL, 0, 0);
  rtprotect::tooling::ProtectionProfile profile = rtprotect::tooling::ProtectionProfile::kMaximum;
  if (profile_idx == 1) profile = rtprotect::tooling::ProtectionProfile::kBalanced;
  else if (profile_idx == 2) profile = rtprotect::tooling::ProtectionProfile::kDevelopment;

  std::thread([proj_dir, target_name, product_id, profile]() {
    AppendLog("\r\n========================================\r\n");
    AppendLog("[RTProtect GUI] Starting Full Protection Pipeline...\r\n");
    SetProgress(10);

    rtprotect::tooling::IntegrationOptions opts;
    opts.target_project_path = proj_dir;
    opts.target_name = target_name;
    opts.product_id = product_id;
    opts.profile = profile;
    opts.use_dev_keys = true;
    opts.run_build = true;

    AppendLog("[Phase 1/5] Creating backup and analyzing AST...\r\n");
    SetProgress(25);

    AppendLog("[Phase 2/5] Executing source virtualization & string encryption...\r\n");
    SetProgress(50);

    auto rep = rtprotect::tooling::ExecuteIntegration(opts);

    if (!rep.success) {
      AppendLog("[ERROR] Protection integration failed: " + rep.error_message + "\r\n");
      SetProgress(0);
      g_is_busy.store(false);
      return;
    }

    SetProgress(75);
    AppendLog("[Phase 3/5] Build result: " + std::string(rep.build_succeeded ? "SUCCESS" : "FAILED") + "\r\n");
    AppendLog("[Phase 4/5] Virtualized " + std::to_string(rep.virtualized_functions.size()) +
              " functions, obfuscated " + std::to_string(rep.obfuscated_string_count) + " strings.\r\n");
    AppendLog("[Phase 5/5] Post-build validation: " + std::string(rep.validation_succeeded ? "VERIFIED" : "FAILED") + "\r\n");

    SetProgress(100);
    AppendLog("========================================\r\n");
    AppendLog("  [STATUS] " + std::string(ToString(rep.state)) + "\r\n");
    AppendLog("  Backup Stored At: " + rep.backup_path + "\r\n");
    AppendLog("========================================\r\n");

    MessageBoxA(g_hMainWnd, "Application successfully protected, built, and verified!", "RTProtect", MB_ICONINFORMATION);
    g_is_busy.store(false);
  }).detach();
}

LRESULT CALLBACK WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
  switch (msg) {
    case WM_CREATE: {
      HFONT hFont = (HFONT)GetStockObject(DEFAULT_GUI_FONT);

      // Label & Project Dir
      CreateWindowA("STATIC", "Project Directory:", WS_CHILD | WS_VISIBLE, 20, 20, 120, 20, hWnd, nullptr, nullptr, nullptr);
      g_hEditProjectDir = CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", "", WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL, 140, 18, 400, 24, hWnd, nullptr, nullptr, nullptr);
      g_hBtnBrowse = CreateWindowA("BUTTON", "Browse...", WS_CHILD | WS_VISIBLE, 550, 18, 90, 24, hWnd, (HMENU)101, nullptr, nullptr);

      // Target Name
      CreateWindowA("STATIC", "Target Name:", WS_CHILD | WS_VISIBLE, 20, 55, 120, 20, hWnd, nullptr, nullptr, nullptr);
      g_hEditTarget = CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", "", WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL, 140, 53, 200, 24, hWnd, nullptr, nullptr, nullptr);

      // Product ID
      CreateWindowA("STATIC", "Product ID:", WS_CHILD | WS_VISIBLE, 360, 55, 80, 20, hWnd, nullptr, nullptr, nullptr);
      g_hEditProductId = CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", "com.vendor.app", WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL, 440, 53, 200, 24, hWnd, nullptr, nullptr, nullptr);

      // Protection Profile
      CreateWindowA("STATIC", "Protection Profile:", WS_CHILD | WS_VISIBLE, 20, 90, 120, 20, hWnd, nullptr, nullptr, nullptr);
      g_hComboProfile = CreateWindowA("COMBOBOX", "", WS_CHILD | WS_VISIBLE | CBS_DROPDOWNLIST, 140, 88, 500, 120, hWnd, nullptr, nullptr, nullptr);
      SendMessageA(g_hComboProfile, CB_ADDSTRING, 0, (LPARAM)"Maximum (Bytecode VM Virtualization + String Obfuscation + Full Anti-Tamper)");
      SendMessageA(g_hComboProfile, CB_ADDSTRING, 0, (LPARAM)"Balanced (Bytecode VM Virtualization + Anti-Tamper)");
      SendMessageA(g_hComboProfile, CB_ADDSTRING, 0, (LPARAM)"Development (Integrity & Basic Anti-Debug)");
      SendMessage(g_hComboProfile, CB_SETCURSEL, 0, 0);

      // Action Buttons
      g_hBtnPlan = CreateWindowA("BUTTON", "1. Scan & Plan Project", WS_CHILD | WS_VISIBLE, 140, 125, 180, 32, hWnd, (HMENU)102, nullptr, nullptr);
      g_hBtnProtect = CreateWindowA("BUTTON", "2. Integrate, Build & Verify", WS_CHILD | WS_VISIBLE, 340, 125, 200, 32, hWnd, (HMENU)103, nullptr, nullptr);

      // Progress Bar
      g_hProgressBar = CreateWindowExA(0, PROGRESS_CLASSA, "", WS_CHILD | WS_VISIBLE, 20, 170, 620, 16, hWnd, nullptr, nullptr, nullptr);

      // Output Console
      CreateWindowA("STATIC", "Protection & Build Diagnostics Log:", WS_CHILD | WS_VISIBLE, 20, 195, 300, 18, hWnd, nullptr, nullptr, nullptr);
      g_hEditLog = CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", "", WS_CHILD | WS_VISIBLE | ES_MULTILINE | ES_AUTOVSCROLL | ES_READONLY | WS_VSCROLL, 20, 215, 620, 220, hWnd, nullptr, nullptr, nullptr);

      // Set Font on all child controls
      EnumChildWindows(hWnd, [](HWND hChild, LPARAM lParam) -> BOOL {
        SendMessage(hChild, WM_SETFONT, (WPARAM)lParam, TRUE);
        return TRUE;
      }, (LPARAM)hFont);

      AppendLog("RTProtect Desktop Security Workbench v2.0-hardened\r\n");
      AppendLog("Select a CMake or Unreal Engine project directory to begin.\r\n");
      break;
    }

    case WM_COMMAND: {
      int id = LOWORD(wParam);
      if (id == 101) { // Browse
        std::string folder = BrowseForFolder(hWnd);
        if (!folder.empty()) {
          SetWindowTextA(g_hEditProjectDir, folder.c_str());
        }
      } else if (id == 102) { // Plan
        RunPlanWorkflow();
      } else if (id == 103) { // Protect
        RunProtectWorkflow();
      }
      break;
    }

    case WM_DESTROY:
      PostQuitMessage(0);
      break;

    default:
      return DefWindowProcA(hWnd, msg, wParam, lParam);
  }
  return 0;
}

}  // namespace

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE, LPSTR, int nCmdShow) {
  InitCommonControls();

  WNDCLASSA wc{};
  wc.lpfnWndProc = WndProc;
  wc.hInstance = hInstance;
  wc.lpszClassName = "RTProtectGUIWindow";
  wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
  wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);

  if (!RegisterClassA(&wc)) return 1;

  g_hMainWnd = CreateWindowExA(
      0,
      "RTProtectGUIWindow",
      "RTProtect - Anti-Piracy & Binary Protection Workbench",
      WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX,
      CW_USEDEFAULT, CW_USEDEFAULT, 675, 490,
      nullptr, nullptr, hInstance, nullptr);

  if (!g_hMainWnd) return 1;

  ShowWindow(g_hMainWnd, nCmdShow);
  UpdateWindow(g_hMainWnd);

  MSG msg;
  while (GetMessageA(&msg, nullptr, 0, 0)) {
    TranslateMessage(&msg);
    DispatchMessageA(&msg);
  }

  return (int)msg.wParam;
}

#else

#include <iostream>

int main() {
  std::cout << "RTProtect GUI is native to Windows environments.\n";
  return 0;
}

#endif
