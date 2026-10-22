// tooling/gui_main.cpp
//
// Native Desktop GUI for RTProtect Security Framework (Stage 5).
// Provides an intuitive graphical workspace for project selection, protection
// profiling, AST function virtualization review, automated build execution,
// explicit Development vs. Production workflows, managed worker threads,
// and cryptographic verification reporting.

#if defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <commctrl.h>
#include <commdlg.h>
#include <shlobj.h>
#include <string>
#include <vector>
#include <sstream>
#include <thread>
#include <atomic>
#include <memory>

#include "tooling/integration_engine.h"

namespace {

#define WM_APP_APPEND_LOG   (WM_USER + 101)
#define WM_APP_SET_PROGRESS (WM_USER + 102)
#define WM_APP_WORK_DONE    (WM_USER + 103)

HWND g_hMainWnd = nullptr;
HWND g_hEditProjectDir = nullptr;
HWND g_hEditTarget = nullptr;
HWND g_hComboProfile = nullptr;
HWND g_hEditProductId = nullptr;
HWND g_hRadioDevMode = nullptr;
HWND g_hRadioProdMode = nullptr;
HWND g_hEditManPubKey = nullptr;
HWND g_hEditLicPubKey = nullptr;
HWND g_hBtnBrowseManPub = nullptr;
HWND g_hBtnBrowseLicPub = nullptr;
HWND g_hBtnBrowse = nullptr;
HWND g_hBtnPlan = nullptr;
HWND g_hBtnProtect = nullptr;
HWND g_hEditLog = nullptr;
HWND g_hProgressBar = nullptr;

std::atomic<bool> g_is_busy{false};
std::atomic<bool> g_worker_cancelling{false};
std::thread g_worker_thread;

void AppendLog(const std::string& text) {
  if (g_worker_cancelling.load()) return;
  if (!g_hMainWnd || !IsWindow(g_hMainWnd)) return;
  char* buf = new char[text.size() + 1];
  std::memcpy(buf, text.c_str(), text.size() + 1);
  if (!PostMessageA(g_hMainWnd, WM_APP_APPEND_LOG, 0, (LPARAM)buf)) {
    delete[] buf;
  }
}

void SetProgress(int percent) {
  if (g_worker_cancelling.load()) return;
  if (!g_hMainWnd || !IsWindow(g_hMainWnd)) return;
  PostMessageA(g_hMainWnd, WM_APP_SET_PROGRESS, (WPARAM)percent, 0);
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

std::string BrowseForFile(HWND hWnd, const char* title, const char* filter) {
  char path[MAX_PATH] = {0};
  OPENFILENAMEA ofn{};
  ofn.lStructSize = sizeof(ofn);
  ofn.hwndOwner = hWnd;
  ofn.lpstrFilter = filter;
  ofn.lpstrFile = path;
  ofn.nMaxFile = MAX_PATH;
  ofn.lpstrTitle = title;
  ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST;

  if (GetOpenFileNameA(&ofn)) {
    return std::string(path);
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

  if (g_worker_thread.joinable()) {
    g_worker_thread.join();
  }

  g_worker_thread = std::thread([proj_dir, target_name, product_id]() {
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

    if (g_hMainWnd && IsWindow(g_hMainWnd)) {
      PostMessageA(g_hMainWnd, WM_APP_WORK_DONE, 0, 0);
    }
  });
}

void RunProtectWorkflow() {
  if (g_is_busy.exchange(true)) return;

  char dir_buf[MAX_PATH] = {0};
  char target_buf[256] = {0};
  char prod_buf[256] = {0};
  char man_pub_buf[MAX_PATH] = {0};
  char lic_pub_buf[MAX_PATH] = {0};

  GetWindowTextA(g_hEditProjectDir, dir_buf, MAX_PATH);
  GetWindowTextA(g_hEditTarget, target_buf, 256);
  GetWindowTextA(g_hEditProductId, prod_buf, 256);
  GetWindowTextA(g_hEditManPubKey, man_pub_buf, MAX_PATH);
  GetWindowTextA(g_hEditLicPubKey, lic_pub_buf, MAX_PATH);

  std::string proj_dir(dir_buf);
  std::string target_name(target_buf);
  std::string product_id = prod_buf[0] ? std::string(prod_buf) : "com.vendor.app";
  std::string man_pub_path(man_pub_buf);
  std::string lic_pub_path(lic_pub_buf);

  if (proj_dir.empty()) {
    MessageBoxA(g_hMainWnd, "Please select a project directory first.", "RTProtect", MB_ICONWARNING);
    g_is_busy.store(false);
    return;
  }

  bool is_prod_mode = (SendMessageA(g_hRadioProdMode, BM_GETCHECK, 0, 0) == BST_CHECKED);
  if (is_prod_mode) {
    if (man_pub_path.empty() || lic_pub_path.empty()) {
      MessageBoxA(g_hMainWnd,
                  "Production Release Mode requires configured vendor verification public keys.\n\n"
                  "Please specify both Manifest Public Key and License Public Key, or switch to Development Mode.",
                  "RTProtect - Missing Production Keys", MB_ICONERROR);
      g_is_busy.store(false);
      return;
    }
  }

  int profile_idx = (int)SendMessage(g_hComboProfile, CB_GETCURSEL, 0, 0);
  rtprotect::tooling::ProtectionProfile profile = rtprotect::tooling::ProtectionProfile::kMaximum;
  if (profile_idx == 1) profile = rtprotect::tooling::ProtectionProfile::kBalanced;
  else if (profile_idx == 2) profile = rtprotect::tooling::ProtectionProfile::kDevelopment;

  if (g_worker_thread.joinable()) {
    g_worker_thread.join();
  }

  g_worker_thread = std::thread([proj_dir, target_name, product_id, profile, is_prod_mode, man_pub_path, lic_pub_path]() {
    AppendLog("\r\n========================================\r\n");
    AppendLog(std::string("[RTProtect GUI] Starting ") +
              (is_prod_mode ? "PRODUCTION RELEASE" : "DEVELOPMENT") + " Pipeline...\r\n");
    SetProgress(10);

    rtprotect::tooling::IntegrationOptions opts;
    opts.target_project_path = proj_dir;
    opts.target_name = target_name;
    opts.product_id = product_id;
    opts.profile = profile;
    opts.run_build = true;

    if (is_prod_mode) {
      opts.use_dev_keys = false;
      opts.manifest_pubkey_path = man_pub_path;
      opts.license_pubkey_path = lic_pub_path;
    } else {
      opts.use_dev_keys = true;
    }

    AppendLog("[Phase 1/5] Creating backup and analyzing AST...\r\n");
    SetProgress(25);

    AppendLog("[Phase 2/5] Executing source virtualization & string encryption...\r\n");
    SetProgress(50);

    auto rep = rtprotect::tooling::ExecuteIntegration(opts);

    if (!rep.success) {
      AppendLog("[ERROR] Protection integration failed: " + rep.error_message + "\r\n");
      SetProgress(0);
      if (g_hMainWnd && IsWindow(g_hMainWnd)) {
        PostMessageA(g_hMainWnd, WM_APP_WORK_DONE, 0, 0);
      }
      return;
    }

    SetProgress(75);
    AppendLog("[Phase 3/5] Build result: " + std::string(rep.build_succeeded ? "SUCCESS" : "FAILED") + "\r\n");
    AppendLog("[Phase 4/5] Virtualized " + std::to_string(rep.virtualized_functions.size()) +
              " functions, obfuscated " + std::to_string(rep.obfuscated_string_count) + " strings.\r\n");
    AppendLog("[Phase 5/5] Post-build validation: " + std::string(rep.validation_succeeded ? "VERIFIED" : "FAILED") + "\r\n");

    SetProgress(100);
    AppendLog("========================================\r\n");
    AppendLog("  [INTEGRATION STATE] " + std::string(ToString(rep.state)) + "\r\n");
    AppendLog("  [BUILD STATUS]      " + std::string(rep.build_succeeded ? "SUCCESS" : "FAILED") + "\r\n");
    AppendLog("  [VALIDATION STATUS] " + std::string(rep.validation_succeeded ? "VERIFIED" : "FAILED") + "\r\n");
    if (!rep.backup_path.empty()) {
      AppendLog("  Backup Stored At:   " + rep.backup_path + "\r\n");
    }
    AppendLog("========================================\r\n");

    if (rep.success && rep.state == rtprotect::tooling::IntegrationState::kValidated &&
        rep.build_succeeded && rep.validation_succeeded) {
      if (!g_worker_cancelling.load() && g_hMainWnd && IsWindow(g_hMainWnd)) {
        MessageBoxA(g_hMainWnd, "Application successfully protected, built, and cryptographically verified!", "RTProtect", MB_ICONINFORMATION);
      }
    } else if (rep.success && (!rep.build_succeeded || !rep.validation_succeeded)) {
      if (!g_worker_cancelling.load() && g_hMainWnd && IsWindow(g_hMainWnd)) {
        MessageBoxA(g_hMainWnd, "Source integration succeeded, but build and/or post-build cryptographic validation failed. Check diagnostics log.", "RTProtect", MB_ICONWARNING);
      }
    }

    if (g_hMainWnd && IsWindow(g_hMainWnd)) {
      PostMessageA(g_hMainWnd, WM_APP_WORK_DONE, 0, 0);
    }
  });
}

LRESULT CALLBACK WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
  switch (msg) {
    case WM_CREATE: {
      HFONT hFont = (HFONT)GetStockObject(DEFAULT_GUI_FONT);

      // Label & Project Dir
      CreateWindowA("STATIC", "Project Directory:", WS_CHILD | WS_VISIBLE, 20, 18, 120, 20, hWnd, nullptr, nullptr, nullptr);
      g_hEditProjectDir = CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", "", WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL, 140, 16, 440, 24, hWnd, nullptr, nullptr, nullptr);
      g_hBtnBrowse = CreateWindowA("BUTTON", "Browse...", WS_CHILD | WS_VISIBLE, 590, 16, 90, 24, hWnd, (HMENU)101, nullptr, nullptr);

      // Target Name
      CreateWindowA("STATIC", "Target Name:", WS_CHILD | WS_VISIBLE, 20, 48, 120, 20, hWnd, nullptr, nullptr, nullptr);
      g_hEditTarget = CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", "", WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL, 140, 46, 200, 24, hWnd, nullptr, nullptr, nullptr);

      // Product ID
      CreateWindowA("STATIC", "Product ID:", WS_CHILD | WS_VISIBLE, 360, 48, 80, 20, hWnd, nullptr, nullptr, nullptr);
      g_hEditProductId = CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", "com.vendor.app", WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL, 440, 46, 240, 24, hWnd, nullptr, nullptr, nullptr);

      // Protection Profile
      CreateWindowA("STATIC", "Protection Profile:", WS_CHILD | WS_VISIBLE, 20, 78, 120, 20, hWnd, nullptr, nullptr, nullptr);
      g_hComboProfile = CreateWindowA("COMBOBOX", "", WS_CHILD | WS_VISIBLE | CBS_DROPDOWNLIST, 140, 76, 540, 120, hWnd, nullptr, nullptr, nullptr);
      SendMessageA(g_hComboProfile, CB_ADDSTRING, 0, (LPARAM)"Maximum (Bytecode VM Virtualization + String Obfuscation + Full Anti-Tamper)");
      SendMessageA(g_hComboProfile, CB_ADDSTRING, 0, (LPARAM)"Balanced (Bytecode VM Virtualization + Anti-Tamper)");
      SendMessageA(g_hComboProfile, CB_ADDSTRING, 0, (LPARAM)"Development (Integrity & Basic Anti-Debug)");
      SendMessage(g_hComboProfile, CB_SETCURSEL, 0, 0);

      // Workflow Mode Radio Buttons
      CreateWindowA("STATIC", "Workflow Mode:", WS_CHILD | WS_VISIBLE, 20, 108, 120, 20, hWnd, nullptr, nullptr, nullptr);
      g_hRadioDevMode = CreateWindowA("BUTTON", "Development / Test Mode (ephemeral dev keys & local token)",
                                      WS_CHILD | WS_VISIBLE | BS_AUTORADIOBUTTON | WS_GROUP,
                                      140, 106, 280, 22, hWnd, (HMENU)110, nullptr, nullptr);
      g_hRadioProdMode = CreateWindowA("BUTTON", "Production Release Mode (pre-provisioned keys required)",
                                       WS_CHILD | WS_VISIBLE | BS_AUTORADIOBUTTON,
                                       430, 106, 260, 22, hWnd, (HMENU)111, nullptr, nullptr);
      SendMessage(g_hRadioDevMode, BM_SETCHECK, BST_CHECKED, 0);

      // Production Public Keys (Manifest Pub Key)
      CreateWindowA("STATIC", "Manifest PubKey:", WS_CHILD | WS_VISIBLE, 20, 138, 120, 20, hWnd, nullptr, nullptr, nullptr);
      g_hEditManPubKey = CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", "", WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL, 140, 136, 440, 24, hWnd, nullptr, nullptr, nullptr);
      g_hBtnBrowseManPub = CreateWindowA("BUTTON", "Browse...", WS_CHILD | WS_VISIBLE, 590, 136, 90, 24, hWnd, (HMENU)104, nullptr, nullptr);

      // License Public Key
      CreateWindowA("STATIC", "License PubKey:", WS_CHILD | WS_VISIBLE, 20, 168, 120, 20, hWnd, nullptr, nullptr, nullptr);
      g_hEditLicPubKey = CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", "", WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL, 140, 166, 440, 24, hWnd, nullptr, nullptr, nullptr);
      g_hBtnBrowseLicPub = CreateWindowA("BUTTON", "Browse...", WS_CHILD | WS_VISIBLE, 590, 166, 90, 24, hWnd, (HMENU)105, nullptr, nullptr);

      // Action Buttons
      g_hBtnPlan = CreateWindowA("BUTTON", "1. Scan & Plan Project", WS_CHILD | WS_VISIBLE, 140, 202, 190, 32, hWnd, (HMENU)102, nullptr, nullptr);
      g_hBtnProtect = CreateWindowA("BUTTON", "2. Integrate, Build & Verify", WS_CHILD | WS_VISIBLE, 350, 202, 230, 32, hWnd, (HMENU)103, nullptr, nullptr);

      // Progress Bar
      g_hProgressBar = CreateWindowExA(0, PROGRESS_CLASSA, "", WS_CHILD | WS_VISIBLE, 20, 246, 660, 16, hWnd, nullptr, nullptr, nullptr);

      // Output Console
      CreateWindowA("STATIC", "Protection & Build Diagnostics Log:", WS_CHILD | WS_VISIBLE, 20, 270, 300, 18, hWnd, nullptr, nullptr, nullptr);
      g_hEditLog = CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", "", WS_CHILD | WS_VISIBLE | ES_MULTILINE | ES_AUTOVSCROLL | ES_READONLY | WS_VSCROLL, 20, 290, 660, 250, hWnd, nullptr, nullptr, nullptr);

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
      if (id == 101) { // Browse project dir
        std::string folder = BrowseForFolder(hWnd);
        if (!folder.empty()) {
          SetWindowTextA(g_hEditProjectDir, folder.c_str());
        }
      } else if (id == 104) { // Browse manifest pub key
        std::string file = BrowseForFile(hWnd, "Select Manifest Public Key (release.pub)", "Public Key Files (*.pub)\0*.pub\0All Files (*.*)\0*.*\0");
        if (!file.empty()) {
          SetWindowTextA(g_hEditManPubKey, file.c_str());
        }
      } else if (id == 105) { // Browse license pub key
        std::string file = BrowseForFile(hWnd, "Select License Public Key (license.pub)", "Public Key Files (*.pub)\0*.pub\0All Files (*.*)\0*.*\0");
        if (!file.empty()) {
          SetWindowTextA(g_hEditLicPubKey, file.c_str());
        }
      } else if (id == 102) { // Plan
        RunPlanWorkflow();
      } else if (id == 103) { // Protect
        RunProtectWorkflow();
      }
      break;
    }

    case WM_APP_APPEND_LOG: {
      char* str = reinterpret_cast<char*>(lParam);
      if (str && g_hEditLog && IsWindow(g_hEditLog)) {
        int len = GetWindowTextLengthA(g_hEditLog);
        SendMessageA(g_hEditLog, EM_SETSEL, (WPARAM)len, (LPARAM)len);
        SendMessageA(g_hEditLog, EM_REPLACESEL, FALSE, (LPARAM)str);
        SendMessageA(g_hEditLog, EM_SCROLLCARET, 0, 0);
      }
      delete[] str;
      return 0;
    }

    case WM_APP_SET_PROGRESS: {
      if (g_hProgressBar && IsWindow(g_hProgressBar)) {
        SendMessage(g_hProgressBar, PBM_SETPOS, wParam, 0);
      }
      return 0;
    }

    case WM_APP_WORK_DONE: {
      g_is_busy.store(false);
      return 0;
    }

    case WM_CLOSE: {
      g_worker_cancelling.store(true);
      if (g_worker_thread.joinable()) {
        g_worker_thread.join();
      }
      DestroyWindow(hWnd);
      return 0;
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
      CW_USEDEFAULT, CW_USEDEFAULT, 715, 600,
      nullptr, nullptr, hInstance, nullptr);

  if (!g_hMainWnd) return 1;

  ShowWindow(g_hMainWnd, nCmdShow);
  UpdateWindow(g_hMainWnd);

  MSG msg;
  while (GetMessageA(&msg, nullptr, 0, 0)) {
    TranslateMessage(&msg);
    DispatchMessageA(&msg);
  }

  if (g_worker_thread.joinable()) {
    g_worker_thread.join();
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
