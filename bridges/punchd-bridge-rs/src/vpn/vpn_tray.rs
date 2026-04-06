///! System tray for the VPN client (Windows).
///!
///! Shows a tray icon with right-click menu:
///! - Show Logs (opens a console/log window)
///! - Refresh Token (re-authenticates via WebView)
///! - Reconnect (drops and re-establishes VPN)
///! - Quit (exits the process)

#[cfg(target_os = "windows")]
use std::sync::Mutex;
#[cfg(target_os = "windows")]
use std::sync::OnceLock;

#[cfg(target_os = "windows")]
static TRAY_CALLBACKS: OnceLock<Mutex<TrayCallbacks>> = OnceLock::new();

#[cfg(target_os = "windows")]
struct TrayCallbacks {
    on_refresh_token: Option<Box<dyn Fn() + Send>>,
    on_reconnect: Option<Box<dyn Fn() + Send>>,
    on_show_logs: Option<Box<dyn Fn() + Send>>,
}

/// Spawn the system tray on a background thread.
#[cfg(target_os = "windows")]
pub fn spawn_vpn_tray() {
    TRAY_CALLBACKS.get_or_init(|| Mutex::new(TrayCallbacks {
        on_refresh_token: None,
        on_reconnect: None,
        on_show_logs: None,
    }));
    std::thread::Builder::new()
        .name("vpn-tray".into())
        .spawn(|| unsafe { win32::run_tray() })
        .ok();
}

#[cfg(not(target_os = "windows"))]
pub fn spawn_vpn_tray() {}

/// Set callback for "Refresh Token" menu item.
#[cfg(target_os = "windows")]
pub fn set_refresh_callback(cb: impl Fn() + Send + 'static) {
    if let Some(cbs) = TRAY_CALLBACKS.get() {
        if let Ok(mut cbs) = cbs.lock() {
            cbs.on_refresh_token = Some(Box::new(cb));
        }
    }
}

#[cfg(not(target_os = "windows"))]
pub fn set_refresh_callback(_cb: impl Fn() + Send + 'static) {}

/// Set callback for "Reconnect" menu item.
#[cfg(target_os = "windows")]
pub fn set_reconnect_callback(cb: impl Fn() + Send + 'static) {
    if let Some(cbs) = TRAY_CALLBACKS.get() {
        if let Ok(mut cbs) = cbs.lock() {
            cbs.on_reconnect = Some(Box::new(cb));
        }
    }
}

#[cfg(not(target_os = "windows"))]
pub fn set_reconnect_callback(_cb: impl Fn() + Send + 'static) {}

/// Set callback for "Show Logs" menu item.
#[cfg(target_os = "windows")]
pub fn set_logs_callback(cb: impl Fn() + Send + 'static) {
    if let Some(cbs) = TRAY_CALLBACKS.get() {
        if let Ok(mut cbs) = cbs.lock() {
            cbs.on_show_logs = Some(Box::new(cb));
        }
    }
}

#[cfg(not(target_os = "windows"))]
pub fn set_logs_callback(_cb: impl Fn() + Send + 'static) {}

#[cfg(target_os = "windows")]
fn fire_callback(which: usize) {
    if let Some(cbs) = TRAY_CALLBACKS.get() {
        if let Ok(cbs) = cbs.lock() {
            match which {
                1001 => { if let Some(ref cb) = cbs.on_show_logs { cb(); } }
                1002 => { if let Some(ref cb) = cbs.on_refresh_token { cb(); } }
                1003 => { if let Some(ref cb) = cbs.on_reconnect { cb(); } }
                _ => {}
            }
        }
    }
}

#[cfg(target_os = "windows")]
mod win32 {
    use super::fire_callback;
    use std::mem::{size_of, zeroed};

    type HWND = *mut std::ffi::c_void;
    type HMENU = *mut std::ffi::c_void;
    type HICON = *mut std::ffi::c_void;
    type HINSTANCE = *mut std::ffi::c_void;
    type HBRUSH = *mut std::ffi::c_void;
    type HCURSOR = *mut std::ffi::c_void;
    type WPARAM = usize;
    type LPARAM = isize;
    type LRESULT = isize;
    type ATOM = u16;
    type WNDPROC = unsafe extern "system" fn(HWND, u32, WPARAM, LPARAM) -> LRESULT;

    #[repr(C)]
    struct GUID { data1: u32, data2: u16, data3: u16, data4: [u8; 8] }

    #[repr(C)]
    struct WNDCLASSEXW {
        cb_size: u32, style: u32, lpfn_wnd_proc: WNDPROC,
        cb_cls_extra: i32, cb_wnd_extra: i32, h_instance: HINSTANCE,
        h_icon: HICON, h_cursor: HCURSOR, hbr_background: HBRUSH,
        lpsz_menu_name: *const u16, lpsz_class_name: *const u16, h_icon_sm: HICON,
    }

    #[repr(C)]
    struct MSG { hwnd: HWND, message: u32, w_param: WPARAM, l_param: LPARAM, time: u32, pt: POINT }

    #[repr(C)]
    #[derive(Copy, Clone)]
    struct POINT { x: i32, y: i32 }

    #[repr(C)]
    struct NOTIFYICONDATAW {
        cb_size: u32, h_wnd: HWND, u_id: u32, u_flags: u32,
        u_callback_message: u32, h_icon: HICON, sz_tip: [u16; 128],
        dw_state: u32, dw_state_mask: u32, sz_info: [u16; 256],
        u_timeout_or_version: u32, sz_info_title: [u16; 64], dw_info_flags: u32,
        guid_item: GUID, h_balloon_icon: HICON,
    }

    const WM_USER: u32 = 0x0400;
    const WM_TRAYICON: u32 = WM_USER + 1;
    const WM_COMMAND: u32 = 0x0111;
    const WM_DESTROY: u32 = 0x0002;
    const WM_RBUTTONUP: u32 = 0x0205;

    const NIM_ADD: u32 = 0x00;
    const NIM_DELETE: u32 = 0x02;
    const NIF_MESSAGE: u32 = 0x01;
    const NIF_ICON: u32 = 0x02;
    const NIF_TIP: u32 = 0x04;

    const TPM_BOTTOMALIGN: u32 = 0x0020;
    const TPM_LEFTALIGN: u32 = 0x0000;
    const MF_STRING: u32 = 0x0000;
    const MF_SEPARATOR: u32 = 0x0800;

    const ID_SHOW_LOGS: usize = 1001;
    const ID_REFRESH_TOKEN: usize = 1002;
    const ID_RECONNECT: usize = 1003;
    const ID_QUIT: usize = 1004;

    const HWND_MESSAGE: HWND = -3isize as HWND;

    unsafe extern "system" {
        fn GetModuleHandleW(name: *const u16) -> HINSTANCE;
        fn RegisterClassExW(wc: *const WNDCLASSEXW) -> ATOM;
        fn CreateWindowExW(
            ex_style: u32, class: *const u16, title: *const u16,
            style: u32, x: i32, y: i32, w: i32, h: i32,
            parent: HWND, menu: HMENU, instance: HINSTANCE, param: *mut std::ffi::c_void,
        ) -> HWND;
        fn DefWindowProcW(hwnd: HWND, msg: u32, wp: WPARAM, lp: LPARAM) -> LRESULT;
        fn GetMessageW(msg: *mut MSG, hwnd: HWND, min: u32, max: u32) -> i32;
        fn TranslateMessage(msg: *const MSG) -> i32;
        fn DispatchMessageW(msg: *const MSG) -> LRESULT;
        fn PostQuitMessage(code: i32);
        fn Shell_NotifyIconW(msg: u32, data: *mut NOTIFYICONDATAW) -> i32;
        fn LoadIconW(instance: HINSTANCE, name: *const u16) -> HICON;
        fn CreatePopupMenu() -> HMENU;
        fn AppendMenuW(menu: HMENU, flags: u32, id: usize, text: *const u16) -> i32;
        fn TrackPopupMenu(menu: HMENU, flags: u32, x: i32, y: i32, reserved: i32, hwnd: HWND, rect: *const std::ffi::c_void) -> i32;
        fn DestroyMenu(menu: HMENU) -> i32;
        fn GetCursorPos(point: *mut POINT) -> i32;
        fn SetForegroundWindow(hwnd: HWND) -> i32;
        fn GetLastError() -> u32;
    }

    fn to_wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    fn wide_into_array<const N: usize>(s: &str) -> [u16; N] {
        let mut arr = [0u16; N];
        for (i, c) in s.encode_utf16().take(N - 1).enumerate() { arr[i] = c; }
        arr
    }

    unsafe extern "system" fn wnd_proc(hwnd: HWND, msg: u32, wp: WPARAM, lp: LPARAM) -> LRESULT {
        unsafe {
            match msg {
                WM_TRAYICON => {
                    let event = (lp as u32) & 0xFFFF;
                    if event == WM_RBUTTONUP {
                        show_context_menu(hwnd);
                    }
                    0
                }
                WM_COMMAND => {
                    let id = wp & 0xFFFF;
                    match id {
                        ID_SHOW_LOGS | ID_REFRESH_TOKEN | ID_RECONNECT => {
                            fire_callback(id);
                        }
                        ID_QUIT => {
                            remove_tray_icon(hwnd);
                            PostQuitMessage(0);
                            std::process::exit(0);
                        }
                        _ => {}
                    }
                    0
                }
                WM_DESTROY => {
                    remove_tray_icon(hwnd);
                    PostQuitMessage(0);
                    0
                }
                _ => DefWindowProcW(hwnd, msg, wp, lp),
            }
        }
    }

    unsafe fn show_context_menu(hwnd: HWND) {
        unsafe {
            let menu = CreatePopupMenu();
            let logs = to_wide("Show Logs");
            let refresh = to_wide("Refresh Token");
            let reconnect = to_wide("Reconnect");
            let quit = to_wide("Quit");

            AppendMenuW(menu, MF_STRING, ID_SHOW_LOGS, logs.as_ptr());
            AppendMenuW(menu, MF_STRING, ID_REFRESH_TOKEN, refresh.as_ptr());
            AppendMenuW(menu, MF_STRING, ID_RECONNECT, reconnect.as_ptr());
            AppendMenuW(menu, MF_SEPARATOR, 0, std::ptr::null());
            AppendMenuW(menu, MF_STRING, ID_QUIT, quit.as_ptr());

            let mut pt: POINT = zeroed();
            GetCursorPos(&mut pt);
            SetForegroundWindow(hwnd);
            TrackPopupMenu(menu, TPM_LEFTALIGN | TPM_BOTTOMALIGN, pt.x, pt.y, 0, hwnd, std::ptr::null());
            DestroyMenu(menu);
        }
    }

    unsafe fn add_tray_icon(hwnd: HWND) {
        unsafe {
            let h_instance = GetModuleHandleW(std::ptr::null());
            let icon = LoadIconW(h_instance, 1 as *const u16);
            let icon = if icon.is_null() {
                LoadIconW(std::ptr::null_mut() as HINSTANCE, 32512 as *const u16)
            } else { icon };

            let mut nid: NOTIFYICONDATAW = zeroed();
            nid.cb_size = size_of::<NOTIFYICONDATAW>() as u32;
            nid.h_wnd = hwnd;
            nid.u_id = 1;
            nid.u_flags = NIF_MESSAGE | NIF_ICON | NIF_TIP;
            nid.u_callback_message = WM_TRAYICON;
            nid.h_icon = icon;
            nid.sz_tip = wide_into_array::<128>("Punchd VPN");
            Shell_NotifyIconW(NIM_ADD, &mut nid);
        }
    }

    unsafe fn remove_tray_icon(hwnd: HWND) {
        unsafe {
            let mut nid: NOTIFYICONDATAW = zeroed();
            nid.cb_size = size_of::<NOTIFYICONDATAW>() as u32;
            nid.h_wnd = hwnd;
            nid.u_id = 1;
            Shell_NotifyIconW(NIM_DELETE, &mut nid);
        }
    }

    pub unsafe fn run_tray() {
        unsafe {
            let class_name = to_wide("PunchdVPNTray");
            let h_instance = GetModuleHandleW(std::ptr::null());

            let wc = WNDCLASSEXW {
                cb_size: size_of::<WNDCLASSEXW>() as u32,
                style: 0, lpfn_wnd_proc: wnd_proc,
                cb_cls_extra: 0, cb_wnd_extra: 0, h_instance,
                h_icon: std::ptr::null_mut() as HICON,
                h_cursor: std::ptr::null_mut() as HCURSOR,
                hbr_background: std::ptr::null_mut() as HBRUSH,
                lpsz_menu_name: std::ptr::null(),
                lpsz_class_name: class_name.as_ptr(),
                h_icon_sm: std::ptr::null_mut() as HICON,
            };

            if RegisterClassExW(&wc) == 0 { return; }

            let title = to_wide("Punchd VPN");
            let hwnd = CreateWindowExW(
                0, class_name.as_ptr(), title.as_ptr(),
                0, 0, 0, 0, 0,
                HWND_MESSAGE, std::ptr::null_mut() as HMENU, h_instance, std::ptr::null_mut(),
            );
            if hwnd.is_null() { return; }

            add_tray_icon(hwnd);

            let mut msg: MSG = zeroed();
            while GetMessageW(&mut msg, std::ptr::null_mut() as HWND, 0, 0) > 0 {
                TranslateMessage(&msg);
                DispatchMessageW(&msg);
            }
        }
    }
}
