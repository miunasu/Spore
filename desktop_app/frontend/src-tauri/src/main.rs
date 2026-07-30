// Spore - Tauri 入口
// 一体化启动：自动启动/关闭 Python 后端
// 使用 Windows Job Object 确保所有子进程在 Spore 进程树下

#![cfg_attr(
    all(not(debug_assertions), target_os = "windows"),
    windows_subsystem = "windows"
)]

use std::process::{Child, Command};
use std::sync::Mutex;
use std::path::PathBuf;
use std::fs;
use tauri::Manager;

mod edge_snap;

#[cfg(target_os = "windows")]
use std::ptr::null_mut;

#[cfg(target_os = "windows")]
type HANDLE = *mut std::ffi::c_void;

// Wrapper 类型让 HANDLE 可以跨线程传递
#[cfg(target_os = "windows")]
struct SafeHandle(HANDLE);

#[cfg(target_os = "windows")]
unsafe impl Send for SafeHandle {}

#[cfg(target_os = "windows")]
unsafe impl Sync for SafeHandle {}

#[cfg(target_os = "windows")]
static JOB_HANDLE: Mutex<Option<SafeHandle>> = Mutex::new(None);

static BACKEND_PROCESS: Mutex<Option<Child>> = Mutex::new(None);

#[derive(serde::Serialize)]
struct FileClipboardPayload {
    paths: Vec<String>,
    operation: String,
}

struct AppState {
    spore_root: PathBuf,
}

const ALLOWED_FILE_ROOTS: [&str; 5] = ["output", "skills", "prompt", "history", "characters"];
const ALLOWED_ROOT_FILES: [&str; 2] = ["note.txt", ".env"];

fn normalize_spore_relative_path(path: &str) -> Result<PathBuf, String> {
    let normalized = path.replace('\\', "/");
    let trimmed = normalized.trim_matches('/');

    if trimmed.is_empty() || trimmed == "." {
        return Err("路径不能为空".to_string());
    }

    if trimmed.contains('\0') {
        return Err("路径包含非法字符".to_string());
    }

    let relative = PathBuf::from(trimmed);
    if relative.is_absolute() {
        return Err("右栏路径不能是绝对路径".to_string());
    }

    for component in relative.components() {
        match component {
            std::path::Component::Normal(_) => {}
            _ => return Err(format!("路径超出允许范围: {}", path)),
        }
    }

    if ALLOWED_ROOT_FILES.contains(&trimmed) {
        return Ok(relative);
    }

    let root = trimmed.split('/').next().unwrap_or("");
    if ALLOWED_FILE_ROOTS.contains(&root) {
        Ok(relative)
    } else {
        Err(format!("不允许访问目录: {}", root))
    }
}

fn resolve_spore_path(path: &str, spore_root: &PathBuf) -> Result<PathBuf, String> {
    normalize_spore_relative_path(path).map(|relative| spore_root.join(relative))
}

fn resolve_clipboard_path(path: &str, spore_root: &PathBuf) -> Result<PathBuf, String> {
    let candidate = PathBuf::from(path);
    if candidate.is_absolute() {
        Ok(candidate)
    } else {
        resolve_spore_path(path, spore_root)
    }
}

fn unique_target_path(target_dir: &std::path::Path, source: &std::path::Path) -> Result<PathBuf, String> {
    let file_name = source
        .file_name()
        .ok_or_else(|| format!("无法获取文件名: {}", source.display()))?;

    let first_candidate = target_dir.join(file_name);
    if !first_candidate.exists() {
        return Ok(first_candidate);
    }

    let name = file_name.to_string_lossy();
    let is_file = source.is_file();
    let (base_name, extension) = if is_file {
        match name.rfind('.') {
            Some(index) if index > 0 => (&name[..index], &name[index..]),
            _ => (name.as_ref(), ""),
        }
    } else {
        (name.as_ref(), "")
    };

    for index in 1..1000 {
        let suffix = if index == 1 {
            " - Copy".to_string()
        } else {
            format!(" - Copy {}", index)
        };
        let candidate = target_dir.join(format!("{}{}{}", base_name, suffix, extension));
        if !candidate.exists() {
            return Ok(candidate);
        }
    }

    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_millis())
        .unwrap_or(0);

    Ok(target_dir.join(format!("{} - Copy {}{}", base_name, timestamp, extension)))
}

fn copy_path_recursively(source: &std::path::Path, target: &std::path::Path) -> Result<(), String> {
    if source.is_dir() {
        fs::create_dir_all(target)
            .map_err(|error| format!("创建目录失败 {}: {}", target.display(), error))?;

        for entry in fs::read_dir(source)
            .map_err(|error| format!("读取目录失败 {}: {}", source.display(), error))?
        {
            let entry = entry.map_err(|error| format!("读取目录项失败: {}", error))?;
            let child_source = entry.path();
            let child_target = target.join(entry.file_name());
            copy_path_recursively(&child_source, &child_target)?;
        }
    } else {
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent)
                .map_err(|error| format!("创建父目录失败 {}: {}", parent.display(), error))?;
        }

        fs::copy(source, target)
            .map_err(|error| format!("复制文件失败 {} -> {}: {}", source.display(), target.display(), error))?;
    }

    Ok(())
}

fn move_path(source: &std::path::Path, target: &std::path::Path) -> Result<(), String> {
    if let Some(parent) = target.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| format!("创建父目录失败 {}: {}", parent.display(), error))?;
    }

    match fs::rename(source, target) {
        Ok(_) => Ok(()),
        Err(_) => {
            copy_path_recursively(source, target)?;
            if source.is_dir() {
                fs::remove_dir_all(source)
                    .map_err(|error| format!("删除源目录失败 {}: {}", source.display(), error))?;
            } else {
                fs::remove_file(source)
                    .map_err(|error| format!("删除源文件失败 {}: {}", source.display(), error))?;
            }
            Ok(())
        }
    }
}

fn paste_paths_to_directory(payload: FileClipboardPayload, target_dir: PathBuf) -> Result<Vec<String>, String> {
    if target_dir.exists() && !target_dir.is_dir() {
        return Err(format!("目标路径不是目录: {}", target_dir.display()));
    }

    fs::create_dir_all(&target_dir)
        .map_err(|error| format!("创建目标目录失败 {}: {}", target_dir.display(), error))?;

    let canonical_target_dir = target_dir
        .canonicalize()
        .map_err(|error| format!("解析目标目录失败 {}: {}", target_dir.display(), error))?;

    let is_cut = payload.operation == "cut";
    let mut pasted_paths = Vec::new();

    for path in payload.paths {
        let source = PathBuf::from(&path);
        if !source.exists() {
            return Err(format!("源路径不存在: {}", source.display()));
        }

        let canonical_source = source
            .canonicalize()
            .map_err(|error| format!("解析源路径失败 {}: {}", source.display(), error))?;
        let target = unique_target_path(&canonical_target_dir, &canonical_source)?;

        if canonical_source.is_dir() && target.starts_with(&canonical_source) {
            return Err("不能将文件夹粘贴到自身或其子目录".to_string());
        }

        if is_cut {
            move_path(&canonical_source, &target)?;
        } else {
            copy_path_recursively(&canonical_source, &target)?;
        }

        pasted_paths.push(target.to_string_lossy().to_string());
    }

    if is_cut {
        let _ = clear_system_file_clipboard();
    }

    Ok(pasted_paths)
}

/// 从 .env 文件读取 DESKTOP_API_PORT，供前端动态获取后端端口
#[tauri::command]
fn get_api_port(state: tauri::State<AppState>) -> u16 {
    let env_path = state.spore_root.join(".env");
    if let Ok(content) = fs::read_to_string(&env_path) {
        for line in content.lines() {
            let line = line.trim();
            if line.starts_with('#') || line.is_empty() {
                continue;
            }
            if let Some(rest) = line.strip_prefix("DESKTOP_API_PORT=") {
                if let Ok(port) = rest.trim().parse::<u16>() {
                    return port;
                }
            }
        }
    }
    8765
}

#[tauri::command]
fn configure_edge_snap(
    window: tauri::Window,
    mini_mode: bool,
    enabled: bool,
) -> Result<(), String> {
    edge_snap::configure(&window, mini_mode, enabled)
}

#[tauri::command]
fn set_file_clipboard(
    paths: Vec<String>,
    operation: String,
    state: tauri::State<AppState>,
) -> Result<(), String> {
    let mut resolved_paths = Vec::new();

    for path in paths {
        let resolved = resolve_clipboard_path(&path, &state.spore_root)?;
        if !resolved.exists() {
            return Err(format!("路径不存在: {}", resolved.display()));
        }
        resolved_paths.push(resolved);
    }

    set_system_file_clipboard(resolved_paths, &operation)
}

#[tauri::command]
fn get_file_clipboard() -> Result<Option<FileClipboardPayload>, String> {
    get_system_file_clipboard()
}

#[tauri::command]
fn paste_file_clipboard(
    target_directory: String,
    state: tauri::State<AppState>,
) -> Result<Vec<String>, String> {
    let payload = get_system_file_clipboard()?.ok_or_else(|| "系统剪贴板中没有文件".to_string())?;
    let target_dir = resolve_spore_path(&target_directory, &state.spore_root)?;
    paste_paths_to_directory(payload, target_dir)
}

#[cfg(target_os = "windows")]
const CF_HDROP: u32 = 15;
#[cfg(target_os = "windows")]
const GMEM_MOVEABLE: u32 = 0x0002;
#[cfg(target_os = "windows")]
const GMEM_ZEROINIT: u32 = 0x0040;
#[cfg(target_os = "windows")]
const DROPEFFECT_COPY: u32 = 1;
#[cfg(target_os = "windows")]
const DROPEFFECT_MOVE: u32 = 2;

#[cfg(target_os = "windows")]
#[repr(C)]
struct DropFiles {
    p_files: u32,
    pt_x: i32,
    pt_y: i32,
    f_nc: i32,
    f_wide: i32,
}

#[cfg(target_os = "windows")]
#[link(name = "user32")]
extern "system" {
    fn OpenClipboard(h_wnd_new_owner: HANDLE) -> i32;
    fn EmptyClipboard() -> i32;
    fn CloseClipboard() -> i32;
    fn SetClipboardData(u_format: u32, h_mem: HANDLE) -> HANDLE;
    fn GetClipboardData(u_format: u32) -> HANDLE;
    fn IsClipboardFormatAvailable(format: u32) -> i32;
    fn RegisterClipboardFormatW(lpsz_format: *const u16) -> u32;
}

#[cfg(target_os = "windows")]
#[link(name = "kernel32")]
extern "system" {
    fn GlobalAlloc(u_flags: u32, dw_bytes: usize) -> HANDLE;
    fn GlobalFree(h_mem: HANDLE) -> HANDLE;
    fn GlobalLock(h_mem: HANDLE) -> *mut std::ffi::c_void;
    fn GlobalUnlock(h_mem: HANDLE) -> i32;
    fn GlobalSize(h_mem: HANDLE) -> usize;
}

#[cfg(target_os = "windows")]
#[link(name = "shell32")]
extern "system" {
    fn DragQueryFileW(h_drop: HANDLE, i_file: u32, lpsz_file: *mut u16, cch: u32) -> u32;
}

#[cfg(target_os = "windows")]
struct ClipboardGuard;

#[cfg(target_os = "windows")]
impl Drop for ClipboardGuard {
    fn drop(&mut self) {
        unsafe {
            CloseClipboard();
        }
    }
}

#[cfg(target_os = "windows")]
fn open_clipboard_guard() -> Result<ClipboardGuard, String> {
    unsafe {
        if OpenClipboard(null_mut()) == 0 {
            Err("无法打开系统剪贴板".to_string())
        } else {
            Ok(ClipboardGuard)
        }
    }
}

#[cfg(target_os = "windows")]
fn preferred_drop_effect_format() -> Result<u32, String> {
    use std::os::windows::ffi::OsStrExt;

    let format_name: Vec<u16> = std::ffi::OsStr::new("Preferred DropEffect")
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    let format = unsafe { RegisterClipboardFormatW(format_name.as_ptr()) };
    if format == 0 {
        Err("注册 Preferred DropEffect 剪贴板格式失败".to_string())
    } else {
        Ok(format)
    }
}

#[cfg(target_os = "windows")]
fn create_hdrop_data(paths: &[PathBuf]) -> Result<HANDLE, String> {
    use std::os::windows::ffi::OsStrExt;

    let mut wide_paths: Vec<u16> = Vec::new();
    for path in paths {
        wide_paths.extend(path.as_os_str().encode_wide());
        wide_paths.push(0);
    }
    wide_paths.push(0);

    let header_size = std::mem::size_of::<DropFiles>();
    let total_size = header_size + wide_paths.len() * std::mem::size_of::<u16>();

    unsafe {
        let handle = GlobalAlloc(GMEM_MOVEABLE | GMEM_ZEROINIT, total_size);
        if handle.is_null() {
            return Err("分配剪贴板内存失败".to_string());
        }

        let locked = GlobalLock(handle) as *mut u8;
        if locked.is_null() {
            GlobalFree(handle);
            return Err("锁定剪贴板内存失败".to_string());
        }

        let drop_files = DropFiles {
            p_files: header_size as u32,
            pt_x: 0,
            pt_y: 0,
            f_nc: 0,
            f_wide: 1,
        };

        std::ptr::write(locked as *mut DropFiles, drop_files);
        std::ptr::copy_nonoverlapping(
            wide_paths.as_ptr() as *const u8,
            locked.add(header_size),
            wide_paths.len() * std::mem::size_of::<u16>(),
        );

        GlobalUnlock(handle);
        Ok(handle)
    }
}

#[cfg(target_os = "windows")]
fn create_drop_effect_data(effect: u32) -> Result<HANDLE, String> {
    unsafe {
        let handle = GlobalAlloc(GMEM_MOVEABLE | GMEM_ZEROINIT, std::mem::size_of::<u32>());
        if handle.is_null() {
            return Err("分配 DropEffect 内存失败".to_string());
        }

        let locked = GlobalLock(handle) as *mut u32;
        if locked.is_null() {
            GlobalFree(handle);
            return Err("锁定 DropEffect 内存失败".to_string());
        }

        std::ptr::write(locked, effect);
        GlobalUnlock(handle);
        Ok(handle)
    }
}

#[cfg(target_os = "windows")]
fn set_system_file_clipboard(paths: Vec<PathBuf>, operation: &str) -> Result<(), String> {
    if paths.is_empty() {
        return Err("没有可写入剪贴板的文件".to_string());
    }

    let effect = if operation == "cut" {
        DROPEFFECT_MOVE
    } else {
        DROPEFFECT_COPY
    };

    let hdrop = create_hdrop_data(&paths)?;
    let drop_effect = create_drop_effect_data(effect)?;
    let drop_effect_format = preferred_drop_effect_format()?;
    let _guard = open_clipboard_guard()?;

    unsafe {
        if EmptyClipboard() == 0 {
            GlobalFree(hdrop);
            GlobalFree(drop_effect);
            return Err("清空系统剪贴板失败".to_string());
        }

        if SetClipboardData(CF_HDROP, hdrop).is_null() {
            GlobalFree(hdrop);
            GlobalFree(drop_effect);
            return Err("写入 CF_HDROP 失败".to_string());
        }

        if SetClipboardData(drop_effect_format, drop_effect).is_null() {
            GlobalFree(drop_effect);
            return Err("写入 Preferred DropEffect 失败".to_string());
        }
    }

    Ok(())
}

#[cfg(target_os = "windows")]
fn clear_system_file_clipboard() -> Result<(), String> {
    let _guard = open_clipboard_guard()?;

    unsafe {
        if EmptyClipboard() == 0 {
            Err("清空系统剪贴板失败".to_string())
        } else {
            Ok(())
        }
    }
}

#[cfg(target_os = "windows")]
fn read_drop_effect() -> Result<String, String> {
    let format = preferred_drop_effect_format()?;

    unsafe {
        if IsClipboardFormatAvailable(format) == 0 {
            return Ok("copy".to_string());
        }

        let handle = GetClipboardData(format);
        if handle.is_null() {
            return Ok("copy".to_string());
        }

        if GlobalSize(handle) < std::mem::size_of::<u32>() {
            return Ok("copy".to_string());
        }

        let locked = GlobalLock(handle) as *const u32;
        if locked.is_null() {
            return Ok("copy".to_string());
        }

        let effect = std::ptr::read(locked);
        GlobalUnlock(handle);

        if effect & DROPEFFECT_MOVE != 0 {
            Ok("cut".to_string())
        } else {
            Ok("copy".to_string())
        }
    }
}

#[cfg(target_os = "windows")]
fn get_system_file_clipboard() -> Result<Option<FileClipboardPayload>, String> {
    use std::ffi::OsString;
    use std::os::windows::ffi::OsStringExt;

    unsafe {
        if IsClipboardFormatAvailable(CF_HDROP) == 0 {
            return Ok(None);
        }
    }

    let _guard = open_clipboard_guard()?;

    unsafe {
        let handle = GetClipboardData(CF_HDROP);
        if handle.is_null() {
            return Ok(None);
        }

        let count = DragQueryFileW(handle, u32::MAX, std::ptr::null_mut(), 0);
        if count == 0 {
            return Ok(None);
        }

        let mut paths = Vec::new();
        for index in 0..count {
            let len = DragQueryFileW(handle, index, std::ptr::null_mut(), 0);
            if len == 0 {
                continue;
            }

            let mut buffer = vec![0u16; len as usize + 1];
            let written = DragQueryFileW(handle, index, buffer.as_mut_ptr(), buffer.len() as u32);
            if written == 0 {
                continue;
            }

            let path = OsString::from_wide(&buffer[..written as usize])
                .to_string_lossy()
                .to_string();
            paths.push(path);
        }

        if paths.is_empty() {
            return Ok(None);
        }

        Ok(Some(FileClipboardPayload {
            paths,
            operation: read_drop_effect()?,
        }))
    }
}

#[cfg(not(target_os = "windows"))]
fn set_system_file_clipboard(_paths: Vec<PathBuf>, _operation: &str) -> Result<(), String> {
    Err("文件剪贴板互通当前仅支持 Windows".to_string())
}

#[cfg(not(target_os = "windows"))]
fn clear_system_file_clipboard() -> Result<(), String> {
    Ok(())
}

#[cfg(not(target_os = "windows"))]
fn get_system_file_clipboard() -> Result<Option<FileClipboardPayload>, String> {
    Ok(None)
}

/// 创建 Windows Job Object，确保所有子进程跟随父进程退出
#[cfg(target_os = "windows")]
fn setup_job_object() -> Option<HANDLE> {
    use std::mem::zeroed;
    
    #[link(name = "kernel32")]
    extern "system" {
        fn CreateJobObjectW(lpJobAttributes: *mut std::ffi::c_void, lpName: *const u16) -> HANDLE;
        fn SetInformationJobObject(
            hJob: HANDLE,
            JobObjectInformationClass: u32,
            lpJobObjectInformation: *mut std::ffi::c_void,
            cbJobObjectInformationLength: u32,
        ) -> i32;
        fn CloseHandle(hObject: HANDLE) -> i32;
    }
    
    const JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE: u32 = 0x2000;
    const JOB_OBJECT_EXTENDED_LIMIT_INFORMATION: u32 = 9;
    
    #[repr(C)]
    struct JOBOBJECT_BASIC_LIMIT_INFORMATION {
        per_process_user_time_limit: i64,
        per_job_user_time_limit: i64,
        limit_flags: u32,
        minimum_working_set_size: usize,
        maximum_working_set_size: usize,
        active_process_limit: u32,
        affinity: usize,
        priority_class: u32,
        scheduling_class: u32,
    }
    
    #[repr(C)]
    struct IO_COUNTERS {
        read_operation_count: u64,
        write_operation_count: u64,
        other_operation_count: u64,
        read_transfer_count: u64,
        write_transfer_count: u64,
        other_transfer_count: u64,
    }
    
    #[repr(C)]
    struct JOBOBJECT_EXTENDED_LIMIT_INFORMATION {
        basic_limit_information: JOBOBJECT_BASIC_LIMIT_INFORMATION,
        io_info: IO_COUNTERS,
        process_memory_limit: usize,
        job_memory_limit: usize,
        peak_process_memory_used: usize,
        peak_job_memory_used: usize,
    }
    
    unsafe {
        // 创建 Job Object
        let job = CreateJobObjectW(null_mut(), null_mut());
        if job.is_null() {
            return None;
        }
        
        // 设置 Job Object 属性：当 Job 关闭时杀死所有进程
        let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = zeroed();
        info.basic_limit_information.limit_flags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        
        let result = SetInformationJobObject(
            job,
            JOB_OBJECT_EXTENDED_LIMIT_INFORMATION,
            &mut info as *mut _ as *mut std::ffi::c_void,
            std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
        );
        
        if result == 0 {
            CloseHandle(job);
            return None;
        }
        
        Some(job)
    }
}

/// 将进程添加到 Job Object
#[cfg(target_os = "windows")]
fn add_process_to_job(job: HANDLE, pid: u32) -> bool {
    #[link(name = "kernel32")]
    extern "system" {
        fn OpenProcess(dwDesiredAccess: u32, bInheritHandle: i32, dwProcessId: u32) -> HANDLE;
        fn AssignProcessToJobObject(hJob: HANDLE, hProcess: HANDLE) -> i32;
        fn CloseHandle(hObject: HANDLE) -> i32;
    }
    
    const PROCESS_ALL_ACCESS: u32 = 0x1F0FFF;
    
    unsafe {
        let process = OpenProcess(PROCESS_ALL_ACCESS, 0, pid);
        if process.is_null() {
            return false;
        }
        
        let result = AssignProcessToJobObject(job, process);
        CloseHandle(process);
        
        result != 0
    }
}

/// 在指定目录中查找后端 exe 文件
/// 支持两种命名：spore_backend.exe 和 spore_backend-<triple>.exe
fn find_backend_exe(dir: &std::path::Path) -> Option<PathBuf> {
    // 优先查找带平台后缀的版本（Tauri externalBin 格式）
    let sidecar_name = format!("spore_backend-{}.exe", get_target_triple());
    let sidecar_path = dir.join(&sidecar_name);
    if sidecar_path.exists() {
        return Some(sidecar_path);
    }
    
    // 其次查找不带后缀的版本（直接部署格式）
    let plain_path = dir.join("spore_backend.exe");
    if plain_path.exists() {
        return Some(plain_path);
    }
    
    None
}

/// 判断是否为打包环境（安装后运行）
fn is_packaged() -> bool {
    let exe_path = std::env::current_exe().unwrap_or_default();
    let exe_dir = exe_path.parent().unwrap_or(std::path::Path::new("."));
    
    // 打包后，后端 exe 在 Spore.exe 同目录下
    find_backend_exe(exe_dir).is_some()
}

/// 获取当前平台的 target triple
fn get_target_triple() -> &'static str {
    if cfg!(target_os = "windows") {
        if cfg!(target_arch = "x86_64") {
            "x86_64-pc-windows-msvc"
        } else if cfg!(target_arch = "aarch64") {
            "aarch64-pc-windows-msvc"
        } else {
            "x86_64-pc-windows-msvc"
        }
    } else if cfg!(target_os = "linux") {
        "x86_64-unknown-linux-gnu"
    } else if cfg!(target_os = "macos") {
        "x86_64-apple-darwin"
    } else {
        "unknown"
    }
}

/// 获取 Spore 根目录（所有数据和资源的基础目录）
/// 
/// 打包环境：exe 所在目录即为根目录
/// 开发环境：向上查找包含 main_entry.py 的目录
fn get_spore_root() -> Option<PathBuf> {
    let exe_path = std::env::current_exe().ok()?;
    let exe_dir = exe_path.parent()?;
    
    if is_packaged() {
        // 打包环境：exe 所在目录就是 Spore 根目录
        return Some(exe_dir.to_path_buf());
    }
    
    // 开发环境：向上查找项目根目录
    let mut current = exe_dir.to_path_buf();
    for _ in 0..10 {
        if current.join("main_entry.py").exists() {
            return Some(current);
        }
        if let Some(parent) = current.parent() {
            current = parent.to_path_buf();
        } else {
            break;
        }
    }
    
    // 尝试 cwd
    if let Ok(cwd) = std::env::current_dir() {
        if cwd.join("main_entry.py").exists() {
            return Some(cwd);
        }
    }
    
    None
}

/// 确保可写目录存在
fn ensure_writable_dirs(root: &PathBuf) {
    let dirs = ["output", "history", "logs"];
    for dir in &dirs {
        let _ = fs::create_dir_all(root.join(dir));
    }
    
    // .env 文件由安装程序直接释放到安装根目录
    
    // 如果 note.txt 不存在，创建空文件
    let note_file = root.join("note.txt");
    if !note_file.exists() {
        let _ = fs::write(&note_file, "");
    }
}

/// 启动后端进程
fn start_backend(spore_root: &PathBuf) -> Option<Child> {
    let log_dir = spore_root.join("logs");
    let _ = fs::create_dir_all(&log_dir);
    
    if is_packaged() {
        // 打包环境：启动后端 exe
        let sidecar_path = find_backend_exe(spore_root).unwrap_or_else(|| {
            spore_root.join("spore_backend.exe")
        });
        
        let _ = fs::write(
            log_dir.join("startup.log"),
            format!("Starting sidecar: {}\nWorking dir: {}", sidecar_path.display(), spore_root.display()),
        );
        
        #[cfg(target_os = "windows")]
        {
            use std::os::windows::process::CommandExt;
            use std::fs::File;
            const CREATE_NO_WINDOW: u32 = 0x08000000;
            
            let stdout_file = File::create(log_dir.join("backend_stdout.log")).ok();
            let stderr_file = File::create(log_dir.join("backend_stderr.log")).ok();
            
            // 设置资源目录环境变量
            // 打包后资源直接在安装根目录下（与 exe 同级）
            // SPORE_RESOURCE_DIR 设置为安装根目录，这样代码中使用 cwd 即可访问资源
            
            let mut cmd = Command::new(&sidecar_path);
            cmd.current_dir(spore_root)
                .env("SPORE_DESKTOP_MODE", "1")
                .env("SPORE_RESOURCE_DIR", spore_root.to_str().unwrap_or(""))
                .creation_flags(CREATE_NO_WINDOW);
            
            if let Some(f) = stdout_file {
                cmd.stdout(f);
            }
            if let Some(f) = stderr_file {
                cmd.stderr(f);
            }
            
            let result = cmd.spawn();
            
            match &result {
                Ok(child) => {
                    let pid = child.id();
                    let _ = fs::write(
                        log_dir.join("startup.log"),
                        format!("Backend (sidecar) started with PID: {}\nResource dir: {}", pid, spore_root.display()),
                    );
                    
                    // 将进程添加到 Job Object
                    if let Ok(guard) = JOB_HANDLE.lock() {
                        if let Some(ref safe_job) = *guard {
                            if add_process_to_job(safe_job.0, pid) {
                                let _ = fs::write(
                                    log_dir.join("job.log"),
                                    format!("Process {} added to Job Object", pid),
                                );
                            }
                        }
                    }
                }
                Err(e) => {
                    let _ = fs::write(
                        log_dir.join("startup.log"),
                        format!("Failed to start sidecar backend: {}", e),
                    );
                }
            }
            
            return result.ok();
        }
        
        #[cfg(not(target_os = "windows"))]
        {
            return None;
        }
    } else {
        // 开发环境：用 uv 启动 main_entry.py
        let script = spore_root.join("main_entry.py");
        let uv_cache_dir = spore_root.join(".uv-cache");
        
        #[cfg(target_os = "windows")]
        {
            use std::os::windows::process::CommandExt;
            use std::fs::File;
            const CREATE_NO_WINDOW: u32 = 0x08000000;
            
            let stdout_file = File::create(log_dir.join("backend_stdout.log")).ok();
            let stderr_file = File::create(log_dir.join("backend_stderr.log")).ok();
            
            let mut cmd = Command::new("uv");
            cmd.args(["run", "python"])
                .arg(&script)
                .current_dir(spore_root)
                .env("SPORE_DESKTOP_MODE", "1")
                .env("UV_CACHE_DIR", &uv_cache_dir)
                .creation_flags(CREATE_NO_WINDOW);
            
            if let Some(f) = stdout_file {
                cmd.stdout(f);
            }
            if let Some(f) = stderr_file {
                cmd.stderr(f);
            }
            
            let result = cmd.spawn();
            
            match &result {
                Ok(child) => {
                    let pid = child.id();
                    let _ = fs::write(
                        log_dir.join("startup.log"),
                        format!("Backend (dev) started with PID: {}", pid),
                    );
                    
                    // 将 Python 进程添加到 Job Object
                    if let Ok(guard) = JOB_HANDLE.lock() {
                        if let Some(ref safe_job) = *guard {
                            if add_process_to_job(safe_job.0, pid) {
                                let _ = fs::write(
                                    log_dir.join("job.log"),
                                    format!("Process {} added to Job Object", pid),
                                );
                            }
                        }
                    }
                }
                Err(e) => {
                    let _ = fs::write(
                        log_dir.join("startup.log"),
                        format!("Failed to start dev backend: {}", e),
                    );
                }
            }
            
            return result.ok();
        }
        
        #[cfg(not(target_os = "windows"))]
        {
            use std::fs::File;
            
            let stdout_file = File::create(log_dir.join("backend_stdout.log")).ok();
            let stderr_file = File::create(log_dir.join("backend_stderr.log")).ok();
            
            let mut cmd = Command::new("uv");
            cmd.args(["run", "python"])
                .arg(&script)
                .current_dir(spore_root)
                .env("SPORE_DESKTOP_MODE", "1")
                .env("UV_CACHE_DIR", &uv_cache_dir);
            
            if let Some(f) = stdout_file {
                cmd.stdout(f);
            }
            if let Some(f) = stderr_file {
                cmd.stderr(f);
            }
            
            return cmd.spawn().ok();
        }
    }
}

fn stop_backend() {
    if let Ok(mut guard) = BACKEND_PROCESS.lock() {
        if let Some(mut child) = guard.take() {
            let pid = child.id();
            
            #[cfg(target_os = "windows")]
            {
                use std::os::windows::process::CommandExt;
                const CREATE_NO_WINDOW: u32 = 0x08000000;
                // 使用 taskkill /T 杀死整个进程树
                let _ = Command::new("taskkill")
                    .args(["/F", "/T", "/PID", &pid.to_string()])
                    .creation_flags(CREATE_NO_WINDOW)
                    .output();
            }
            
            #[cfg(not(target_os = "windows"))]
            {
                let _ = Command::new("kill")
                    .args(["-TERM", &format!("-{}", pid)])
                    .output();
            }
            
            let _ = child.wait();
        }
    }
}

fn main() {
    // Windows: 创建 Job Object
    #[cfg(target_os = "windows")]
    {
        if let Some(job) = setup_job_object() {
            if let Ok(mut guard) = JOB_HANDLE.lock() {
                *guard = Some(SafeHandle(job));
            }
        }
    }
    
    // 获取 Spore 根目录
    let spore_root = get_spore_root().expect("Cannot find Spore root directory");
    
    // 确保可写目录存在
    ensure_writable_dirs(&spore_root);
    
    tauri::Builder::default()
        .manage(AppState {
            spore_root: spore_root.clone(),
        })
        .invoke_handler(tauri::generate_handler![
            get_api_port,
            configure_edge_snap,
            set_file_clipboard,
            get_file_clipboard,
            paste_file_clipboard
        ])
        .setup(move |app| {
            // 启动后端
            if let Some(child) = start_backend(&spore_root) {
                if let Ok(mut guard) = BACKEND_PROCESS.lock() {
                    *guard = Some(child);
                }
                // 等待后端启动
                std::thread::sleep(std::time::Duration::from_secs(3));
            }
            
            let window = app.get_window("main").unwrap();
            edge_snap::start(window.clone());

            #[cfg(target_os = "windows")]
            {
                use window_vibrancy::apply_mica;
                let _ = apply_mica(&window, Some(true));
            }
            
            Ok(())
        })
        .on_window_event(|event| {
            match event.event() {
                tauri::WindowEvent::Moved(_) if event.window().label() == "main" => {
                    edge_snap::window_moved(event.window());
                }
                tauri::WindowEvent::Destroyed => {
                    edge_snap::shutdown();
                    stop_backend();
                }
                _ => {}
            }
        })
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
    
    stop_backend();
    
    // 关闭 Job Object（会自动杀死所有子进程）
    #[cfg(target_os = "windows")]
    {
        #[link(name = "kernel32")]
        extern "system" {
            fn CloseHandle(hObject: HANDLE) -> i32;
        }
        
        if let Ok(mut guard) = JOB_HANDLE.lock() {
            if let Some(safe_job) = guard.take() {
                unsafe { CloseHandle(safe_job.0); }
            }
        }
    }
}
