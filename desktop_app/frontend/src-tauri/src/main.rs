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
            
            #[cfg(target_os = "windows")]
            {
                use window_vibrancy::apply_mica;
                let _ = apply_mica(&window, Some(true));
            }
            
            Ok(())
        })
        .on_window_event(|event| {
            if let tauri::WindowEvent::Destroyed = event.event() {
                stop_backend();
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
