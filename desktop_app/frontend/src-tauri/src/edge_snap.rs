#[cfg(target_os = "windows")]
mod windows {
    use std::sync::Mutex;
    use std::time::{Duration, Instant};

    use serde::Serialize;
    use tauri::{PhysicalPosition, Window};

    const SNAP_DISTANCE: i32 = 40;
    const REVEAL_SIZE: i32 = 8;
    const REVEAL_TRIGGER_SIZE: i32 = 12;
    const MOVE_SETTLE_DELAY: Duration = Duration::from_millis(180);
    const HIDE_DELAY: Duration = Duration::from_millis(650);
    const POLL_INTERVAL: Duration = Duration::from_millis(50);
    const ANIMATION_STEPS: i32 = 8;
    const ANIMATION_INTERVAL: Duration = Duration::from_millis(14);

    type Handle = *mut std::ffi::c_void;

    #[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
    #[serde(rename_all = "lowercase")]
    enum SnapEdge {
        Left,
        Right,
        Top,
        Bottom,
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    struct WorkArea {
        left: i32,
        top: i32,
        right: i32,
        bottom: i32,
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    struct DockedWindow {
        edge: SnapEdge,
        shown: PhysicalPosition<i32>,
        hidden: PhysicalPosition<i32>,
        work_area: WorkArea,
    }

    struct EdgeSnapState {
        mini_mode: bool,
        enabled: bool,
        dock: Option<DockedWindow>,
        hidden: bool,
        animating: bool,
        generation: u64,
        last_move_at: Option<Instant>,
        last_move_cursor: Option<PhysicalPosition<i32>>,
        mouse_out_since: Option<Instant>,
        reveal_armed: bool,
        suppress_moved_until: Option<Instant>,
        shutting_down: bool,
    }

    static EDGE_SNAP_STATE: Mutex<EdgeSnapState> = Mutex::new(EdgeSnapState {
        mini_mode: false,
        enabled: false,
        dock: None,
        hidden: false,
        animating: false,
        generation: 0,
        last_move_at: None,
        last_move_cursor: None,
        mouse_out_since: None,
        reveal_armed: false,
        suppress_moved_until: None,
        shutting_down: false,
    });

    #[derive(Clone, Serialize)]
    #[serde(rename_all = "camelCase")]
    struct EdgeSnapPayload {
        edge: Option<SnapEdge>,
        hidden: bool,
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct Point {
        x: i32,
        y: i32,
    }

    #[repr(C)]
    struct Rect {
        left: i32,
        top: i32,
        right: i32,
        bottom: i32,
    }

    #[repr(C)]
    struct MonitorInfo {
        cb_size: u32,
        rc_monitor: Rect,
        rc_work: Rect,
        flags: u32,
    }

    #[link(name = "user32")]
    extern "system" {
        fn MonitorFromPoint(point: Point, flags: u32) -> Handle;
        fn GetMonitorInfoW(monitor: Handle, info: *mut MonitorInfo) -> i32;
        fn GetCursorPos(point: *mut Point) -> i32;
        fn GetAsyncKeyState(key: i32) -> i16;
    }

    fn emit_state(window: &Window, dock: Option<DockedWindow>, hidden: bool) {
        let _ = window.emit(
            "edge-snap-state",
            EdgeSnapPayload {
                edge: dock.map(|value| value.edge),
                hidden,
            },
        );
    }

    fn work_area_at(point: PhysicalPosition<i32>) -> Option<WorkArea> {
        const MONITOR_DEFAULTTONEAREST: u32 = 2;
        let monitor = unsafe {
            MonitorFromPoint(
                Point {
                    x: point.x,
                    y: point.y,
                },
                MONITOR_DEFAULTTONEAREST,
            )
        };
        if monitor.is_null() {
            return None;
        }

        let mut info = MonitorInfo {
            cb_size: std::mem::size_of::<MonitorInfo>() as u32,
            rc_monitor: Rect {
                left: 0,
                top: 0,
                right: 0,
                bottom: 0,
            },
            rc_work: Rect {
                left: 0,
                top: 0,
                right: 0,
                bottom: 0,
            },
            flags: 0,
        };
        if unsafe { GetMonitorInfoW(monitor, &mut info) } == 0 {
            return None;
        }

        Some(WorkArea {
            left: info.rc_work.left,
            top: info.rc_work.top,
            right: info.rc_work.right,
            bottom: info.rc_work.bottom,
        })
    }

    fn cursor_position() -> Option<PhysicalPosition<i32>> {
        let mut point = Point { x: 0, y: 0 };
        if unsafe { GetCursorPos(&mut point) } == 0 {
            None
        } else {
            Some(PhysicalPosition::new(point.x, point.y))
        }
    }

    fn left_button_pressed() -> bool {
        const VK_LBUTTON: i32 = 0x01;
        unsafe { (GetAsyncKeyState(VK_LBUTTON) as u16 & 0x8000) != 0 }
    }

    fn clamp(value: i32, min: i32, max: i32) -> i32 {
        if max < min {
            min
        } else {
            value.max(min).min(max)
        }
    }

    fn edge_distance(
        edge: SnapEdge,
        position: PhysicalPosition<i32>,
        width: i32,
        height: i32,
        cursor: PhysicalPosition<i32>,
        work: WorkArea,
    ) -> i32 {
        // 窗口边框一旦越过对应工作区边缘，距离保持为 0。
        // 不能使用 abs()：越界越多时绝对值反而越大，会错误地取消吸附。
        let window_distance = match edge {
            SnapEdge::Left => (position.x - work.left).max(0),
            SnapEdge::Right => (work.right - (position.x + width)).max(0),
            SnapEdge::Top => (position.y - work.top).max(0),
            SnapEdge::Bottom => (work.bottom - (position.y + height)).max(0),
        };
        let cursor_distance = match edge {
            SnapEdge::Left => (cursor.x - work.left).abs(),
            SnapEdge::Right => (cursor.x - (work.right - 1)).abs(),
            SnapEdge::Top => (cursor.y - work.top).abs(),
            SnapEdge::Bottom => (cursor.y - (work.bottom - 1)).abs(),
        };
        window_distance.min(cursor_distance)
    }

    fn calculate_dock(
        window: &Window,
        cursor: PhysicalPosition<i32>,
    ) -> Option<DockedWindow> {
        let position = window.outer_position().ok()?;
        let size = window.outer_size().ok()?;
        let width = i32::try_from(size.width).ok()?;
        let height = i32::try_from(size.height).ok()?;
        let work = work_area_at(cursor)?;

        let edges = [
            SnapEdge::Left,
            SnapEdge::Right,
            SnapEdge::Top,
            SnapEdge::Bottom,
        ];
        let edge = edges.into_iter().min_by_key(|edge| {
            edge_distance(*edge, position, width, height, cursor, work)
        })?;
        if edge_distance(edge, position, width, height, cursor, work) > SNAP_DISTANCE {
            return None;
        }

        let shown_x = match edge {
            SnapEdge::Left => work.left,
            SnapEdge::Right => work.right - width,
            SnapEdge::Top | SnapEdge::Bottom => {
                clamp(position.x, work.left, work.right - width)
            }
        };
        let shown_y = match edge {
            SnapEdge::Top => work.top,
            SnapEdge::Bottom => work.bottom - height,
            SnapEdge::Left | SnapEdge::Right => {
                clamp(position.y, work.top, work.bottom - height)
            }
        };
        let hidden_x = match edge {
            SnapEdge::Left => work.left - width + REVEAL_SIZE,
            SnapEdge::Right => work.right - REVEAL_SIZE,
            SnapEdge::Top | SnapEdge::Bottom => shown_x,
        };
        let hidden_y = match edge {
            SnapEdge::Top => work.top - height + REVEAL_SIZE,
            SnapEdge::Bottom => work.bottom - REVEAL_SIZE,
            SnapEdge::Left | SnapEdge::Right => shown_y,
        };

        Some(DockedWindow {
            edge,
            shown: PhysicalPosition::new(shown_x, shown_y),
            hidden: PhysicalPosition::new(hidden_x, hidden_y),
            work_area: work,
        })
    }

    fn animation_is_current(generation: u64) -> bool {
        EDGE_SNAP_STATE
            .lock()
            .map(|state| state.generation == generation && state.animating)
            .unwrap_or(false)
    }

    fn animate_to(
        window: &Window,
        target: PhysicalPosition<i32>,
        generation: u64,
    ) -> bool {
        let start = match window.outer_position() {
            Ok(value) => value,
            Err(_) => return false,
        };

        for step in 1..=ANIMATION_STEPS {
            if !animation_is_current(generation) {
                return false;
            }
            let x = start.x + (target.x - start.x) * step / ANIMATION_STEPS;
            let y = start.y + (target.y - start.y) * step / ANIMATION_STEPS;
            if window
                .set_position(PhysicalPosition::new(x, y))
                .is_err()
            {
                return false;
            }
            if step < ANIMATION_STEPS {
                std::thread::sleep(ANIMATION_INTERVAL);
            }
        }
        true
    }

    fn dock_and_hide(window: &Window, dock: DockedWindow, generation: u64) {
        {
            let mut state = match EDGE_SNAP_STATE.lock() {
                Ok(value) => value,
                Err(_) => return,
            };
            if state.generation != generation
                || !state.mini_mode
                || !state.enabled
                || state.dock.is_some()
            {
                return;
            }
            state.animating = true;
            state.dock = Some(dock);
        }

        let completed = animate_to(window, dock.shown, generation)
            && animate_to(window, dock.hidden, generation);
        let mut should_emit = false;
        if let Ok(mut state) = EDGE_SNAP_STATE.lock() {
            if completed
                && state.generation == generation
                && state.mini_mode
                && state.enabled
            {
                state.hidden = true;
                state.mouse_out_since = None;
                state.reveal_armed = false;
                state.suppress_moved_until = Some(Instant::now() + MOVE_SETTLE_DELAY);
                should_emit = true;
            } else if state.generation == generation {
                state.dock = None;
                state.hidden = false;
            }
            if state.generation == generation {
                state.animating = false;
            }
        }
        if should_emit {
            emit_state(window, Some(dock), true);
        }
    }

    fn transition_docked(
        window: &Window,
        dock: DockedWindow,
        hide: bool,
        generation: u64,
    ) {
        {
            let mut state = match EDGE_SNAP_STATE.lock() {
                Ok(value) => value,
                Err(_) => return,
            };
            if state.generation != generation
                || state.dock != Some(dock)
                || state.animating
            {
                return;
            }
            state.animating = true;
        }

        let target = if hide { dock.hidden } else { dock.shown };
        let completed = animate_to(window, target, generation);
        let mut should_emit = false;
        if let Ok(mut state) = EDGE_SNAP_STATE.lock() {
            if completed && state.generation == generation && state.dock == Some(dock) {
                state.hidden = hide;
                state.mouse_out_since = None;
                state.reveal_armed = false;
                state.suppress_moved_until = Some(Instant::now() + MOVE_SETTLE_DELAY);
                should_emit = true;
            }
            if state.generation == generation {
                state.animating = false;
            }
        }
        if should_emit {
            emit_state(window, Some(dock), hide);
        }
    }

    fn cursor_hits_reveal(
        cursor: PhysicalPosition<i32>,
        dock: DockedWindow,
        window: &Window,
    ) -> bool {
        let size = match window.outer_size() {
            Ok(value) => value,
            Err(_) => return false,
        };
        let width = size.width as i32;
        let height = size.height as i32;

        match dock.edge {
            SnapEdge::Left => {
                cursor.x >= dock.work_area.left
                    && cursor.x <= dock.work_area.left + REVEAL_TRIGGER_SIZE
                    && cursor.y >= dock.shown.y
                    && cursor.y < dock.shown.y + height
            }
            SnapEdge::Right => {
                cursor.x >= dock.work_area.right - REVEAL_TRIGGER_SIZE
                    && cursor.x < dock.work_area.right
                    && cursor.y >= dock.shown.y
                    && cursor.y < dock.shown.y + height
            }
            SnapEdge::Top => {
                cursor.y >= dock.work_area.top
                    && cursor.y <= dock.work_area.top + REVEAL_TRIGGER_SIZE
                    && cursor.x >= dock.shown.x
                    && cursor.x < dock.shown.x + width
            }
            SnapEdge::Bottom => {
                cursor.y >= dock.work_area.bottom - REVEAL_TRIGGER_SIZE
                    && cursor.y < dock.work_area.bottom
                    && cursor.x >= dock.shown.x
                    && cursor.x < dock.shown.x + width
            }
        }
    }

    fn cursor_inside_window(cursor: PhysicalPosition<i32>, window: &Window) -> bool {
        let position = match window.outer_position() {
            Ok(value) => value,
            Err(_) => return false,
        };
        let size = match window.outer_size() {
            Ok(value) => value,
            Err(_) => return false,
        };
        let right = position.x.saturating_add(size.width as i32);
        let bottom = position.y.saturating_add(size.height as i32);
        cursor.x >= position.x
            && cursor.x < right
            && cursor.y >= position.y
            && cursor.y < bottom
    }

    fn poll_edge_snap(window: Window) {
        loop {
            std::thread::sleep(POLL_INTERVAL);

            let snapshot = {
                let state = match EDGE_SNAP_STATE.lock() {
                    Ok(value) => value,
                    Err(_) => continue,
                };
                if state.shutting_down {
                    break;
                }
                if !state.mini_mode || !state.enabled || state.animating {
                    continue;
                }
                (
                    state.dock,
                    state.hidden,
                    state.generation,
                    state.last_move_at,
                    state.last_move_cursor,
                    state.reveal_armed,
                )
            };

            if let Some(dock) = snapshot.0 {
                let cursor = match cursor_position() {
                    Some(value) => value,
                    None => continue,
                };
                if snapshot.1 {
                    let hits_reveal = cursor_hits_reveal(cursor, dock, &window);
                    if !snapshot.5 {
                        if !hits_reveal {
                            if let Ok(mut state) = EDGE_SNAP_STATE.lock() {
                                state.reveal_armed = true;
                            }
                        }
                        continue;
                    }
                    if hits_reveal {
                        transition_docked(&window, dock, false, snapshot.2);
                    }
                    continue;
                }

                if cursor_inside_window(cursor, &window) {
                    if let Ok(mut state) = EDGE_SNAP_STATE.lock() {
                        state.mouse_out_since = None;
                    }
                    continue;
                }

                let should_hide = {
                    let mut state = match EDGE_SNAP_STATE.lock() {
                        Ok(value) => value,
                        Err(_) => continue,
                    };
                    let since = state.mouse_out_since.get_or_insert_with(Instant::now);
                    since.elapsed() >= HIDE_DELAY
                };
                if should_hide {
                    transition_docked(&window, dock, true, snapshot.2);
                }
                continue;
            }

            if left_button_pressed() {
                continue;
            }
            if !snapshot
                .3
                .map(|time| time.elapsed() >= MOVE_SETTLE_DELAY)
                .unwrap_or(false)
            {
                continue;
            }

            if let Ok(mut state) = EDGE_SNAP_STATE.lock() {
                state.last_move_at = None;
            }
            let cursor = snapshot.4.or_else(cursor_position);
            if let Some(dock) = cursor.and_then(|value| calculate_dock(&window, value)) {
                dock_and_hide(&window, dock, snapshot.2);
            }
        }
    }

    pub fn start(window: Window) {
        std::thread::spawn(move || poll_edge_snap(window));
    }

    pub fn window_moved(window: &Window) {
        let mut undocked = false;
        if let Ok(mut state) = EDGE_SNAP_STATE.lock() {
            if !state.mini_mode || !state.enabled || state.animating {
                return;
            }
            if state
                .suppress_moved_until
                .map(|until| Instant::now() < until)
                .unwrap_or(false)
            {
                return;
            }
            state.suppress_moved_until = None;
            if state.dock.is_some() && !state.hidden && left_button_pressed() {
                state.generation = state.generation.wrapping_add(1);
                state.dock = None;
                state.hidden = false;
                state.mouse_out_since = None;
                undocked = true;
            }
            if state.dock.is_none() {
                state.last_move_at = Some(Instant::now());
                state.last_move_cursor = cursor_position();
            }
        }
        if undocked {
            emit_state(window, None, false);
        }
    }

    pub fn configure(window: &Window, mini_mode: bool, enabled: bool) -> Result<(), String> {
        let (dock_to_restore, generation) = {
            let mut state = EDGE_SNAP_STATE
                .lock()
                .map_err(|_| "边缘吸附状态锁已损坏".to_string())?;
            state.generation = state.generation.wrapping_add(1);
            let generation = state.generation;
            state.mini_mode = mini_mode;
            state.enabled = mini_mode && enabled;
            state.last_move_at = None;
            state.last_move_cursor = None;
            state.mouse_out_since = None;
            state.reveal_armed = false;
            state.suppress_moved_until = None;
            let dock = if state.enabled {
                None
            } else {
                state.dock.take()
            };
            state.hidden = false;
            state.animating = dock.is_some();
            (dock, generation)
        };

        if let Some(dock) = dock_to_restore {
            let _ = animate_to(window, dock.shown, generation);
        }

        if let Ok(mut state) = EDGE_SNAP_STATE.lock() {
            if state.generation == generation {
                state.animating = false;
                state.hidden = false;
            }
        }
        emit_state(window, None, false);
        Ok(())
    }

    pub fn shutdown() {
        if let Ok(mut state) = EDGE_SNAP_STATE.lock() {
            state.shutting_down = true;
            state.generation = state.generation.wrapping_add(1);
        }
    }
}

#[cfg(target_os = "windows")]
pub use windows::{configure, shutdown, start, window_moved};

#[cfg(not(target_os = "windows"))]
pub fn start(_window: tauri::Window) {}

#[cfg(not(target_os = "windows"))]
pub fn window_moved(_window: &tauri::Window) {}

#[cfg(not(target_os = "windows"))]
pub fn configure(
    _window: &tauri::Window,
    _mini_mode: bool,
    _enabled: bool,
) -> Result<(), String> {
    Ok(())
}

#[cfg(not(target_os = "windows"))]
pub fn shutdown() {}
