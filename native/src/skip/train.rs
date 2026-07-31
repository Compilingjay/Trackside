//! Training cut-in skip + Photo Studio guard.

#![allow(dead_code)]

use std::ffi::c_void;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::OnceLock;

use crate::hooks::{in_heaven, ReentryGuard};
use crate::skip::{call_orig, is_enabled, rr_log, Invokable, TRAIN_SKIPS};

// Invokable (set in install).
pub(crate) static SKIP_RUNTIME: OnceLock<Invokable> = OnceLock::new(); // training

crate::skip_hook_slot!(TR_START, D_START);
crate::skip_hook_slot!(TR_PLAY, D_PLAY);
crate::skip_hook_slot!(TR_MAIN, D_MAIN);
crate::skip_hook_slot!(TR_PHOTO_PLAY, D_PHOTO_PLAY); // PhotoStudioCuttController.PlayCutIn
crate::skip_hook_slot!(TR_PHOTO_ASYNC, D_PHOTO_ASYNC); // .PlayCutInAsync
crate::skip_hook_slot!(TR_PHOTO_END, D_PHOTO_END); // .OnEndCutIn
// True while the Photo Studio is replaying a cut. It reuses SingleModeTrainingCutInHelper
// (PhotoStudioCuttController._cutInHelperList@0x18), so those helpers fire our OnPlayCutIn
// hook — without this flag the training-skip would swallow the photo-studio animation too.
static PHOTO_CUT_ACTIVE: AtomicBool = AtomicBool::new(false);

// ── TRAINING: run SkipRuntime after a cut-in start. ─────────────────────────
fn do_training_skip(this: *mut c_void, src: &str) {
    // DEBUG-GATED TRACE. Every training cut-in that reaches one of our three hooks logs here, so a
    // cut-in that skips nothing AND produces no line proves the controller is not hooked at all —
    // which no bail message can tell you apart from a stuck guard. Costs nothing with debug off.
    crate::tools::debug(&format!("[train] cut-in via {src}"));
    if !is_enabled() {
        return;
    }
    // DIAGNOSTIC: log the bail reason. If the rainbow "stops skipping" mid-run, this shows whether it is
    // a stuck re-entry guard (in_heaven) — the prime suspect for the "worked then nothing skips" bug.
    if in_heaven() {
        rr_log("[train] BAILED: in_heaven guard held (stuck? watchdog clears it next frame)");
        return;
    }
    if this.is_null() {
        return;
    }
    if PHOTO_CUT_ACTIVE.load(Ordering::Relaxed) {
        rr_log("[train] bailed: photo-studio cut active");
        return; // Photo Studio cut recreation — must play normally, never skip it
    }
    if let Some(sr) = SKIP_RUNTIME.get() {
        if sr.ok() {
            let _g = ReentryGuard::enter();
            unsafe { sr.call_void(this) };
            TRAIN_SKIPS.fetch_add(1, Ordering::Relaxed);
            rr_log(&format!("[train] SkipRuntime() fired (via {src})"));
        }
    }
}
pub(crate) unsafe extern "C" fn on_start_cutin(this: *mut c_void, m: *mut c_void) {
    call_orig(&TR_START, this, m);
    do_training_skip(this, "OnStartCutIn");
}
pub(crate) unsafe extern "C" fn on_play_cutin(this: *mut c_void, m: *mut c_void) {
    call_orig(&TR_PLAY, this, m);
    do_training_skip(this, "OnPlayCutIn");
}
pub(crate) unsafe extern "C" fn on_play_main_cutin(this: *mut c_void, m: *mut c_void) {
    call_orig(&TR_MAIN, this, m);
    do_training_skip(this, "OnPlayMainCutIn");
}

// ── PHOTO STUDIO: pause the training-skip while a recreated cut plays ────────
// PhotoStudioCuttController replays training cut-ins through the SAME
// SingleModeTrainingCutInHelper instances (its _cutInHelperList@0x18), so those
// helpers fire on_play_cutin above and SkipRuntime() would skip the photo cut too.
// We flag the play window (both the sync PlayCutIn and the async coroutine entry,
// whichever the view controller uses) and clear it on OnEndCutIn.
type Photo3Fn = unsafe extern "C" fn(*mut c_void, *mut c_void, *mut c_void, *mut c_void, *mut c_void);
type Photo1RetFn = unsafe extern "C" fn(*mut c_void, *mut c_void, *mut c_void) -> *mut c_void;

/// True only if we can both call the original AND will get the end callback that clears the guard.
///
/// ORDERING BUG this fixes: the guard used to be set BEFORE checking the trampoline. If the play
/// hook was missing we set the flag and never called through, so `OnEndCutIn` never fired and
/// `PHOTO_CUT_ACTIVE` stayed true for the rest of the session — silently disabling EVERY training
/// skip. Same if the end hook itself failed to install. Both are the "worked, then nothing skips"
/// shape, so the guard is now only raised when there is a clear path to lowering it.
fn photo_guard_safe(play_trampoline: usize) -> bool {
    play_trampoline != 0 && TR_PHOTO_END.load(Ordering::Relaxed) != 0
}

pub(crate) unsafe extern "C" fn on_photo_play_cut(
    this: *mut c_void,
    model: *mut c_void,
    on_end: *mut c_void,
    on_clean: *mut c_void,
    m: *mut c_void,
) {
    let t = TR_PHOTO_PLAY.load(Ordering::Relaxed);
    if !photo_guard_safe(t) {
        crate::tools::debug("[photo] PlayCutIn: no callable original or no end hook — guard NOT raised");
        if t != 0 {
            let f: Photo3Fn = std::mem::transmute(t);
            f(this, model, on_end, on_clean, m);
        }
        return;
    }
    PHOTO_CUT_ACTIVE.store(true, Ordering::Relaxed);
    rr_log("[photo] cut start -> training-skip paused");
    let f: Photo3Fn = std::mem::transmute(t);
    f(this, model, on_end, on_clean, m);
}
pub(crate) unsafe extern "C" fn on_photo_play_cut_async(
    this: *mut c_void,
    model: *mut c_void,
    m: *mut c_void,
) -> *mut c_void {
    let t = TR_PHOTO_ASYNC.load(Ordering::Relaxed);
    if !photo_guard_safe(t) {
        crate::tools::debug("[photo] PlayCutInAsync: no callable original or no end hook — guard NOT raised");
        if t != 0 {
            let f: Photo1RetFn = std::mem::transmute(t);
            return f(this, model, m);
        }
        return std::ptr::null_mut();
    }
    PHOTO_CUT_ACTIVE.store(true, Ordering::Relaxed);
    let f: Photo1RetFn = std::mem::transmute(t);
    f(this, model, m)
}
pub(crate) unsafe extern "C" fn on_photo_end_cut(this: *mut c_void, m: *mut c_void) {
    call_orig(&TR_PHOTO_END, this, m);
    PHOTO_CUT_ACTIVE.store(false, Ordering::Relaxed);
    rr_log("[photo] cut end -> training-skip resumed");
}
