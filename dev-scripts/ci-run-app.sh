#!/bin/sh
# Run an app under touchHLE for a bounded amount of time, for CI.
#
# touchHLE runs apps indefinitely, which isn't useful in CI, so this launches
# the emulator in the background, waits a fixed number of seconds, and then
# stops it. Being killed after reaching that time limit is the normal, expected
# outcome and is reported as success; only the app exiting on its own with a
# non-zero status is treated as a failure.
#
# This is written for POSIX sh so it works the same on Linux, macOS and on
# Windows under the Git Bash that GitHub Actions provides.
#
# Usage: ci-run-app.sh <binary> <run_seconds> <app_path> [extra touchHLE args...]
set -u

BINARY="$1"
RUN_SECONDS="$2"
APP_PATH="$3"
shift 3

echo "Running '$APP_PATH' under '$BINARY' for up to ${RUN_SECONDS}s..."

# Launch in the background so we can stop it ourselves after the time limit.
# Output goes straight to the log file (not via a pipe) so that $! is the
# emulator's PID rather than some intermediate process's. We tail it as it runs
# so the output is also visible in the CI log.
: > run.log
"$BINARY" "$APP_PATH" --no-error-popup "$@" > run.log 2>&1 &
APP_PID=$!
tail -f run.log &
TAIL_PID=$!

# Poll once a second so we can notice an early exit instead of always waiting
# the full duration. On the way, photograph the screen: a log can say the
# render loop is alive and every frame can still be black, and only the pixels
# settle that.
# An app can be waiting for a tap, and a log full of a healthy render loop
# looks exactly the same as one that is stuck. TAP_SECONDS is a comma-separated
# list of elapsed times at which to click, and TAP_XY the point to click at,
# defaulting to the middle of the screen.
tap_pending="${TAP_SECONDS:-}"
tap_point="${TAP_XY:-}"
if [ -z "$tap_point" ] && [ -n "$tap_pending" ]; then
    tap_point=$(xdotool getdisplaygeometry 2>/dev/null \
        | awk '{ printf "%d,%d", $1 / 2, $2 / 2 }')
    tap_point="${tap_point:-640,512}"
fi

# Click once at TAP_XY. Separated out because a tap that lands while the app is
# mid-frame is worth repeating, and because a missing xdotool should say so
# rather than silently do nothing.
tap_screen() {
    if ! command -v xdotool >/dev/null 2>&1; then
        echo "no xdotool, cannot tap"
        return
    fi
    tap_x=${tap_point%,*}
    tap_y=${tap_point#*,}
    echo "===== tapping at (${tap_x}, ${tap_y}) after ${elapsed}s ====="
    xdotool mousemove "$tap_x" "$tap_y" 2>/dev/null || true
    # Press and release with a gap: a recognizer that measures how long the
    # touch lasted sees nothing in a zero-length one.
    xdotool mousedown 1 2>/dev/null || true
    sleep 1
    xdotool mouseup 1 2>/dev/null || true
}

elapsed=0
next_shot=0
shot=0
while [ "$elapsed" -lt "$RUN_SECONDS" ]; do
    if ! kill -0 "$APP_PID" 2>/dev/null; then
        break
    fi
    if [ -n "$tap_pending" ] && [ -n "${DISPLAY:-}" ]; then
        due=${tap_pending%%,*}
        if [ "$elapsed" -ge "$due" ]; then
            tap_screen
            import -window root -silent "screenshot-${elapsed}s-after-tap.png" 2>/dev/null || true
            case "$tap_pending" in
                *,*) tap_pending=${tap_pending#*,} ;;
                *) tap_pending="" ;;
            esac
        fi
    fi
    if [ -n "${DISPLAY:-}" ] && [ "$elapsed" -ge "$next_shot" ] && command -v import >/dev/null 2>&1; then
        shot=$((shot + 1))
        import -window root -silent "screenshot-${elapsed}s.png" 2>/dev/null || true
        # Early, then spread out: an app draws its first frame long before its
        # last, and both are worth having.
        next_shot=$((elapsed + 10 + shot * 10))
    fi
    sleep 1
    elapsed=$((elapsed + 1))
done

# One last look, before the app is stopped rather than after.
if [ -n "${DISPLAY:-}" ] && command -v import >/dev/null 2>&1; then
    import -window root -silent "screenshot-final.png" 2>/dev/null || true
fi

if kill -0 "$APP_PID" 2>/dev/null; then
    echo "Reached the ${RUN_SECONDS}s time limit; stopping the app."
    kill "$APP_PID" 2>/dev/null || true
    sleep 2
    kill -9 "$APP_PID" 2>/dev/null || true
    kill "$TAIL_PID" 2>/dev/null || true
    echo "App ran successfully (still running when stopped)."
    exit 0
fi

# The app exited on its own; surface its real exit status.
wait "$APP_PID"
status=$?
kill "$TAIL_PID" 2>/dev/null || true
echo "touchHLE exited on its own with status ${status}."
exit "$status"
