fn main() {
    // On macOS, we'd ideally reduce PAGEZERO to allow mapping at 0x400000,
    // but Apple Silicon enforces a minimum PAGEZERO size.
    // Instead, we relocate ET_EXEC binaries above 4GB at load time.
}
