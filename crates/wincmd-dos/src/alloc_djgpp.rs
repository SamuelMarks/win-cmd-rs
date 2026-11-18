//! Alignment-safe `#[global_allocator]` wrapper (`DjgppAllocator`) over DJGPP `malloc`/`realloc`/`free`.
//!
//! DJGPP's `malloc` guarantees 8-byte alignment on 32-bit x86. Rust types with `#[repr(align(16))]`
//! or SIMD/hash tables may request alignments `> 8`. `DjgppAllocator`:
//! - Routes `layout.align() <= 8` directly to `raw_malloc` / `raw_realloc` / `raw_free` with zero overhead.
//! - Over-allocates `size + align + sizeof(usize)` for `layout.align() > 8` using saturating/checked
//!   arithmetic, storing the original base pointer immediately below the aligned payload address and
//!   returning `core::ptr::null_mut()` on address-space wrap or DPMI out-of-memory—never panicking or invoking UB.

use core::alloc::{GlobalAlloc, Layout};
use core::ptr;

use crate::ffi::DjgppRawMemoryApi;

/// Native alignment guaranteed by DJGPP `libc` `malloc` on 32-bit x86 (`8` bytes).
pub const DJGPP_NATIVE_MALLOC_ALIGN: usize = 8;

/// Alignment-preserving [`GlobalAlloc`] adapter parameterized over [`DjgppRawMemoryApi`].
#[derive(Debug, Clone, Copy, Default)]
pub struct DjgppAllocator<M: DjgppRawMemoryApi> {
    /// Underlying raw `malloc`/`realloc`/`free` provider.
    pub mem: M,
}

impl<M: DjgppRawMemoryApi> DjgppAllocator<M> {
    /// Constructs a new [`DjgppAllocator`] wrapping `mem`.
    ///
    /// # Arguments
    /// * `mem` - [`DjgppRawMemoryApi`] implementation.
    ///
    /// # Returns
    /// Initialized [`DjgppAllocator`].
    #[must_use]
    pub const fn new(mem: M) -> Self {
        Self { mem }
    }

    /// Computes total over-allocation bytes needed to satisfy `align > 8` plus a `usize` base-pointer header.
    ///
    /// # Arguments
    /// * `size` - Payload byte size (`>= 1`).
    /// * `align` - Power-of-two alignment (`> 8`).
    ///
    /// # Returns
    /// `Some(total_bytes)` or `None` on `usize` overflow.
    #[must_use]
    pub const fn checked_overalloc_total(size: usize, align: usize) -> Option<usize> {
        match size.checked_add(align) {
            Some(s1) => s1.checked_add(size_of::<usize>()),
            None => None,
        }
    }
}

/// Global heap allocation implementation delegating to [`DjgppRawMemoryApi`].
// SAFETY: `DjgppAllocator` upholds all `GlobalAlloc` alignment, non-overlapping, and null-on-OOM invariants.
unsafe impl<M: DjgppRawMemoryApi> GlobalAlloc for DjgppAllocator<M> {
    /// Allocates memory matching `layout` on the DPMI heap.
    ///
    /// # Arguments
    /// * `layout` - Requested non-zero allocation size and alignment.
    ///
    /// # Returns
    /// Aligned payload pointer, or `core::ptr::null_mut()` on OOM or address wrap.
    ///
    /// # Safety
    /// `layout` must have non-zero size per [`GlobalAlloc::alloc`].
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let size = layout.size().max(1);
        let align = layout.align();
        if align <= DJGPP_NATIVE_MALLOC_ALIGN {
            return self.mem.raw_malloc(size);
        }

        // `core::alloc::Layout` guarantees `size.next_multiple_of(align) <= isize::MAX`,
        // so `size + align + size_of::<usize>()` never overflows `usize`.
        let total = size
            .saturating_add(align)
            .saturating_add(size_of::<usize>());
        let raw_base = self.mem.raw_malloc(total);
        if raw_base.is_null() {
            return ptr::null_mut();
        }

        let base_addr = raw_base.expose_provenance();
        let Some(after_hdr) = base_addr.checked_add(size_of::<usize>()) else {
            // SAFETY: `raw_base` was just returned by `raw_malloc` and has not been exposed to callers.
            unsafe { self.mem.raw_free(raw_base) };
            return ptr::null_mut();
        };
        let mask = align.wrapping_sub(1);
        let Some(padded) = after_hdr.checked_add(mask) else {
            // SAFETY: `raw_base` was just returned by `raw_malloc` and has not been exposed to callers.
            unsafe { self.mem.raw_free(raw_base) };
            return ptr::null_mut();
        };
        let aligned_addr = padded & !mask;
        let header_addr = aligned_addr.wrapping_sub(size_of::<usize>());
        let header_ptr = ptr::with_exposed_provenance_mut::<usize>(header_addr);
        // SAFETY: `header_addr >= base_addr`, `aligned_addr + size <= base_addr + total`,
        // and `aligned_addr` is a multiple of `align >= 16` (hence `usize`-aligned).
        unsafe {
            ptr::write(header_ptr, base_addr);
        }
        ptr::with_exposed_provenance_mut(aligned_addr)
    }

    /// Deallocates a block previously allocated by [`Self::alloc`] or [`Self::realloc`].
    ///
    /// # Arguments
    /// * `ptr` - Payload pointer to release.
    /// * `layout` - Exact [`Layout`] used to allocate `ptr`.
    ///
    /// # Safety
    /// `ptr` must have been allocated by this allocator with matching `layout`.
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if ptr.is_null() {
            return;
        }
        if layout.align() <= DJGPP_NATIVE_MALLOC_ALIGN {
            // SAFETY: `ptr` was allocated directly by `raw_malloc` / `raw_realloc` with `align <= 8`.
            unsafe { self.mem.raw_free(ptr) };
            return;
        }

        let aligned_addr = ptr.expose_provenance();
        let header_addr = aligned_addr.wrapping_sub(size_of::<usize>());
        let header_ptr = ptr::with_exposed_provenance::<usize>(header_addr);
        // SAFETY: `alloc` wrote the original `raw_base` address at `aligned_addr - sizeof(usize)`.
        let base_addr = unsafe { ptr::read(header_ptr) };
        let raw_base = ptr::with_exposed_provenance_mut::<u8>(base_addr);
        // SAFETY: `raw_base` is the exact pointer originally returned by `raw_malloc`.
        unsafe { self.mem.raw_free(raw_base) };
    }

    /// Resizes a block previously allocated with `layout` to `new_size` bytes.
    ///
    /// # Arguments
    /// * `ptr` - Existing payload pointer.
    /// * `layout` - Current allocation [`Layout`].
    /// * `new_size` - New requested byte size (`> 0`).
    ///
    /// # Returns
    /// Resized aligned pointer, or `core::ptr::null_mut()` on OOM/overflow (preserving `ptr`).
    ///
    /// # Safety
    /// `ptr` must have been allocated by this allocator with `layout`, and `new_size` must be valid for `layout.align()`.
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        if layout.align() <= DJGPP_NATIVE_MALLOC_ALIGN {
            // SAFETY: `ptr` was allocated directly via `raw_malloc`/`raw_realloc` (`align <= 8`).
            return unsafe { self.mem.raw_realloc(ptr, new_size.max(1)) };
        }

        let Ok(new_layout) = Layout::from_size_align(new_size.max(1), layout.align()) else {
            return ptr::null_mut();
        };
        // SAFETY: `new_layout` is non-zero and validated by `Layout::from_size_align`.
        let new_ptr = unsafe { self.alloc(new_layout) };
        if new_ptr.is_null() {
            return ptr::null_mut();
        }
        let copy_len = layout.size().min(new_size);
        // SAFETY: `ptr` is valid for `layout.size()` bytes, `new_ptr` is valid for `new_size.max(1)`
        // bytes, and the two allocations do not overlap.
        unsafe {
            ptr::copy_nonoverlapping(ptr, new_ptr, copy_len);
            self.dealloc(ptr, layout);
        }
        new_ptr
    }
}

#[cfg(not(feature = "host-sim"))]
/// Global DPMI heap allocator for `WINCMD.EXE` and `WINCHECK.EXE` on 32-bit MS-DOS.
#[global_allocator]
static GLOBAL_DOS_ALLOCATOR: DjgppAllocator<crate::ffi::djgpp_c::DjgppLibcMemory> =
    DjgppAllocator::new(crate::ffi::djgpp_c::DjgppLibcMemory);
