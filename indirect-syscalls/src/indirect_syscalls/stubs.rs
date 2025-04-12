use std::ffi::c_void;
use winapi::shared::ntdef::{LARGE_INTEGER, NTSTATUS};
use winapi::um::winnt::HANDLE;
use crate::utils::OBJECTATTRIBUTES;

extern "system" {
    pub fn NtCreateSection(
        section_handle: *mut HANDLE,
        desired_access: u32,
        object_attributes: *mut OBJECTATTRIBUTES,
        maximum_size: *mut LARGE_INTEGER,
        page_attributes: u32,
        section_attributes: u32,
        file_handle: HANDLE,
    ) -> NTSTATUS;

    pub fn NtMapViewOfSection(
        section_handle: HANDLE,
        process_handle: HANDLE,
        base_address: *mut *mut c_void,
        zero_bits: usize,
        commit_size: usize,
        section_offset: *mut LARGE_INTEGER,
        view_size: *mut usize,
        inherit_disposition: u32,
        allocation_type: u32,
        win_protect: u32,
    ) -> NTSTATUS;

    pub fn NtCreateThreadEx(
        thread_handle: *mut HANDLE,
        desired_access: u32,
        object_attributes: *mut c_void,
        process_handle: HANDLE,
        start_address: *mut c_void,
        parameter: *mut c_void,
        create_flags: u32,
        zero_bits: usize,
        stack_size: usize,
        maximum_stack_size: usize,
        attribute_list: *mut c_void,
    ) -> NTSTATUS;

    pub fn NtDelayExecution(
        alertable: u8, // BOOLEAN é só um alias pra `u8`
        delay_interval: *const LARGE_INTEGER,
    ) -> NTSTATUS;
}
