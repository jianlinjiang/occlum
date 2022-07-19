use aligned::{Aligned, A4096};
use core::ptr;
use serde::{Deserialize, Serialize};
use sgx_tcrypto::*;
use sgx_trts::libc::memcpy;
use sgx_types::*;
use std::convert::TryInto;
const SGX_MAGE_SEC_SIZE: usize = 4096;
const SGX_MAGE_ENTRY_SIZE: usize = 64;

const HANDLE_HASH_OFFSET: isize = 168;
const HANDLE_SIZE_OFFSET: isize = 152;
pub const SHA256_DIGEST_SIZE: usize = 32;

const SIZE_NAMED_VALUE: usize = 8;
const DATA_BLOCK_SIZE: usize = 64;
const SE_PAGE_SIZE: usize = 0x1000;

// This value will be modified during occlum build
#[used]
#[link_section = ".sgx_mage"]
static SGX_MAGE_BUF: Aligned<A4096, [u8; SGX_MAGE_SEC_SIZE]> = Aligned([0; SGX_MAGE_SEC_SIZE]);

#[derive(Serialize, Deserialize, Debug)]
struct SgxMageEntry {
    pub size: u64,
    pub offset: u64,
    pub isv_svn: u64,
    pub isv_prodid: u64,
    pub digest: [u8; 32],
}

pub fn sgx_mage_derive_measurement_by_isvinfo(
    isv_svn: u64,
    isv_prodid: u64,
) -> SgxResult<sgx_sha256_hash_t> {
    let mage_buf = std::hint::black_box(&SGX_MAGE_BUF);
    let entry_size_buf = &mage_buf[0..8];
    let mage_entry_num = usize::from_le_bytes(entry_size_buf.try_into().unwrap());
    let found: bool = false;
    for i in 0..mage_entry_num {
        let entry_data = &mage_buf[i * SGX_MAGE_ENTRY_SIZE + 8..(i + 1) * SGX_MAGE_ENTRY_SIZE + 8];
        let mage_isv_svn = u64::from_le_bytes(entry_data[16..24].try_into().unwrap());
        let mage_isv_prodid = u64::from_le_bytes(entry_data[24..32].try_into().unwrap());
        if mage_isv_svn == isv_svn && mage_isv_prodid == isv_prodid {
            return sgx_mage_derive_measurement(i);
        }
    }
    return Err(sgx_status_t::SGX_ERROR_INVALID_PARAMETER);
}

pub fn sgx_mage_derive_measurement(mage_idx: usize) -> SgxResult<sgx_sha256_hash_t> {
    let mage_buf = std::hint::black_box(&SGX_MAGE_BUF);
    let entry_size_buf = &mage_buf[0..8];
    let mage_entry_num = usize::from_le_bytes(entry_size_buf.try_into().unwrap());
    if (mage_idx + 1) * SGX_MAGE_ENTRY_SIZE >= SGX_MAGE_SEC_SIZE || mage_idx >= mage_entry_num {
        error!("mage_idx {} is out of range", mage_idx);
        return Err(sgx_status_t::SGX_ERROR_INVALID_PARAMETER);
    }

    let entry_data =
        &mage_buf[mage_idx * SGX_MAGE_ENTRY_SIZE + 8..(mage_idx + 1) * SGX_MAGE_ENTRY_SIZE + 8];

    let size = u64::from_le_bytes(entry_data[0..8].try_into().unwrap());
    if size == 0 {
        error!("invalid sgx mage entry, size is zero");
        return Err(sgx_status_t::SGX_ERROR_INVALID_PARAMETER);
    }

    let offset = u64::from_le_bytes(entry_data[8..16].try_into().unwrap());

    let mut digest = [0u8; 32];
    digest.copy_from_slice(&entry_data[32..]);

    let mut sha_handle: sgx_sha_state_handle_t = ptr::null_mut() as sgx_sha_state_handle_t;

    let mut ret = unsafe { sgx_sha256_init(&mut sha_handle as *mut sgx_sha_state_handle_t) };
    match ret {
        sgx_status_t::SGX_SUCCESS => {}
        _ => {
            error!("sgx_sha256_init error, {:02x?}", ret);
            return Err(ret);
        }
    }

    // init sha handle
    unsafe {
        let digest_ptr = &digest as *const u8 as *const c_void;
        let size_ptr = &size as *const u64 as *const c_void;
        memcpy(
            (&mut sha_handle).wrapping_offset(HANDLE_HASH_OFFSET),
            digest_ptr,
            SHA256_DIGEST_SIZE,
        );
        memcpy(
            (&mut sha_handle).wrapping_offset(HANDLE_SIZE_OFFSET),
            size_ptr,
            8,
        );
    }

    let mut source = &SGX_MAGE_BUF[0] as *const u8;
    let mage_sec_end_addr = source.wrapping_offset(SGX_MAGE_SEC_SIZE as isize);

    let mut page_offset: u64 = offset;
    loop {
        if source >= mage_sec_end_addr {
            break;
        }
        // "EADD\0\0\0\0"
        let eadd_val: [u8; SIZE_NAMED_VALUE] = [69, 65, 68, 68, 0, 0, 0, 0];
        let mut sinfo: [u8; 64] = [0u8; 64];
        sinfo[0] = 0x01;
        sinfo[1] = 0x02;

        let mut data_block = [0u8; DATA_BLOCK_SIZE];
        // eadd_val
        data_block[0..8].copy_from_slice(&eadd_val[..]);
        // page_offset
        data_block[8..16].copy_from_slice(&page_offset.to_le_bytes()[..]);
        // sinfo
        data_block[16..].copy_from_slice(&sinfo[0..48]);

        let mut ret = unsafe {
            sgx_sha256_update(
                (&data_block).as_ptr() as *const u8,
                DATA_BLOCK_SIZE as u32,
                sha_handle,
            )
        };

        match ret {
            sgx_status_t::SGX_SUCCESS => {}
            _ => {
                unsafe { sgx_sha256_close(sha_handle) };
                error!("sgx_sha256_update error{:02x?}", ret);
                return Err(ret);
            }
        }

        // "EEXTEND"
        let eextend_val: [u8; SIZE_NAMED_VALUE] = [69, 69, 88, 84, 69, 78, 68, 0];
        const EEXTEND_TIME: usize = 4;
        for i in (0..SE_PAGE_SIZE).step_by(DATA_BLOCK_SIZE * EEXTEND_TIME) {
            data_block.iter_mut().for_each(|m| *m = 0);
            // EEXTEND
            data_block[0..8].copy_from_slice(&eextend_val[..]);
            // page_offset
            data_block[8..16].copy_from_slice(&page_offset.to_le_bytes()[..]);
            ret = unsafe {
                sgx_sha256_update(&data_block as *const u8, DATA_BLOCK_SIZE as u32, sha_handle)
            };
            match ret {
                sgx_status_t::SGX_SUCCESS => {}
                _ => {
                    unsafe { sgx_sha256_close(sha_handle) };
                    error!("sgx_sha256_update error {:02x?}", ret);
                    return Err(ret);
                }
            }

            for j in 0..EEXTEND_TIME {
                unsafe {
                    memcpy(
                        &mut data_block as *mut u8 as *mut c_void,
                        source as *const c_void,
                        DATA_BLOCK_SIZE,
                    );
                }

                ret = unsafe {
                    sgx_sha256_update(
                        (&data_block).as_ptr() as *const u8,
                        DATA_BLOCK_SIZE as u32,
                        sha_handle,
                    )
                };

                match ret {
                    sgx_status_t::SGX_SUCCESS => {}
                    _ => {
                        unsafe { sgx_sha256_close(sha_handle) };
                        error!("sgx_sha256_update error {:02x?}", ret);
                        return Err(ret);
                    }
                }
                source = source.wrapping_offset(DATA_BLOCK_SIZE as isize);
                page_offset += DATA_BLOCK_SIZE as u64;
            }
        }
    }

    let mut hash = sgx_sha256_hash_t::default();
    ret = unsafe { sgx_sha256_get_hash(sha_handle, &mut hash as *mut sgx_sha256_hash_t) };
    match ret {
        sgx_status_t::SGX_SUCCESS => {}
        _ => {
            unsafe { sgx_sha256_close(sha_handle) };
            error!("sgx_sha256_get_hash error{:02x?}", ret);
            return Err(ret);
        }
    }
    unsafe { sgx_sha256_close(sha_handle) };
    Ok(hash)
}
