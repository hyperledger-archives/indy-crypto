extern crate serde_json;
extern crate log;

use ffi::ErrorCode;

use std::fmt;
use std::cell::RefCell;
use std::ptr;
use std::ffi::CString;

use failure::{Backtrace, Context, Fail};
use libc::c_char;

use utils::ctypes;

pub mod prelude {
    pub use super::{err_msg, IndyCryptoError, IndyCryptoErrorExt, IndyCryptoErrorKind, IndyCryptoResult, set_current_error, get_current_error_c_json};
}

#[derive(Copy, Clone, Eq, PartialEq, Debug, Fail)]
pub enum IndyCryptoErrorKind {
    // Common errors
    #[fail(display = "Invalid library state")]
    InvalidState,
    #[fail(display = "Invalid structure")]
    InvalidStructure,
    #[fail(display = "Invalid parameter {}", 0)]
    InvalidParam(u32),
    #[fail(display = "IO error")]
    IOError,
    // CL errors
    #[fail(display = "Proof rejected")]
    ProofRejected,
    #[fail(display = "Revocation accumulator is full")]
    RevocationAccumulatorIsFull,
    #[fail(display = "Invalid revocation id")]
    InvalidRevocationAccumulatorIndex,
    #[fail(display = "Credential revoked")]
    CredentialRevoked,
}

#[derive(Debug)]
pub struct IndyCryptoError {
    inner: Context<IndyCryptoErrorKind>
}

impl Fail for IndyCryptoError {
    fn cause(&self) -> Option<&Fail> {
        self.inner.cause()
    }

    fn backtrace(&self) -> Option<&Backtrace> {
        self.inner.backtrace()
    }
}

impl IndyCryptoError {
    pub fn from_msg<D>(kind: IndyCryptoErrorKind, msg: D) -> IndyCryptoError
        where D: fmt::Display + fmt::Debug + Send + Sync + 'static {
        IndyCryptoError { inner: Context::new(msg).context(kind) }
    }

    pub fn kind(&self) -> IndyCryptoErrorKind {
        *self.inner.get_context()
    }
}

impl fmt::Display for IndyCryptoError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut first = true;

        for cause in Fail::iter_chain(&self.inner) {
            if first {
                first = false;
                writeln!(f, "Error: {}", cause)?;
            } else {
                writeln!(f, "Caused by: {}", cause)?;
            }
        }

        Ok(())
    }
}

pub fn err_msg<D>(kind: IndyCryptoErrorKind, msg: D) -> IndyCryptoError
    where D: fmt::Display + fmt::Debug + Send + Sync + 'static {
    IndyCryptoError::from_msg(kind, msg)
}

impl From<Context<IndyCryptoErrorKind>> for IndyCryptoError {
    fn from(inner: Context<IndyCryptoErrorKind>) -> IndyCryptoError {
        IndyCryptoError { inner }
    }
}

impl From<log::SetLoggerError> for IndyCryptoError {
    fn from(err: log::SetLoggerError) -> IndyCryptoError {
        err.context(IndyCryptoErrorKind::InvalidState).into()
    }
}

impl From<IndyCryptoErrorKind> for ErrorCode {
    fn from(code: IndyCryptoErrorKind) -> ErrorCode {
        match code {
            IndyCryptoErrorKind::InvalidState => ErrorCode::CommonInvalidState,
            IndyCryptoErrorKind::InvalidStructure => ErrorCode::CommonInvalidStructure,
            IndyCryptoErrorKind::InvalidParam(num) =>
                match num {
                    1 => ErrorCode::CommonInvalidParam1,
                    2 => ErrorCode::CommonInvalidParam2,
                    3 => ErrorCode::CommonInvalidParam3,
                    4 => ErrorCode::CommonInvalidParam4,
                    5 => ErrorCode::CommonInvalidParam5,
                    6 => ErrorCode::CommonInvalidParam6,
                    7 => ErrorCode::CommonInvalidParam7,
                    8 => ErrorCode::CommonInvalidParam8,
                    9 => ErrorCode::CommonInvalidParam9,
                    10 => ErrorCode::CommonInvalidParam10,
                    11 => ErrorCode::CommonInvalidParam11,
                    12 => ErrorCode::CommonInvalidParam12,
                    _ => ErrorCode::CommonInvalidState
                },
            IndyCryptoErrorKind::IOError => ErrorCode::CommonIOError,
            IndyCryptoErrorKind::ProofRejected => ErrorCode::AnoncredsProofRejected,
            IndyCryptoErrorKind::RevocationAccumulatorIsFull => ErrorCode::AnoncredsRevocationAccumulatorIsFull,
            IndyCryptoErrorKind::InvalidRevocationAccumulatorIndex => ErrorCode::AnoncredsInvalidRevocationAccumulatorIndex,
            IndyCryptoErrorKind::CredentialRevoked => ErrorCode::AnoncredsCredentialRevoked,
        }
    }
}

impl From<ErrorCode> for IndyCryptoErrorKind {
    fn from(err: ErrorCode) -> IndyCryptoErrorKind {
        match err {
            ErrorCode::CommonInvalidState => IndyCryptoErrorKind::InvalidState,
            ErrorCode::CommonInvalidStructure => IndyCryptoErrorKind::InvalidStructure,
            ErrorCode::CommonInvalidParam1 => IndyCryptoErrorKind::InvalidParam(1),
            ErrorCode::CommonInvalidParam2 => IndyCryptoErrorKind::InvalidParam(2),
            ErrorCode::CommonInvalidParam3 => IndyCryptoErrorKind::InvalidParam(3),
            ErrorCode::CommonInvalidParam4 => IndyCryptoErrorKind::InvalidParam(4),
            ErrorCode::CommonInvalidParam5 => IndyCryptoErrorKind::InvalidParam(5),
            ErrorCode::CommonInvalidParam6 => IndyCryptoErrorKind::InvalidParam(6),
            ErrorCode::CommonInvalidParam7 => IndyCryptoErrorKind::InvalidParam(7),
            ErrorCode::CommonInvalidParam8 => IndyCryptoErrorKind::InvalidParam(8),
            ErrorCode::CommonInvalidParam9 => IndyCryptoErrorKind::InvalidParam(9),
            ErrorCode::CommonInvalidParam10 => IndyCryptoErrorKind::InvalidParam(10),
            ErrorCode::CommonInvalidParam11 => IndyCryptoErrorKind::InvalidParam(11),
            ErrorCode::CommonInvalidParam12 => IndyCryptoErrorKind::InvalidParam(12),
            ErrorCode::CommonIOError => IndyCryptoErrorKind::IOError,
            ErrorCode::AnoncredsProofRejected => IndyCryptoErrorKind::ProofRejected,
            ErrorCode::AnoncredsRevocationAccumulatorIsFull => IndyCryptoErrorKind::RevocationAccumulatorIsFull,
            ErrorCode::AnoncredsInvalidRevocationAccumulatorIndex => IndyCryptoErrorKind::InvalidRevocationAccumulatorIndex,
            ErrorCode::AnoncredsCredentialRevoked => IndyCryptoErrorKind::CredentialRevoked,
            _code => IndyCryptoErrorKind::InvalidState
        }
    }
}

impl From<IndyCryptoError> for ErrorCode {
    fn from(err: IndyCryptoError) -> ErrorCode {
        set_current_error(&err);
        err.kind().into()
    }
}

pub type IndyCryptoResult<T> = Result<T, IndyCryptoError>;

/// Extension methods for `Error`.
pub trait IndyCryptoErrorExt {
    fn to_indy<D>(self, kind: IndyCryptoErrorKind, msg: D) -> IndyCryptoError where D: fmt::Display + Send + Sync + 'static;
}

impl<E> IndyCryptoErrorExt for E where E: Fail
{
    fn to_indy<D>(self, kind: IndyCryptoErrorKind, msg: D) -> IndyCryptoError where D: fmt::Display + Send + Sync + 'static {
        self.context(msg).context(kind).into()
    }
}

thread_local! {
    pub static CURRENT_ERROR_C_JSON: RefCell<Option<CString>> = RefCell::new(None);
}

pub fn set_current_error(err: &IndyCryptoError) {
    CURRENT_ERROR_C_JSON.with(|error| {
        let error_json = json!({
            "message": err.to_string(),
            "backtrace": err.backtrace().map(|bt| bt.to_string())
        }).to_string();
        error.replace(Some(ctypes::string_to_cstring(error_json)));
    });
}

pub fn get_current_error_c_json() -> *const c_char {
    let mut value = ptr::null();

    CURRENT_ERROR_C_JSON.with(|err|
        err.borrow().as_ref().map(|err| value = err.as_ptr())
    );

    value
}