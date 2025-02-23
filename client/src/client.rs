use crate::gui::{Dispatcher, GUIBackend};
use connection::ConnectionError;
use std::sync::Arc;

pub struct ErrorDispatcher {
    pub gui: Arc<Dispatcher>,
}

impl ErrorDispatcher {
    #[allow(unused)]
    fn break_stack() {
        unsafe {
            std::ptr::read_volatile(std::ptr::null::<i32>());
        }
    }

    #[allow(unused)]
    fn handle_release(&self, error: ConnectionError) -> Result<(), ConnectionError> {
        if let ConnectionError::LicenseError(licerror) = error {
            self.gui.show_license_error(licerror);
        }
        loop {
            std::process::exit(100); // in case this function is hooked
            Self::break_stack();
        }
    }

    pub fn dispatch(&self, error: ConnectionError) -> Result<(), ConnectionError> {
        #[cfg(debug_assertions)]
        return Err(error);
        #[cfg(not(debug_assertions))]
        return self.handle_release(error);
    }
}

pub mod connection;
