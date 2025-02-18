use std::{ops::Deref, sync::Arc};

use chrono::{DateTime, Utc};
use colored::Colorize;
use proto::software::v1::{info_response, ChronoExt, LicenseError};

const GUI_DELAY: std::time::Duration = std::time::Duration::from_secs(10);

pub trait GUIBackend: Send + 'static + Sync {
    fn prompt_license(&self) -> String;
    fn show_license_details(&self, license: info_response::Response);
    fn show_license_error(&self, error: LicenseError);
}

fn display_license_error(error: &LicenseError) -> &'static str {
    match error {
        LicenseError::Expired => "Your license has expired!",
        LicenseError::InvalidKey => "Your license key is invalid!",
        LicenseError::TooManySessions => "Too many sessions!",
        LicenseError::Revoked => "Your license has been revoked!",
        LicenseError::Internal => "Internal error! Contact support.",
    }
}

pub struct TUI;
impl GUIBackend for TUI {
    fn prompt_license(&self) -> String {
        // if we panic, it's safe cause communication haven't even started yet
        let prompt = dialoguer::Input::new()
            .with_prompt("Enter your license key")
            .interact()
            .unwrap();
        prompt
    }

    fn show_license_details(&self, license: info_response::Response) {
        let expiration_line = format!(
            "You license expires at: {}",
            license
                .expiry
                .map(|d| DateTime::from_protobuf(&d))
                .unwrap_or(chrono::DateTime::<Utc>::MAX_UTC)
                .to_string()
        );
        println!("{}\n{}", "Access Granted!".green(), expiration_line);
    }
    fn show_license_error(&self, error: LicenseError) {
        let error = println!(
            "{}\n{}",
            "Access Denied!".red(),
            display_license_error(&error)
        );
        std::thread::sleep(GUI_DELAY);
    }
}

pub struct GUI;

impl GUIBackend for GUI {
    fn prompt_license(&self) -> String {
        todo!()
    }

    fn show_license_details(&self, license: info_response::Response) {
        todo!()
    }

    fn show_license_error(&self, error: LicenseError) {
        todo!()
    }
}

pub struct Dispatcher {
    backend: Box<dyn GUIBackend>,
}

impl Dispatcher {
    pub fn new() -> Self {
        // TODO: add gui dispatching here
        Self {
            backend: Box::new(TUI),
        }
    }
}

impl GUIBackend for Dispatcher {
    fn prompt_license(&self) -> String {
        self.backend.prompt_license()
    }

    fn show_license_details(&self, license: info_response::Response) {
        self.backend.show_license_details(license);
    }

    fn show_license_error(&self, error: LicenseError) {
        self.backend.show_license_error(error);
    }
}

impl<T: GUIBackend + Sync> GUIBackend for Arc<T> {
    fn prompt_license(&self) -> String {
        self.deref().prompt_license()
    }

    fn show_license_details(&self, license: info_response::Response) {
        self.deref().show_license_details(license)
    }

    fn show_license_error(&self, error: LicenseError) {
        self.deref().show_license_error(error)
    }
}
