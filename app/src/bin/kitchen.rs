// The kitchen sink in a real window, for judging the design on the actual monitor.
// Light theme: `kitchen light`.
#![windows_subsystem = "windows"]

use slint::ComponentHandle;

fn main() -> Result<(), slint::PlatformError> {
    let ui = vibeftp_app::kitchen()?;
    if std::env::args().any(|a| a == "light") {
        ui.global::<vibeftp_app::Theme>().set_dark(false);
    }
    ui.run()
}
