//! Runs the retained systemd image staging primitive without boot selection.

#[path = "../executable.rs"]
mod executable;
#[path = "../image_stage.rs"]
mod image_stage;

fn main() {
    if let Err(error) = image_stage::run_from_process() {
        eprintln!("aos-systemd-image-stage: {error:#}");
        std::process::exit(1);
    }
}
