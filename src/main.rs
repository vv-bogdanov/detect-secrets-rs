use detect_secrets_rs::run_current_process;

fn main() {
    if let Err(error) = run_current_process() {
        eprintln!("error: {error:#}");
        std::process::exit(1);
    }
}
