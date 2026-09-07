pub mod json;
pub mod terminal;

pub use json::{JsonResult, JsonTarget, print_json};
pub use terminal::{print_human, print_trace};
