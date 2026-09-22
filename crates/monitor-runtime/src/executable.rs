//! Resolve a user-selected executable or macOS application bundle.
use std::path::{Path, PathBuf};

pub fn resolve_executable(input: &Path) -> Result<PathBuf, String> {
    if !input.is_absolute() {
        return Err("请选择程序的绝对路径".into());
    }
    let mut path = input.to_path_buf();
    if input.extension().is_some_and(|e| e == "app") && input.is_dir() {
        let value = plist::Value::from_file(input.join("Contents/Info.plist"))
            .map_err(|_| "无法读取应用 Info.plist")?;
        let name = value
            .as_dictionary()
            .and_then(|d| d.get("CFBundleExecutable"))
            .and_then(|v| v.as_string())
            .ok_or("应用缺少 CFBundleExecutable")?;
        if Path::new(name).components().count() != 1
            || name == "."
            || name == ".."
            || name.contains(['/', '\\'])
        {
            return Err("应用可执行文件名称无效".into());
        }
        path = input.join("Contents/MacOS").join(name);
    }
    let path = path
        .canonicalize()
        .map_err(|_| "程序路径不存在或不可访问")?;
    if !path.is_file() {
        return Err("请选择可执行文件或 macOS .app".into());
    }
    #[cfg(windows)]
    if !path
        .extension()
        .and_then(|e| e.to_str())
        .is_some_and(|e| e.eq_ignore_ascii_case("exe"))
    {
        return Err("当前支持直接启动 .exe；不通过 shell 执行脚本".into());
    }
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn invalid_bundle_cannot_escape_its_executable_directory() {
        let dir = tempfile::tempdir().unwrap();
        let app = dir.path().join("Test.app");
        std::fs::create_dir_all(app.join("Contents")).unwrap();
        std::fs::write(app.join("Contents/Info.plist"),r#"<?xml version="1.0"?><plist version="1.0"><dict><key>CFBundleExecutable</key><string>../../outside</string></dict></plist>"#).unwrap();
        assert!(resolve_executable(&app).is_err());
        assert!(resolve_executable(Path::new("relative-program")).is_err());
    }
}
