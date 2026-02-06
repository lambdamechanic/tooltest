#[cfg(unix)]
mod tooltest_prof_tests {
    use std::env;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};
    use std::process::Command;
    use tooltest_test_support::temp_path;

    fn write_executable(path: &Path, contents: &str) {
        fs::write(path, contents).expect("write script");
        let mut perms = fs::metadata(path).expect("metadata").permissions();
        perms.set_mode(0o755);
        fs::set_permissions(path, perms).expect("set permissions");
    }

    fn tooltest_prof_path() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../scripts/tooltest-prof")
    }

    #[test]
    fn tooltest_prof_passes_args_and_output() {
        let root = temp_path("prof-passes");
        fs::create_dir_all(&root).expect("create temp dir");
        let bin_dir = root.join("bin");
        fs::create_dir_all(&bin_dir).expect("create bin dir");

        let args_file = root.join("flamegraph.args");
        let flamegraph = bin_dir.join("flamegraph");
        let tooltest = bin_dir.join("tooltest");

        write_executable(
            &flamegraph,
            "#!/usr/bin/env bash\nset -euo pipefail\nprintf '%s\\n' \"$@\" > \"$FLAMEGRAPH_ARGS_FILE\"\n",
        );
        write_executable(&tooltest, "#!/usr/bin/env bash\nexit 0\n");

        let profile_path = root.join("profile.svg");
        let script = tooltest_prof_path();
        let mut command = Command::new(script);
        command.arg("stdio").arg("--command").arg("server");
        command.env(
            "PATH",
            format!(
                "{}:{}",
                bin_dir.display(),
                env::var("PATH").unwrap_or_default()
            ),
        );
        command.env("FLAMEGRAPH_ARGS_FILE", &args_file);
        command.env("TOOLTEST_PROFILE_PATH", &profile_path);

        let output = command.output().expect("run tooltest-prof");
        assert!(
            output.status.success(),
            "stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );

        let args = fs::read_to_string(&args_file).expect("read args");
        let args: Vec<&str> = args.lines().collect();
        let expected = vec![
            "--output",
            profile_path.to_str().expect("profile path"),
            "--",
            tooltest.to_str().expect("tooltest path"),
            "stdio",
            "--command",
            "server",
        ];
        assert_eq!(args, expected);
        assert!(profile_path.exists(), "profile output should exist");
    }

    #[test]
    fn tooltest_prof_uses_default_output_when_unset() {
        let root = temp_path("prof-default-output");
        fs::create_dir_all(&root).expect("create temp dir");
        let bin_dir = root.join("bin");
        fs::create_dir_all(&bin_dir).expect("create bin dir");

        let args_file = root.join("flamegraph.args");
        let flamegraph = bin_dir.join("flamegraph");
        let tooltest = bin_dir.join("tooltest");

        write_executable(
            &flamegraph,
            "#!/usr/bin/env bash\nset -euo pipefail\nprintf '%s\\n' \"$@\" > \"$FLAMEGRAPH_ARGS_FILE\"\n",
        );
        write_executable(&tooltest, "#!/usr/bin/env bash\nexit 0\n");

        let script = tooltest_prof_path();
        let mut command = Command::new(script);
        command.arg("http").arg("--url").arg("http://example.com");
        command.env(
            "PATH",
            format!(
                "{}:{}",
                bin_dir.display(),
                env::var("PATH").unwrap_or_default()
            ),
        );
        command.env("FLAMEGRAPH_ARGS_FILE", &args_file);
        command.env_remove("TOOLTEST_PROFILE_PATH");

        let output = command.output().expect("run tooltest-prof");
        assert!(
            output.status.success(),
            "stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );

        let args = fs::read_to_string(&args_file).expect("read args");
        let args: Vec<&str> = args.lines().collect();
        let expected = vec![
            "--",
            tooltest.to_str().expect("tooltest path"),
            "http",
            "--url",
            "http://example.com",
        ];
        assert_eq!(args, expected);
    }

    #[test]
    fn tooltest_prof_uses_override_tooltest_path() {
        let root = temp_path("prof-override-tooltest");
        fs::create_dir_all(&root).expect("create temp dir");
        let bin_dir = root.join("bin");
        fs::create_dir_all(&bin_dir).expect("create bin dir");

        let args_file = root.join("flamegraph.args");
        let flamegraph = bin_dir.join("flamegraph");
        let tooltest_override = root.join("tooltest-override");
        let tooltest_in_path = bin_dir.join("tooltest");

        write_executable(
            &flamegraph,
            "#!/usr/bin/env bash\nset -euo pipefail\nprintf '%s\\n' \"$@\" > \"$FLAMEGRAPH_ARGS_FILE\"\n",
        );
        write_executable(&tooltest_override, "#!/usr/bin/env bash\nexit 0\n");
        write_executable(&tooltest_in_path, "#!/usr/bin/env bash\nexit 0\n");

        let script = tooltest_prof_path();
        let mut command = Command::new(script);
        command.arg("stdio").arg("--command").arg("server");
        command.env(
            "PATH",
            format!(
                "{}:{}",
                bin_dir.display(),
                env::var("PATH").unwrap_or_default()
            ),
        );
        command.env("FLAMEGRAPH_ARGS_FILE", &args_file);
        command.env("TOOLTEST_PROFILE_TOOLTEST_PATH", &tooltest_override);

        let output = command.output().expect("run tooltest-prof");
        assert!(
            output.status.success(),
            "stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );

        let args = fs::read_to_string(&args_file).expect("read args");
        let args: Vec<&str> = args.lines().collect();
        let expected = vec![
            "--",
            tooltest_override.to_str().expect("override path"),
            "stdio",
            "--command",
            "server",
        ];
        assert_eq!(args, expected);
    }

    #[test]
    fn tooltest_prof_rejects_directory_path() {
        let root = temp_path("prof-rejects-dir");
        fs::create_dir_all(&root).expect("create temp dir");
        let bin_dir = root.join("bin");
        fs::create_dir_all(&bin_dir).expect("create bin dir");

        let flamegraph = bin_dir.join("flamegraph");
        let tooltest = bin_dir.join("tooltest");

        write_executable(&flamegraph, "#!/usr/bin/env bash\nexit 0\n");
        write_executable(&tooltest, "#!/usr/bin/env bash\nexit 0\n");

        let script = tooltest_prof_path();
        let mut command = Command::new(script);
        command.arg("stdio");
        command.env(
            "PATH",
            format!(
                "{}:{}",
                bin_dir.display(),
                env::var("PATH").unwrap_or_default()
            ),
        );
        command.env("TOOLTEST_PROFILE_PATH", &root);

        let output = command.output().expect("run tooltest-prof");
        assert!(
            !output.status.success(),
            "expected failure for directory path"
        );
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("directory"),
            "stderr should mention directory: {stderr}"
        );
    }
}
