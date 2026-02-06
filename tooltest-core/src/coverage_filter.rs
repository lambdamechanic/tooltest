pub(crate) const LIST_TOOLS_COUNT_LABEL: &str = "tools/list";

pub(crate) fn is_coverage_tool_eligible(
    tool_name: &str,
    coverage_allowlist: Option<&[String]>,
    coverage_blocklist: Option<&[String]>,
) -> bool {
    if tool_name == LIST_TOOLS_COUNT_LABEL {
        return false;
    }
    if let Some(allowlist) = coverage_allowlist {
        if !allowlist.iter().any(|entry| entry == tool_name) {
            return false;
        }
    }
    if let Some(blocklist) = coverage_blocklist {
        if blocklist.iter().any(|entry| entry == tool_name) {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::{is_coverage_tool_eligible, LIST_TOOLS_COUNT_LABEL};

    #[test]
    fn is_coverage_tool_eligible_skips_tools_list_label() {
        assert!(!is_coverage_tool_eligible(
            LIST_TOOLS_COUNT_LABEL,
            None,
            None
        ));
    }

    #[test]
    fn is_coverage_tool_eligible_honors_allowlist_and_blocklist() {
        let allowlist = vec!["alpha".to_string()];
        let blocklist = vec!["beta".to_string()];

        assert!(is_coverage_tool_eligible(
            "alpha",
            Some(allowlist.as_slice()),
            None
        ));
        assert!(!is_coverage_tool_eligible(
            "beta",
            Some(allowlist.as_slice()),
            None
        ));

        assert!(is_coverage_tool_eligible(
            "alpha",
            None,
            Some(blocklist.as_slice())
        ));
        assert!(!is_coverage_tool_eligible(
            "beta",
            None,
            Some(blocklist.as_slice())
        ));

        let allow_and_block = vec!["alpha".to_string()];
        assert!(!is_coverage_tool_eligible(
            "alpha",
            Some(allow_and_block.as_slice()),
            Some(allow_and_block.as_slice())
        ));
    }
}
