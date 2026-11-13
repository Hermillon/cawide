use cawide_protocol::types::{
    MAX_FORGE_BODY_BYTES, MAX_FORGE_DESCRIPTION_BYTES, MAX_FORGE_REPLY_TEXT_BYTES,
};

/// Truncates `body` at a char boundary so its byte length <= `max_bytes`,
/// and charges against `budget` (initially `MAX_FORGE_REPLY_TEXT_BYTES`).
///
/// Returns `true` if the body was truncated (either due to `max_bytes` or exhausted budget).
pub fn cap_body(body: &mut String, budget: &mut usize, max_bytes: usize) -> bool {
    let mut truncated = false;

    if *budget == 0 {
        if !body.is_empty() {
            body.clear();
            return true;
        }
        return false;
    }

    let limit = max_bytes.min(*budget);
    if body.len() > limit {
        truncated = true;
        let mut idx = limit;
        while idx > 0 && !body.is_char_boundary(idx) {
            idx -= 1;
        }
        body.truncate(idx);
    }

    *budget = budget.saturating_sub(body.len());
    truncated
}

pub fn cap_comment_body(body: &mut String, budget: &mut usize) -> bool {
    cap_body(body, budget, MAX_FORGE_BODY_BYTES)
}

pub fn cap_description(body: &mut String, budget: &mut usize) -> bool {
    cap_body(body, budget, MAX_FORGE_DESCRIPTION_BYTES)
}

pub fn initial_reply_budget() -> usize {
    MAX_FORGE_REPLY_TEXT_BYTES
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cap_body_within_limit() {
        let mut body = "short comment".to_string();
        let mut budget = initial_reply_budget();
        let truncated = cap_comment_body(&mut body, &mut budget);
        assert!(!truncated);
        assert_eq!(body, "short comment");
        assert_eq!(budget, MAX_FORGE_REPLY_TEXT_BYTES - 13);
    }

    #[test]
    fn test_cap_body_exceeds_max_bytes() {
        let mut body = "a".repeat(MAX_FORGE_BODY_BYTES + 500);
        let mut budget = initial_reply_budget();
        let truncated = cap_comment_body(&mut body, &mut budget);
        assert!(truncated);
        assert_eq!(body.len(), MAX_FORGE_BODY_BYTES);
    }

    #[test]
    fn test_cap_body_exhausted_budget() {
        let mut body = "hello".to_string();
        let mut budget = 0;
        let truncated = cap_comment_body(&mut body, &mut budget);
        assert!(truncated);
        assert!(body.is_empty());
    }
}
