use cawide_protocol::types::GitErrorKind;
use std::process::ExitStatus;

pub fn classify(stderr: &str, _exit: Option<ExitStatus>, user_managed_ssh: bool) -> GitErrorKind {
    let lower = stderr.to_ascii_lowercase();

    // Row 1
    if lower.contains("remote host identification has changed") {
        return GitErrorKind::HostKeyChanged;
    }
    // Row 2
    if lower.contains("keys of different type are already known for this host") {
        return GitErrorKind::HostKeyChanged;
    }
    // Row 3
    if lower.contains("host key verification failed")
        || lower.contains("no ed25519 host key is known")
        || lower.contains("no ecdsa host key is known")
        || lower.contains("no rsa host key is known")
    {
        return if user_managed_ssh {
            GitErrorKind::UnknownHostKeyCustomSsh
        } else {
            GitErrorKind::UnknownHostKey
        };
    }
    // Row 4
    if lower.contains("please tell me who you are")
        || lower.contains("empty ident name")
        || lower.contains("unable to auto-detect email address")
    {
        return GitErrorKind::IdentityMissing;
    }
    // Row 5
    if lower.contains("returned error: 403")
        || (lower.contains("permission to ") && lower.contains(" denied"))
        || lower.contains("you are not allowed to push")
        || lower.contains("access denied")
        || lower.contains("insufficient permission")
    {
        return GitErrorKind::PermissionDenied;
    }
    // Row 6
    if lower.contains("authentication failed")
        || lower.contains("could not read username")
        || lower.contains("could not read password")
        || lower.contains("terminal prompts disabled")
        || lower.contains("permission denied (publickey")
        || lower.contains("invalid username or password")
        || lower.contains("returned error: 401")
        || lower.contains("cannot prompt because user interactivity has been disabled")
    {
        return GitErrorKind::AuthenticationFailed;
    }
    // Row 7
    if (lower.contains("[rejected]")
        && (lower.contains("non-fast-forward") || lower.contains("fetch first")))
        || lower.contains("updates were rejected")
    {
        return GitErrorKind::NonFastForward;
    }
    // Row 8
    if lower.contains("would be overwritten by") {
        return GitErrorKind::LocalChangesWouldBeOverwritten;
    }
    // Row 9
    if lower.contains("not fully merged") {
        return GitErrorKind::NotFullyMerged;
    }
    // Row 10
    if lower.contains("index.lock': file exists") {
        return GitErrorKind::IndexLocked;
    }
    // Row 11
    if lower.contains("could not resolve host")
        || lower.contains("connection timed out")
        || lower.contains("connection refused")
        || lower.contains("network is unreachable")
        || lower.contains("unable to access")
    {
        return GitErrorKind::Network;
    }
    // Row 12
    if lower.contains("nothing to commit") || lower.contains("no changes added to commit") {
        return GitErrorKind::NothingToCommit;
    }
    // Row 13
    if lower.contains("no upstream")
        || lower.contains("has no upstream branch")
        || lower.contains("no tracking information")
    {
        return GitErrorKind::NoUpstream;
    }
    // Row 14
    GitErrorKind::Other
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_classification_table() {
        let cases = [
            // Row 1
            ("WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!", GitErrorKind::HostKeyChanged),
            // Row 2
            ("keys of different type are already known for this host", GitErrorKind::HostKeyChanged),
            // Row 3 (Cawide-managed vs user-managed)
            ("Host key verification failed.", GitErrorKind::UnknownHostKey),
            ("No RSA host key is known for [example.com]:22", GitErrorKind::UnknownHostKey),
            // Row 4
            ("*** Please tell me who you are.\nRun git config ...", GitErrorKind::IdentityMissing),
            ("empty ident name (for <>) not allowed", GitErrorKind::IdentityMissing),
            ("unable to auto-detect email address (got 'foo@bar')", GitErrorKind::IdentityMissing),
            // Row 5
            ("The requested URL returned error: 403", GitErrorKind::PermissionDenied),
            ("Permission to org/repo denied to user", GitErrorKind::PermissionDenied),
            ("You are not allowed to push code to this project.", GitErrorKind::PermissionDenied),
            // Row 6
            ("Authentication failed for 'https://github.com/org/repo.git/'", GitErrorKind::AuthenticationFailed),
            ("fatal: could not read Username for 'https://github.com': terminal prompts disabled", GitErrorKind::AuthenticationFailed),
            ("fatal: could not read Password for 'https://github.com': terminal prompts disabled", GitErrorKind::AuthenticationFailed),
            ("Permission denied (publickey).", GitErrorKind::AuthenticationFailed),
            ("The requested URL returned error: 401", GitErrorKind::AuthenticationFailed),
            // Row 7
            ("To https://github.com/org/repo.git\n ! [rejected] main -> main (non-fast-forward)", GitErrorKind::NonFastForward),
            ("Updates were rejected because the remote contains work that you do not have locally.", GitErrorKind::NonFastForward),
            // Row 8
            ("error: Your local changes to the following files would be overwritten by checkout:", GitErrorKind::LocalChangesWouldBeOverwritten),
            // Row 9
            ("error: The branch 'feature' is not fully merged.", GitErrorKind::NotFullyMerged),
            // Row 10
            ("fatal: Unable to create '/path/.git/index.lock': File exists.", GitErrorKind::IndexLocked),
            // Row 11
            ("fatal: unable to access 'https://github.com/': Could not resolve host: github.com", GitErrorKind::Network),
            ("fatal: unable to access 'https://github.com/': Connection timed out", GitErrorKind::Network),
            ("fatal: unable to access 'https://github.com/': Failed to connect to github.com: Connection refused", GitErrorKind::Network),
            ("fatal: unable to access 'https://github.com/': Network is unreachable", GitErrorKind::Network),
            // Row 12
            ("nothing to commit, working tree clean", GitErrorKind::NothingToCommit),
            ("no changes added to commit (use \"git add\" to track)", GitErrorKind::NothingToCommit),
            // Row 13
            ("fatal: The current branch main has no upstream branch.", GitErrorKind::NoUpstream),
            ("There is no tracking information for the current branch.", GitErrorKind::NoUpstream),
            // Row 14
            ("fatal: some unknown git internal error", GitErrorKind::Other),
        ];

        for (stderr, expected) in cases {
            assert_eq!(
                classify(stderr, None, false),
                expected,
                "failed classifying: {stderr}"
            );
        }

        // Check custom ssh mapping
        assert_eq!(
            classify("Host key verification failed.", None, true),
            GitErrorKind::UnknownHostKeyCustomSsh
        );
    }
}
