use cawide_protocol::types::{GitGraphEdge, GitGraphHalf, GitGraphRow};

pub struct RawCommitInfo {
    pub oid: String,
    pub parents: Vec<String>,
}

pub fn compute_commit_graph(
    commits: &[RawCommitInfo],
    is_path_query: bool,
) -> (Vec<GitGraphRow>, u8) {
    if commits.is_empty() {
        return (Vec::new(), 0);
    }

    if is_path_query {
        let n = commits.len();
        let mut rows = Vec::with_capacity(n);
        for i in 0..n {
            let mut edges = Vec::new();
            if i > 0 {
                edges.push(GitGraphEdge {
                    from_lane: 0,
                    to_lane: 0,
                    color: 1,
                    half: GitGraphHalf::Top,
                });
            }
            if i + 1 < n {
                edges.push(GitGraphEdge {
                    from_lane: 0,
                    to_lane: 0,
                    color: 1,
                    half: GitGraphHalf::Bottom,
                });
            }
            rows.push(GitGraphRow {
                lane: 0,
                color: 1,
                edges,
            });
        }
        return (rows, 0);
    }

    let mut active_lanes: Vec<Option<&str>> = Vec::new();
    let mut rows = Vec::with_capacity(commits.len());
    let mut max_lane: u8 = 0;

    for commit in commits {
        // 1. Locate all existing lanes expecting this commit
        let mut matching_lanes = Vec::new();
        for (idx, slot) in active_lanes.iter().enumerate() {
            if *slot == Some(commit.oid.as_str()) {
                matching_lanes.push(idx);
            }
        }

        let lane_idx = if let Some(&first) = matching_lanes.first() {
            first
        } else if let Some(free_idx) = active_lanes.iter().position(|s| s.is_none()) {
            free_idx
        } else {
            active_lanes.push(None);
            active_lanes.len() - 1
        };

        let current_lane = (lane_idx.min(u8::MAX as usize)) as u8;
        if current_lane > max_lane {
            max_lane = current_lane;
        }

        let lane_color = 1 + (current_lane % 7);
        let mut edges = Vec::new();

        // 2. Incoming edges from top for active lanes
        let converged_lanes: Vec<usize> = matching_lanes.iter().copied().skip(1).collect();
        for (col, slot) in active_lanes.iter_mut().enumerate() {
            let col_u8 = (col.min(u8::MAX as usize)) as u8;
            if slot.is_some() {
                if converged_lanes.contains(&col) {
                    // Converging lane: emit only converging edge and clear lane
                    edges.push(GitGraphEdge {
                        from_lane: col_u8,
                        to_lane: current_lane,
                        color: 1 + (col_u8 % 7),
                        half: GitGraphHalf::Top,
                    });
                    *slot = None;
                } else {
                    // Matching lane or pass-through lane
                    edges.push(GitGraphEdge {
                        from_lane: col_u8,
                        to_lane: col_u8,
                        color: 1 + (col_u8 % 7),
                        half: GitGraphHalf::Top,
                    });
                }
            }
        }

        // 3. Outgoing edges towards bottom
        let pre_existing_passthrough: Vec<usize> = active_lanes
            .iter()
            .enumerate()
            .filter(|&(col, slot)| col != lane_idx && slot.is_some())
            .map(|(col, _)| col)
            .collect();

        // Update current lane with first parent
        if let Some(first_parent) = commit.parents.first() {
            active_lanes[lane_idx] = Some(first_parent.as_str());
            edges.push(GitGraphEdge {
                from_lane: current_lane,
                to_lane: current_lane,
                color: lane_color,
                half: GitGraphHalf::Bottom,
            });
        } else {
            // Root commit: this lane ends
            active_lanes[lane_idx] = None;
        }

        // Subsequent parents (merge commits)
        for parent_oid in commit.parents.iter().skip(1) {
            let p_oid = parent_oid.as_str();
            let p_lane = if let Some(existing) = active_lanes.iter().position(|s| *s == Some(p_oid))
            {
                existing
            } else if let Some(free_idx) = active_lanes
                .iter()
                .enumerate()
                .position(|(idx, s)| s.is_none() && !converged_lanes.contains(&idx))
            {
                active_lanes[free_idx] = Some(p_oid);
                free_idx
            } else if let Some(free_idx) = active_lanes.iter().position(|s| s.is_none()) {
                active_lanes[free_idx] = Some(p_oid);
                free_idx
            } else {
                active_lanes.push(Some(p_oid));
                active_lanes.len() - 1
            };

            let p_lane_u8 = (p_lane.min(u8::MAX as usize)) as u8;
            if p_lane_u8 > max_lane {
                max_lane = p_lane_u8;
            }

            if p_lane != lane_idx {
                edges.push(GitGraphEdge {
                    from_lane: current_lane,
                    to_lane: p_lane_u8,
                    color: 1 + (p_lane_u8 % 7),
                    half: GitGraphHalf::Bottom,
                });
            }
        }

        // Pass-through lanes continue to the bottom (excluding lanes connected to parents)
        for col in pre_existing_passthrough {
            if commit
                .parents
                .iter()
                .skip(1)
                .any(|p| active_lanes.get(col).copied() == Some(Some(p.as_str())))
            {
                continue;
            }
            let col_u8 = (col.min(u8::MAX as usize)) as u8;
            edges.push(GitGraphEdge {
                from_lane: col_u8,
                to_lane: col_u8,
                color: 1 + (col_u8 % 7),
                half: GitGraphHalf::Bottom,
            });
        }

        // Trim trailing empty lanes
        while active_lanes.last().is_some_and(|s| s.is_none()) {
            active_lanes.pop();
        }

        rows.push(GitGraphRow {
            lane: current_lane,
            color: lane_color,
            edges,
        });
    }

    (rows, max_lane)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_linear_commit_graph() {
        let commits = vec![
            RawCommitInfo {
                oid: "c2".into(),
                parents: vec!["c1".into()],
            },
            RawCommitInfo {
                oid: "c1".into(),
                parents: vec![],
            },
        ];
        let (rows, max_lane) = compute_commit_graph(&commits, false);
        assert_eq!(rows.len(), 2);
        assert_eq!(max_lane, 0);
        assert_eq!(rows[0].lane, 0);
        assert_eq!(rows[1].lane, 0);
    }

    #[test]
    fn test_branch_and_merge_graph() {
        let commits = vec![
            RawCommitInfo {
                oid: "m".into(),
                parents: vec!["m_p1".into(), "feature".into()],
            },
            RawCommitInfo {
                oid: "feature".into(),
                parents: vec!["base".into()],
            },
            RawCommitInfo {
                oid: "m_p1".into(),
                parents: vec!["base".into()],
            },
            RawCommitInfo {
                oid: "base".into(),
                parents: vec![],
            },
        ];
        let (rows, max_lane) = compute_commit_graph(&commits, false);
        assert_eq!(rows.len(), 4);
        assert!(max_lane >= 1);
    }

    #[test]
    fn test_multiple_branches_converging_cleans_lanes() {
        // Two independent branches both based on "root"
        let commits = vec![
            RawCommitInfo {
                oid: "b1".into(),
                parents: vec!["root".into()],
            },
            RawCommitInfo {
                oid: "b2".into(),
                parents: vec!["root".into()],
            },
            RawCommitInfo {
                oid: "root".into(),
                parents: vec![],
            },
        ];
        let (rows, max_lane) = compute_commit_graph(&commits, false);
        assert_eq!(rows.len(), 3);
        assert_eq!(max_lane, 1);
        // After root commit, no phantom lanes linger
        assert_eq!(rows[2].lane, 0);
    }

    #[test]
    fn test_passthrough_lane_emits_both_top_and_bottom_edges() {
        let commits = vec![
            RawCommitInfo {
                oid: "m".into(),
                parents: vec!["m_p1".into(), "feature".into()],
            },
            RawCommitInfo {
                oid: "feature".into(),
                parents: vec!["base".into()],
            },
            RawCommitInfo {
                oid: "m_p1".into(),
                parents: vec!["base".into()],
            },
            RawCommitInfo {
                oid: "base".into(),
                parents: vec![],
            },
        ];
        let (rows, _) = compute_commit_graph(&commits, false);
        // Row 1 is commit "feature" on lane 1. Lane 0 (m_p1) is pass-through.
        assert_eq!(rows[1].lane, 1);
        let top_0 = rows[1]
            .edges
            .iter()
            .any(|e| e.from_lane == 0 && e.to_lane == 0 && matches!(e.half, GitGraphHalf::Top));
        let bottom_0 = rows[1]
            .edges
            .iter()
            .any(|e| e.from_lane == 0 && e.to_lane == 0 && matches!(e.half, GitGraphHalf::Bottom));
        assert!(top_0, "pass-through lane 0 should have Top edge in row 1");
        assert!(
            bottom_0,
            "pass-through lane 0 should have Bottom edge in row 1"
        );
    }

    #[test]
    fn test_converging_lane_does_not_emit_duplicate_vertical_top_stub() {
        let commits = vec![
            RawCommitInfo {
                oid: "b1".into(),
                parents: vec!["root".into()],
            },
            RawCommitInfo {
                oid: "b2".into(),
                parents: vec!["root".into()],
            },
            RawCommitInfo {
                oid: "root".into(),
                parents: vec![],
            },
        ];
        let (rows, _) = compute_commit_graph(&commits, false);
        // Row 2 is "root". Both lane 0 and lane 1 were expecting "root".
        // Lane 1 merges into lane 0. Lane 1 must emit ONLY the converging Top edge (1 -> 0)
        // and NOT a vertical top stub (1 -> 1).
        assert_eq!(rows[2].lane, 0);
        let converging_top = rows[2]
            .edges
            .iter()
            .any(|e| e.from_lane == 1 && e.to_lane == 0 && matches!(e.half, GitGraphHalf::Top));
        let stub_top = rows[2]
            .edges
            .iter()
            .any(|e| e.from_lane == 1 && e.to_lane == 1 && matches!(e.half, GitGraphHalf::Top));
        assert!(
            converging_top,
            "should have converging edge from lane 1 to lane 0"
        );
        assert!(
            !stub_top,
            "converging lane 1 must NOT emit duplicate vertical top stub"
        );
    }
}
