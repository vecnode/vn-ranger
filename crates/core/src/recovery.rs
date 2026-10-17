//! What to say about an action a crash interrupted.
//!
//! An intent with no result is not an error and not a guess: it is two facts about the
//! disk — is the payload in the quarantine root, and is the file still at its original
//! path — and those two facts have four combinations. Each combination gets a verdict, a
//! sentence, and exactly one suggested next step, so the interface never has to invent
//! an explanation for a half-finished action.

use crate::journal::JournalEntry;

/// What the disk says about an interrupted action.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    /// Neither side happened: the intent was written and the process died at once.
    NotStarted,
    /// The payload is in the quarantine and the original is gone, but no result was
    /// written.
    Moved,
    /// The payload is in the quarantine and the original is still there: a cross-volume
    /// move copied the file and did not get to unlink it.
    Copied,
    /// Neither the payload nor the original is there.
    Unexplained,
}

impl Phase {
    /// A short label for the journal list.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::NotStarted => "not started",
            Self::Moved => "moved, not recorded",
            Self::Copied => "copied, original kept",
            Self::Unexplained => "both paths empty",
        }
    }

    /// What the pair of facts means.
    #[must_use]
    pub fn detail(self) -> &'static str {
        match self {
            Self::NotStarted => {
                "The journal recorded the intent and nothing else happened. The file is where it was."
            }
            Self::Moved => {
                "The file is in the quarantine and the original path is empty, but the result was never written."
            }
            Self::Copied => {
                "The copy is complete and the original was not removed. Two copies exist; the quarantine one is verified."
            }
            Self::Unexplained => {
                "Neither the original nor the payload exists. The manifest records what was expected."
            }
        }
    }

    /// The one next step the interface offers.
    #[must_use]
    pub fn step(self) -> &'static str {
        match self {
            Self::NotStarted => "Retry the action, or forget the entry.",
            Self::Moved => "Verify the payload's hash, then record the move or restore the file.",
            Self::Copied => "Verify the hash, then finish the move or remove the copy.",
            Self::Unexplained => "Read the entry's manifest before doing anything else.",
        }
    }

    /// Whether a person should stop and look before anything else is done.
    #[must_use]
    pub fn needs_attention(self) -> bool {
        matches!(self, Self::Copied | Self::Unexplained)
    }
}

/// A verdict about one interrupted action.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Verdict {
    /// Which of the four states the disk is in.
    pub phase: Phase,
    /// What it means, in a sentence.
    pub detail: &'static str,
    /// The one next step.
    pub step: &'static str,
}

/// Decide what an interrupted intent means from the two facts the caller observed.
#[must_use]
pub fn verdict(payload_present: bool, source_present: bool) -> Verdict {
    let phase = match (payload_present, source_present) {
        (false, true) => Phase::NotStarted,
        (true, false) => Phase::Moved,
        (true, true) => Phase::Copied,
        (false, false) => Phase::Unexplained,
    };
    Verdict {
        phase,
        detail: phase.detail(),
        step: phase.step(),
    }
}

/// A sentence identifying the interrupted entry, for the interface and the exports.
#[must_use]
pub fn describe(intent: &JournalEntry) -> String {
    let action = intent.action.map_or("action", |action| action.label());
    let path = intent.path.as_deref().unwrap_or("an unrecorded path");
    format!("{action} of {path}, started at {}", intent.at)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::journal::{Action, Draft};

    #[test]
    fn the_four_states_have_four_verdicts() {
        assert_eq!(verdict(false, true).phase, Phase::NotStarted);
        assert_eq!(verdict(true, false).phase, Phase::Moved);
        assert_eq!(verdict(true, true).phase, Phase::Copied);
        assert_eq!(verdict(false, false).phase, Phase::Unexplained);
    }

    #[test]
    fn every_verdict_has_a_sentence_and_exactly_one_step() {
        for (payload, source) in [(false, true), (true, false), (true, true), (false, false)] {
            let verdict = verdict(payload, source);
            assert!(!verdict.detail.is_empty());
            assert!(!verdict.step.is_empty());
            assert!(verdict.step.ends_with('.'), "the step is a sentence");
            assert_eq!(verdict.step.matches(". ").count(), 0, "the step is one step");
        }
    }

    #[test]
    fn only_the_two_states_that_need_a_person_say_so() {
        assert!(!verdict(false, true).phase.needs_attention());
        assert!(!verdict(true, false).phase.needs_attention());
        assert!(verdict(true, true).phase.needs_attention());
        assert!(verdict(false, false).phase.needs_attention());
    }

    #[test]
    fn describe_names_the_action_and_the_path() {
        let intent = Draft::intent(Action::Quarantine)
            .with_id("abc")
            .with_path("C:\\Temp\\x.exe")
            .seal(1, 1_700_000_000);
        let line = describe(&intent);
        assert!(line.contains("quarantine"));
        assert!(line.contains("C:\\Temp\\x.exe"));
    }

    #[test]
    fn describe_survives_an_entry_with_no_path() {
        let intent = Draft::intent(Action::Clean).with_id("abc").seal(1, 0);
        assert!(describe(&intent).contains("unrecorded path"));
    }
}
