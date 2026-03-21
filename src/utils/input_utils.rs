//! Helpers for building interactive CLI autocompleters.
//!
//! This module provides small wrapper types that implement `inquire`'s
//! `Autocomplete` trait for several common use cases:
//!
//! - **`StringListAutoCompleter`**: fuzzy autocomplete over a fixed list of
//!   strings (e.g. existing filter record types).
//! - **`RecordTypeAutoCompleter`**: autocomplete for kernel audit record types
//!   backed by the `RecordType` enum.
//! - **`FilePathCompleter`**: filesystem-aware autocomplete for paths with
//!   fuzzy matching.

// TODO: This module could be consolidated into a single autocompleter
// struct/trait implementation. Essentially the only thing that differentiates
// the autocompleters is the type of data they are autocompleting.

use fuzzy_matcher::FuzzyMatcher;
use fuzzy_matcher::skim::SkimMatcherV2;
use inquire::{
    CustomUserError,
    autocompletion::{Autocomplete, Replacement},
};
use std::io::ErrorKind;
use strum::IntoEnumIterator;

use crate::core::parser::audit_types::RecordType;

/// Autocompleter for a fixed list of strings (e.g. existing filter record types
/// from config).
#[derive(Clone)]
pub struct StringListAutoCompleter {
    /// The current input.
    _input: String,
    /// The options to autocomplete.
    options: Vec<String>,
}

impl StringListAutoCompleter {
    /// Construct a new `StringListAutoCompleter` from a list of options.
    ///
    /// **Parameters:**
    ///
    /// * `options`: Vector of strings that will be offered as autocomplete
    ///   suggestions.
    pub fn new(options: Vec<String>) -> Self {
        Self {
            _input: String::new(),
            options,
        }
    }

    /// Return the candidate options sorted by fuzzy match score.
    ///
    /// **Parameters:**
    ///
    /// * `input`: The current user input used to rank the options.
    fn fuzzy_sort(&self, input: &str) -> Vec<(String, i64)> {
        let matcher = SkimMatcherV2::default().smart_case();
        let mut matches: Vec<(String, i64)> = self
            .options
            .iter()
            .filter_map(|s| {
                matcher
                    .fuzzy_match(s, input)
                    .map(|score| (s.clone(), score))
            })
            .collect();
        matches.sort_by(|a, b| b.1.cmp(&a.1));
        matches
    }
}

impl Autocomplete for StringListAutoCompleter {
    /// Return up to 25 fuzzy-matched suggestions from the fixed option list.
    fn get_suggestions(&mut self, input: &str) -> Result<Vec<String>, CustomUserError> {
        let matches = self.fuzzy_sort(input);
        Ok(matches.into_iter().take(25).map(|(s, _)| s).collect())
    }

    /// Resolve the final completion value for the current input.
    ///
    /// If a `highlighted_suggestion` is present, it is used as the completion;
    /// otherwise the best fuzzy match for `input` is chosen.
    fn get_completion(
        &mut self,
        input: &str,
        highlighted_suggestion: Option<String>,
    ) -> Result<Replacement, CustomUserError> {
        Ok(if let Some(suggestion) = highlighted_suggestion {
            Replacement::Some(suggestion)
        } else {
            let matches = self.fuzzy_sort(input);
            matches
                .first()
                .map(|(s, _)| Replacement::Some(s.clone()))
                .unwrap_or(Replacement::None)
        })
    }
}

/// Autocompleter for `RecordType`, backed by the `RecordType` enum.
///
/// This type keeps an internal cache of record types for the last input to
/// avoid recomputing on each keystroke.
#[derive(Clone, Default)]
pub struct RecordTypeAutoCompleter {
    input: String,
    record_types: Vec<RecordType>,
}

impl RecordTypeAutoCompleter {
    /// Refresh the internal cache of record types when the input changes.
    ///
    /// **Parameters:**
    ///
    /// * `input`: The current user input used to constrain the cache.
    fn update_input(&mut self, input: &str) -> Result<(), CustomUserError> {
        if input == self.input && !self.record_types.is_empty() {
            return Ok(());
        }

        self.input = input.to_owned().to_uppercase();
        self.record_types.clear();

        for record_type in RecordType::iter() {
            self.record_types.push(record_type);
        }

        Ok(())
    }

    /// Return matching record types sorted by fuzzy score for the given input.
    ///
    /// **Parameters:**
    ///
    /// * `input`: The current user input used to rank `RecordType` variants.
    fn fuzzy_sort(&self, input: &str) -> Vec<(String, i64)> {
        let mut matches: Vec<(String, i64)> = self
            .record_types
            .iter()
            .filter_map(|record_type| {
                SkimMatcherV2::default()
                    .smart_case()
                    .fuzzy_match(record_type.as_audit_str(), input)
                    .map(|score| (record_type.as_audit_str().to_string().to_lowercase(), score))
            })
            .collect();

        matches.sort_by(|a, b| b.1.cmp(&a.1));
        matches
    }
}

impl Autocomplete for RecordTypeAutoCompleter {
    /// Provide up to 25 `RecordType` suggestions matching the input.
    fn get_suggestions(&mut self, input: &str) -> Result<Vec<String>, CustomUserError> {
        self.update_input(input)?;

        let matches = self.fuzzy_sort(input);
        Ok(matches
            .into_iter()
            .take(25)
            .map(|(record_type, _)| record_type)
            .collect())
    }

    /// Resolve the final completion value for a record type.
    ///
    /// If a `highlighted_suggestion` is present, it is used; otherwise, the
    /// highest-scoring fuzzy match for `input` is returned.
    fn get_completion(
        &mut self,
        input: &str,
        highlighted_suggestion: Option<String>,
    ) -> Result<Replacement, CustomUserError> {
        self.update_input(input)?;

        Ok(if let Some(suggestion) = highlighted_suggestion {
            Replacement::Some(suggestion)
        } else {
            let matches = self.fuzzy_sort(input);
            matches
                .first()
                .map(|(record_type, _)| Replacement::Some(record_type.clone()))
                .unwrap_or(Replacement::None)
        })
    }
}

/// Autocompleter for filesystem paths.
#[derive(Clone, Default)]
pub struct FilePathCompleter {
    /// The current input.
    input: String,
    /// The filesystem paths.
    paths: Vec<String>,
}

impl FilePathCompleter {
    /// Refresh the internal list of filesystem paths for a given input prefix.
    ///
    /// This function attempts to read the directory implied by the current
    /// input (or its parent) and caches the discovered entries for later
    /// fuzzy matching.
    ///
    /// **Parameters:**
    ///
    /// * `input`: Raw user input representing a partial path.
    fn update_input(&mut self, input: &str) -> Result<(), CustomUserError> {
        if input == self.input && !self.paths.is_empty() {
            return Ok(());
        }

        self.input = input.to_owned();
        self.paths.clear();

        let input_path = std::path::PathBuf::from(input);

        let fallback_parent = input_path
            .parent()
            .map(|p| {
                if p.to_string_lossy().is_empty() {
                    std::path::PathBuf::from(".")
                } else {
                    p.to_owned()
                }
            })
            .unwrap_or_else(|| std::path::PathBuf::from("."));

        let scan_dir = if input.ends_with('/') {
            input_path
        } else {
            fallback_parent.clone()
        };

        let entries = match std::fs::read_dir(scan_dir) {
            Ok(read_dir) => Ok(read_dir),
            Err(err) if err.kind() == ErrorKind::NotFound => std::fs::read_dir(fallback_parent),
            Err(err) => Err(err),
        }?
        .collect::<Result<Vec<_>, _>>()?;

        for entry in entries {
            let path = entry.path();
            let path_str = if path.is_dir() {
                format!("{}/", path.to_string_lossy())
            } else {
                path.to_string_lossy().to_string()
            };

            self.paths.push(path_str);
        }

        Ok(())
    }

    /// Return cached filesystem paths sorted by fuzzy match score.
    ///
    /// **Parameters:**
    ///
    /// * `input`: The current user input used to rank cached path entries.
    fn fuzzy_sort(&self, input: &str) -> Vec<(String, i64)> {
        let mut matches: Vec<(String, i64)> = self
            .paths
            .iter()
            .filter_map(|path| {
                SkimMatcherV2::default()
                    .smart_case()
                    .fuzzy_match(path, input)
                    .map(|score| (path.clone(), score))
            })
            .collect();

        matches.sort_by(|a, b| b.1.cmp(&a.1));
        matches
    }
}

impl Autocomplete for FilePathCompleter {
    /// Provide up to 15 filesystem path suggestions matching the input.
    fn get_suggestions(&mut self, input: &str) -> Result<Vec<String>, CustomUserError> {
        self.update_input(input)?;

        let matches = self.fuzzy_sort(input);
        Ok(matches.into_iter().take(15).map(|(path, _)| path).collect())
    }

    /// Resolve the final completion value for a filesystem path.
    ///
    /// If a `highlighted_suggestion` is present, it is used; otherwise, the
    /// best fuzzy match for `input` is returned.
    fn get_completion(
        &mut self,
        input: &str,
        highlighted_suggestion: Option<String>,
    ) -> Result<Replacement, CustomUserError> {
        self.update_input(input)?;

        Ok(if let Some(suggestion) = highlighted_suggestion {
            Replacement::Some(suggestion)
        } else {
            let matches = self.fuzzy_sort(input);
            matches
                .first()
                .map(|(path, _)| Replacement::Some(path.clone()))
                .unwrap_or(Replacement::None)
        })
    }
}
