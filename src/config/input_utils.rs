use crate::parser::audit_types::RecordType;
use fuzzy_matcher::FuzzyMatcher;
use fuzzy_matcher::skim::SkimMatcherV2;
use inquire::{
    CustomUserError, Text,
    autocompletion::{Autocomplete, Replacement},
    validator::{StringValidator, Validation},
};
use strum::IntoEnumIterator;

/// Autocompleter for a fixed list of strings (e.g. existing filter record types from config).
#[derive(Clone)]
pub struct StringListAutoCompleter {
    input: String,
    options: Vec<String>,
}

impl StringListAutoCompleter {
    pub fn new(options: Vec<String>) -> Self {
        Self {
            input: String::new(),
            options,
        }
    }

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
    fn get_suggestions(&mut self, input: &str) -> Result<Vec<String>, CustomUserError> {
        let matches = self.fuzzy_sort(input);
        Ok(matches.into_iter().take(25).map(|(s, _)| s).collect())
    }

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

/// Not sure if this should be hoisted up to ./mod.rs or left here
#[derive(Clone, Default)]
pub struct RecordTypeAutoCompleter {
    input: String,
    record_types: Vec<RecordType>,
}

impl RecordTypeAutoCompleter {
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
    fn get_suggestions(&mut self, input: &str) -> Result<Vec<String>, CustomUserError> {
        self.update_input(input)?;

        let matches = self.fuzzy_sort(input);
        Ok(matches
            .into_iter()
            .take(25)
            .map(|(record_type, _)| record_type)
            .collect())
    }

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
