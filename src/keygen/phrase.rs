use rand::distributions::{Distribution, Uniform};
use rand::rngs::OsRng;
use zeroize::Zeroizing;

use crate::error::{AppError, Result};

pub const MAX_PHRASE_WORDS: usize = 128;
const WORDLIST_TEXT: &str = include_str!("eff_large_wordlist.txt");

pub fn generate_phrase(word_count: usize, separator: &str) -> Result<Zeroizing<String>> {
    if word_count == 0 || word_count > MAX_PHRASE_WORDS {
        return Err(AppError::InvalidGeneratedPhraseWordCount(MAX_PHRASE_WORDS));
    }

    let words = words();
    let range = Uniform::from(0..words.len());
    let mut rng = OsRng;
    let mut phrase = Zeroizing::new(String::with_capacity(phrase_capacity(
        words, word_count, separator,
    )?));
    for word_index in 0..word_count {
        let index = range.sample(&mut rng);
        if word_index > 0 {
            phrase.push_str(separator);
        }
        phrase.push_str(words[index]);
    }

    Ok(phrase)
}

fn phrase_capacity(words: &[&str], word_count: usize, separator: &str) -> Result<usize> {
    let max_word_len = words
        .iter()
        .map(|word| word.len())
        .max()
        .ok_or(AppError::InputTooLarge)?;
    let words_capacity = max_word_len
        .checked_mul(word_count)
        .ok_or(AppError::InputTooLarge)?;
    let separators_capacity = separator
        .len()
        .checked_mul(word_count.saturating_sub(1))
        .ok_or(AppError::InputTooLarge)?;
    words_capacity
        .checked_add(separators_capacity)
        .ok_or(AppError::InputTooLarge)
}

pub fn words() -> &'static [&'static str] {
    use std::sync::OnceLock;

    static WORDS: OnceLock<Vec<&'static str>> = OnceLock::new();
    WORDS
        .get_or_init(|| {
            let words: Vec<_> = WORDLIST_TEXT
                .lines()
                .filter_map(|line| line.split_once(char::is_whitespace).map(|(_, word)| word))
                .collect();
            assert_eq!(
                words.len(),
                7776,
                "embedded EFF large wordlist must contain 7776 words"
            );
            words
        })
        .as_slice()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wordlist_has_eff_large_size() {
        let words = words();
        assert_eq!(words.len(), 7776);
        assert_eq!(words[0], "abacus");
        assert_eq!(words[7775], "zoom");
    }

    #[test]
    fn phrase_uses_requested_word_count_and_separator() {
        let phrase = generate_phrase(6, ".").expect("phrase must be generated");
        let parts: Vec<_> = phrase.split('.').collect();
        assert_eq!(parts.len(), 6);
        assert!(parts.iter().all(|word| words().contains(word)));
    }

    #[test]
    fn invalid_word_counts_are_rejected() {
        let zero = generate_phrase(0, "-").expect_err("zero words must be rejected");
        assert!(matches!(
            zero,
            AppError::InvalidGeneratedPhraseWordCount(MAX_PHRASE_WORDS)
        ));

        let too_many = generate_phrase(MAX_PHRASE_WORDS + 1, "-")
            .expect_err("too many words must be rejected");
        assert!(matches!(
            too_many,
            AppError::InvalidGeneratedPhraseWordCount(MAX_PHRASE_WORDS)
        ));
    }
}
