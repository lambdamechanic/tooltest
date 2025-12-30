use std::collections::HashSet;

use serde_json::{Number, Value as JsonValue};

#[derive(Clone, Debug, Default)]
pub(crate) struct ValueCorpus {
    integers: Vec<i64>,
    numbers: Vec<Number>,
    strings: Vec<String>,
    integer_set: HashSet<i64>,
    number_set: HashSet<Number>,
    pub(super) string_set: HashSet<String>,
}

impl ValueCorpus {
    pub(crate) fn seed_numbers<I>(&mut self, values: I)
    where
        I: IntoIterator<Item = Number>,
    {
        for value in values {
            self.insert_number(value);
        }
    }

    pub(crate) fn seed_strings<I>(&mut self, values: I)
    where
        I: IntoIterator<Item = String>,
    {
        for value in values {
            self.insert_string(value);
        }
    }

    pub(crate) fn mine_structured_content(&mut self, value: &JsonValue) {
        self.walk_value(value);
    }

    pub(crate) fn mine_text(&mut self, text: &str) {
        for token in text.split_whitespace() {
            if let Some(number) = number_from_token(token) {
                self.insert_number(number);
            } else {
                self.insert_string(token.to_string());
            }
        }
    }

    pub(crate) fn mine_text_from_value(&mut self, value: &JsonValue) {
        self.walk_text(value);
    }

    pub(crate) fn merge_from(&mut self, other: &ValueCorpus) {
        for number in other.numbers() {
            self.insert_number(number.clone());
        }
        for value in other.strings() {
            self.insert_string(value.clone());
        }
    }

    pub(crate) fn integers(&self) -> &[i64] {
        &self.integers
    }

    pub(crate) fn numbers(&self) -> &[Number] {
        &self.numbers
    }

    pub(crate) fn strings(&self) -> &[String] {
        &self.strings
    }

    fn insert_number(&mut self, value: Number) {
        if self.number_set.insert(value.clone()) {
            self.numbers.push(value.clone());
        }
        if let Some(integer) = number_to_i64(&value) {
            if self.integer_set.insert(integer) {
                self.integers.push(integer);
            }
        }
    }

    fn insert_string(&mut self, value: String) {
        if self.string_set.insert(value.clone()) {
            self.strings.push(value);
        }
    }

    fn walk_value(&mut self, value: &JsonValue) {
        match value {
            JsonValue::Null | JsonValue::Bool(_) => {}
            JsonValue::Number(number) => self.insert_number(number.clone()),
            JsonValue::String(value) => self.insert_string(value.clone()),
            JsonValue::Array(values) => {
                for value in values {
                    self.walk_value(value);
                }
            }
            JsonValue::Object(map) => {
                let mut keys: Vec<_> = map.keys().collect();
                keys.sort();
                for key in keys {
                    self.insert_string(key.to_string());
                    let value = map.get(key).expect("key from map");
                    self.walk_value(value);
                }
            }
        }
    }

    fn walk_text(&mut self, value: &JsonValue) {
        match value {
            JsonValue::Null | JsonValue::Bool(_) | JsonValue::Number(_) => {}
            JsonValue::String(value) => self.mine_text(value),
            JsonValue::Array(values) => {
                for value in values {
                    self.walk_text(value);
                }
            }
            JsonValue::Object(map) => {
                let mut keys: Vec<_> = map.keys().collect();
                keys.sort();
                for key in keys {
                    self.mine_text(key);
                    let value = map.get(key).expect("key from map");
                    self.walk_text(value);
                }
            }
        }
    }
}

pub(super) fn number_to_i64(value: &Number) -> Option<i64> {
    if let Some(value) = value.as_i64() {
        return Some(value);
    }
    if let Some(value) = value.as_u64() {
        return i64::try_from(value).ok();
    }
    let value = value.as_f64().expect("f64 value");
    if value.fract() != 0.0 {
        return None;
    }
    if value < i64::MIN as f64 || value > i64::MAX as f64 {
        return None;
    }
    Some(value as i64)
}

fn number_from_token(token: &str) -> Option<Number> {
    if let Ok(value) = token.parse::<i64>() {
        return Some(Number::from(value));
    }
    let value = token.parse::<f64>().ok()?;
    Number::from_f64(value)
}
