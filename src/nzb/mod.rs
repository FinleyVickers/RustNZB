use quick_xml::events::Event;
use quick_xml::reader::Reader;
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::BufReader;
use std::path::Path;
use anyhow::{Result, Context};
use regex::Regex;

#[derive(Debug, Serialize, Deserialize)]
pub struct NzbFile {
    pub files: Vec<NzbFileEntry>,
    pub meta: NzbMetadata,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct NzbFileEntry {
    pub subject: String,
    pub groups: Vec<String>,
    pub segments: Vec<Segment>,
    pub filename: String,
    pub bytes: u64,
    pub poster: Option<String>,
    pub date: Option<u64>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Segment {
    pub number: u32,
    pub bytes: u64,
    pub message_id: String,
}

#[derive(Debug, Default, Serialize, Deserialize, Clone)]
pub struct NzbMetadata {
    pub title: Option<String>,
    pub category: Option<String>,
    pub size: Option<u64>,
    pub password: Option<String>,
    pub comment: Option<String>,
}

impl NzbFile {
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let file = File::open(path).context("Failed to open NZB file")?;
        let reader = BufReader::new(file);
        Self::parse(reader)
    }

    fn parse<R: std::io::BufRead>(reader: R) -> Result<Self> {
        let mut xml_reader = Reader::from_reader(reader);
        let mut buf = Vec::new();
        let mut files = Vec::new();
        let mut meta = NzbMetadata::default();
        let mut current_file: Option<NzbFileEntry> = None;
        let mut current_segments = Vec::new();
        let mut current_groups = Vec::new();
        let mut in_head = false;

        loop {
            match xml_reader.read_event_into(&mut buf) {
                Ok(Event::Start(ref e)) => {
                    match e.name().as_ref() {
                        b"head" => in_head = true,
                        b"file" => {
                            let attrs = e.attributes().flatten().collect::<Vec<_>>();
                            let poster = attrs.iter()
                                .find(|attr| attr.key.as_ref() == b"poster")
                                .and_then(|attr| String::from_utf8(attr.value.to_vec()).ok());
                            let date = attrs.iter()
                                .find(|attr| attr.key.as_ref() == b"date")
                                .and_then(|attr| String::from_utf8(attr.value.to_vec()).ok())
                                .and_then(|s| s.parse().ok());

                            current_file = Some(NzbFileEntry {
                                subject: String::new(),
                                groups: Vec::new(),
                                segments: Vec::new(),
                                filename: String::new(),
                                bytes: 0,
                                poster,
                                date,
                            });
                        }
                        b"meta" => {
                            if in_head {
                                let attrs = e.attributes().flatten().collect::<Vec<_>>();
                                if let Some(type_attr) = attrs.iter().find(|attr| attr.key.as_ref() == b"type") {
                                    if let Ok(type_str) = String::from_utf8(type_attr.value.to_vec()) {
                                        match type_str.as_str() {
                                            "title" => meta.title = Some(String::new()),
                                            "category" => meta.category = Some(String::new()),
                                            "size" => meta.size = Some(0),
                                            "password" => meta.password = Some(String::new()),
                                            "comment" => meta.comment = Some(String::new()),
                                            _ => {}
                                        }
                                    }
                                }
                            }
                        }
                        b"segment" => {
                            let attrs = e.attributes().flatten().collect::<Vec<_>>();
                            let number = attrs.iter()
                                .find(|attr| attr.key.as_ref() == b"number")
                                .and_then(|attr| String::from_utf8(attr.value.to_vec()).ok())
                                .and_then(|s| s.parse().ok())
                                .unwrap_or(0);
                            let bytes = attrs.iter()
                                .find(|attr| attr.key.as_ref() == b"bytes")
                                .and_then(|attr| String::from_utf8(attr.value.to_vec()).ok())
                                .and_then(|s| s.parse().ok())
                                .unwrap_or(0);

                            current_segments.push(Segment {
                                number,
                                bytes,
                                message_id: String::new(),
                            });
                        }
                        _ => {}
                    }
                }
                Ok(Event::End(ref e)) => {
                    match e.name().as_ref() {
                        b"head" => in_head = false,
                        b"file" => {
                            if let Some(mut file) = current_file.take() {
                                file.segments = current_segments.clone();
                                file.groups = current_groups.clone();
                                
                                // Try to extract a better filename from the subject if none was set
                                if file.filename.is_empty() && !file.subject.is_empty() {
                                    file.filename = extract_filename_from_subject(&file.subject);
                                }
                                
                                files.push(file);
                                current_segments.clear();
                                current_groups.clear();
                            }
                        }
                        _ => {}
                    }
                }
                Ok(Event::Text(e)) => {
                    if let Some(file) = current_file.as_mut() {
                        file.subject = String::from_utf8_lossy(&e.into_inner()).into_owned();
                    }
                }
                Ok(Event::Eof) => break,
                Err(e) => return Err(anyhow::anyhow!("Error parsing NZB: {}", e)),
                _ => {}
            }
        }

        Ok(NzbFile { files, meta })
    }
}

fn extract_filename_from_subject(subject: &str) -> String {
    // Common patterns for filenames in subjects
    let patterns = vec![
        Regex::new(r#""([^"]+)""#).unwrap(),           // Quoted filename
        Regex::new(r#"\[(\d+/\d+)\] - "([^"]+)""#).unwrap(), // Common scene format
        Regex::new(r#"(?i)filename:?\s*(.+?)(?:\s*\(|\s*$)"#).unwrap(), // Explicit filename
    ];

    for pattern in patterns {
        if let Some(caps) = pattern.captures(subject) {
            if let Some(filename) = caps.get(1).or_else(|| caps.get(2)) {
                return sanitize_filename::sanitize(filename.as_str());
            }
        }
    }

    // Fallback: use the whole subject but sanitize it
    sanitize_filename::sanitize(subject)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple_nzb() {
        let nzb_content = r#"<?xml version="1.0" encoding="utf-8"?>
        <!DOCTYPE nzb PUBLIC "-//newzBin//DTD NZB 1.1//EN" "http://www.newzbin.com/DTD/nzb/nzb-1.1.dtd">
        <nzb xmlns="http://www.newzbin.com/DTD/2003/nzb">
            <head>
                <meta type="title">Test Title</meta>
                <meta type="category">Test</meta>
            </head>
            <file poster="poster@example.com" date="1234567890">
                <groups>
                    <group>alt.binaries.test</group>
                </groups>
                <segments>
                    <segment bytes="12345" number="1">test-msg-id@example.com</segment>
                </segments>
            </file>
        </nzb>"#;

        let result = NzbFile::parse(nzb_content.as_bytes()).unwrap();
        assert_eq!(result.files.len(), 1);
    }

    #[test]
    fn test_extract_filename() {
        assert_eq!(
            extract_filename_from_subject(r#""test.file.rar""#),
            "test.file.rar"
        );
        assert_eq!(
            extract_filename_from_subject("[1/2] - \"test.file.part1.rar\""),
            "test.file.part1.rar"
        );
        assert_eq!(
            extract_filename_from_subject("filename: test.file.zip (1/3)"),
            "test.file.zip"
        );
    }
} 