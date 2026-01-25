use std::collections::HashMap;

use serde::Serialize;

/// Core APS payload fields.
#[derive(Debug, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct Aps {
    pub alert: Alert,
    pub sound: Sound,
    pub mutable_content: u8,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub thread_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub interruption_level: Option<String>,
}

/// Alert content shown to the user.
#[derive(Debug, Serialize)]
pub struct Alert {
    pub title: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body: Option<String>,
}

/// Sound configuration (name or detailed settings).
#[derive(Debug, Serialize)]
#[serde(untagged)]
pub enum Sound {
    Name(String),
    Detailed {
        name: String,
        critical: u8,
        volume: f32,
    },
}

/// Full APNs payload with flattened client data.
#[derive(Debug, Serialize)]
pub struct ApnsPayload {
    pub aps: Aps,
    #[serde(flatten)]
    data: HashMap<String, String>,
}

impl ApnsPayload {
    pub fn new(
        title: String,
        body: Option<String>,
        thread_id: Option<String>,
        level: Option<String>,
        sound: Option<String>,
        volume: Option<f32>,
        data: HashMap<String, String>,
    ) -> Self {
        let sound = build_sound(sound, level.clone(), volume);
        Self {
            aps: Aps {
                alert: Alert { title, body },
                sound,
                mutable_content: 1,
                thread_id,
                interruption_level: level,
            },
            data,
        }
    }
}

fn build_sound(sound: Option<String>, level: Option<String>, volume: Option<f32>) -> Sound {
    let name = sound.unwrap_or_else(|| "default".to_string());
    let level = level.unwrap_or_default().to_ascii_lowercase();
    let has_volume = matches!(volume, Some(v) if v >= 0.0);

    if level == "critical" || has_volume {
        Sound::Detailed {
            name,
            critical: 1,
            volume: volume.unwrap_or(1.0),
        }
    } else {
        Sound::Name(name)
    }
}
