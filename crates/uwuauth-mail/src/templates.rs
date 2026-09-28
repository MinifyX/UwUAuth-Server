//! What the mails say, in German and English.
//!
//! Short, and the same shape every time: a line that says what this is, the one thing to do
//! with it (a link), and a line on what to do if it was not you. Plain text first; the HTML is
//! the same text with a little layout, and everything that comes from outside the server — a
//! name, a device — is escaped before it goes in.

use crate::Language;

/// Every mail the server writes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Mail {
    /// From the admin portal: the mail server works.
    Test,
    /// Somebody may make an account, with the link.
    Invitation {
        link: String,
        /// The household's or the company's name, as the admin set it.
        organization: String,
        /// Who invited, if a person did.
        invited_by: Option<String>,
        /// The day the link stops working, already written for the reader.
        expires: String,
    },
    /// A link to set a new password (and, for somebody who has none yet, a first one).
    PasswordReset { link: String, minutes: i64 },
    /// A link that confirms a new address for the account.
    EmailVerify { link: String, minutes: i64 },
    /// Somebody signed in from a device the account had not used before.
    NewDevice { device: String, ip: String, time: String },
    /// The password was changed or set.
    PasswordChanged { time: String },
    /// A way to sign in was added or removed: a passkey, the authenticator app, recovery codes.
    SignInChanged { what: String, time: String },
}

struct Text {
    subject: String,
    /// Paragraphs. The button goes after the first.
    lines: Vec<String>,
    button: Option<(String, String)>,
    footer: String,
}

impl Mail {
    /// Subject, plain text and HTML.
    pub fn render(&self, language: Language) -> (String, String, String) {
        let text = self.text(language);
        let mut plain = String::new();
        let mut html = String::new();
        for (index, line) in text.lines.iter().enumerate() {
            plain.push_str(line);
            plain.push_str("\n\n");
            html.push_str(&format!("<p style=\"margin:0 0 16px\">{}</p>", escape(line)));
            if let Some((label, link)) = text.button.as_ref().filter(|_| index == 0) {
                plain.push_str(link);
                plain.push_str("\n\n");
                html.push_str(&format!(
                    "<p style=\"margin:0 0 16px\"><a href=\"{link}\" style=\"display:inline-block;padding:12px 20px;\
                     border-radius:10px;background:#e11d74;color:#ffffff;text-decoration:none;font-weight:600\">{label}</a></p>\
                     <p style=\"margin:0 0 16px;font-size:13px;color:#716672;word-break:break-all\">{link}</p>",
                    link = escape(link),
                    label = escape(label)
                ));
            }
        }
        plain.push_str("-- \n");
        plain.push_str(&text.footer);
        plain.push('\n');
        let html = format!(
            "<!doctype html><html><body style=\"margin:0;padding:24px;background:#f8f4f6;\
             font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;color:#1c1420;line-height:1.5\">\
             <div style=\"max-width:520px;margin:0 auto;background:#ffffff;border-radius:16px;padding:28px\">\
             <p style=\"margin:0 0 20px;font-weight:700;font-size:18px;color:#e11d74\">UwUAuth</p>{html}\
             <p style=\"margin:24px 0 0;font-size:12px;color:#716672\">{}</p></div></body></html>",
            escape(&text.footer)
        );
        (text.subject, plain, html)
    }

    fn text(&self, language: Language) -> Text {
        let de = language == Language::De;
        let footer = if de {
            "Diese Mail kommt von deinem UwUAuth Server.".to_string()
        } else {
            "This mail comes from your UwUAuth Server.".to_string()
        };
        let not_you = if de {
            "Warst du das nicht? Dann melde dich an, sieh unter Sicherheit nach und sag der Verwaltung deines Servers Bescheid."
        } else {
            "Wasn't you? Sign in, look under Security, and tell whoever runs your server."
        }
        .to_string();
        match self {
            Mail::Test => Text {
                subject: if de { "Testmail von UwUAuth" } else { "Test mail from UwUAuth" }.into(),
                lines: vec![
                    if de {
                        "Wenn du das liest, kann dein UwUAuth Server Mails verschicken. (◕‿◕✿)"
                    } else {
                        "If you can read this, your UwUAuth Server can send mail. (◕‿◕✿)"
                    }
                    .into(),
                ],
                button: None,
                footer,
            },
            Mail::Invitation { link, organization, invited_by, expires } => Text {
                subject: if de {
                    format!("Einladung zu {organization}")
                } else {
                    format!("You're invited to {organization}")
                },
                lines: vec![
                    match (de, invited_by) {
                        (true, Some(who)) => {
                            format!("{who} hat dich zu {organization} eingeladen. Leg hier dein Konto an:")
                        }
                        (true, None) => format!("Du bist zu {organization} eingeladen. Leg hier dein Konto an:"),
                        (false, Some(who)) => format!("{who} invited you to {organization}. Create your account here:"),
                        (false, None) => format!("You're invited to {organization}. Create your account here:"),
                    },
                    if de {
                        format!("Der Link gilt bis {expires} und nur einmal. Danach braucht es eine neue Einladung.")
                    } else {
                        format!("The link works once, until {expires}. After that, you need a new invitation.")
                    },
                    if de {
                        "Mit dem Konto meldest du dich später bei allen Apps an, die dein Haushalt oder dein Büro damit verbindet."
                    } else {
                        "With this account you sign in to every app your household or office connects to it."
                    }
                    .into(),
                ],
                button: Some((if de { "Konto anlegen" } else { "Create account" }.into(), link.clone())),
                footer,
            },
            Mail::PasswordReset { link, minutes } => Text {
                subject: if de { "Neues Passwort für UwUAuth" } else { "A new password for UwUAuth" }.into(),
                lines: vec![
                    if de {
                        "Hier setzt du ein neues Passwort für dein Konto:"
                    } else {
                        "Set a new password for your account here:"
                    }
                    .into(),
                    if de {
                        format!("Der Link gilt {minutes} Minuten und nur einmal.")
                    } else {
                        format!("The link works once, for {minutes} minutes.")
                    },
                    if de {
                        "Hast du das nicht angefordert? Dann ignorier diese Mail, dein Passwort bleibt, wie es ist."
                    } else {
                        "Didn't ask for this? Ignore this mail; your password stays as it is."
                    }
                    .into(),
                ],
                button: Some((if de { "Passwort setzen" } else { "Set password" }.into(), link.clone())),
                footer,
            },
            Mail::EmailVerify { link, minutes } => Text {
                subject: if de { "Adresse für UwUAuth bestätigen" } else { "Confirm your address for UwUAuth" }.into(),
                lines: vec![
                    if de {
                        "Bestätige, dass diese Adresse zu deinem Konto gehört:"
                    } else {
                        "Confirm that this address belongs to your account:"
                    }
                    .into(),
                    if de {
                        format!("Der Link gilt {minutes} Minuten.")
                    } else {
                        format!("The link works for {minutes} minutes.")
                    },
                    not_you.clone(),
                ],
                button: Some((if de { "Adresse bestätigen" } else { "Confirm address" }.into(), link.clone())),
                footer,
            },
            Mail::NewDevice { device, ip, time } => Text {
                subject: if de { "Neue Anmeldung bei UwUAuth" } else { "New sign-in to UwUAuth" }.into(),
                lines: vec![
                    if de {
                        format!("Dein Konto wurde gerade auf einem neuen Gerät angemeldet: {device}, von {ip}, am {time}.")
                    } else {
                        format!("Your account just signed in on a new device: {device}, from {ip}, at {time}.")
                    },
                    not_you,
                ],
                button: None,
                footer,
            },
            Mail::PasswordChanged { time } => Text {
                subject: if de { "Dein Passwort wurde geändert" } else { "Your password was changed" }.into(),
                lines: vec![
                    if de {
                        format!("Das Passwort deines Kontos wurde am {time} geändert.")
                    } else {
                        format!("The password of your account was changed at {time}.")
                    },
                    not_you,
                ],
                button: None,
                footer,
            },
            Mail::SignInChanged { what, time } => Text {
                subject: if de { "Deine Anmeldung wurde geändert" } else { "How you sign in has changed" }.into(),
                lines: vec![
                    if de { format!("Am {time}: {what}.") } else { format!("At {time}: {what}.") },
                    not_you,
                ],
                button: None,
                footer,
            },
        }
    }
}

fn escape(text: &str) -> String {
    text.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;").replace('\'', "&#39;")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_mail_speaks_both_languages() {
        let all = [
            Mail::Test,
            Mail::Invitation {
                link: "https://auth.example.com/#/invite?token=t".into(),
                organization: "Familie Nyu".into(),
                invited_by: Some("Mama".into()),
                expires: "4. Oktober".into(),
            },
            Mail::PasswordReset { link: "https://auth.example.com/#/reset?token=t".into(), minutes: 60 },
            Mail::EmailVerify { link: "https://auth.example.com/#/verify?token=t".into(), minutes: 60 },
            Mail::NewDevice { device: "Firefox on Linux".into(), ip: "192.0.2.1".into(), time: "12:00".into() },
            Mail::PasswordChanged { time: "12:00".into() },
            Mail::SignInChanged { what: "passkey added".into(), time: "12:00".into() },
        ];
        for mail in all {
            let (de_subject, de_text, _) = mail.render(Language::De);
            let (en_subject, en_text, _) = mail.render(Language::En);
            assert_ne!(de_subject, en_subject);
            assert_ne!(de_text, en_text);
            assert!(de_text.ends_with("UwUAuth Server.\n"));
        }
    }

    #[test]
    fn what_comes_from_outside_is_escaped() {
        let mail = Mail::Invitation {
            link: "https://auth.example.com/#/invite?token=t&x=1".into(),
            organization: "<script>".into(),
            invited_by: Some("\"Nyu\"".into()),
            expires: "morgen".into(),
        };
        let (_, text, html) = mail.render(Language::De);
        assert!(text.contains("<script>"), "plain text stays plain");
        assert!(!html.contains("<script>"));
        assert!(html.contains("&lt;script&gt;"));
        assert!(html.contains("token=t&amp;x=1"));
    }
}
