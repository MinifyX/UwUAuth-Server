//! UwUAuth Server's LDAP: the directory for what cannot do OpenID Connect — a NAS, Linux logins
//! with SSSD, Nextcloud's LDAP backend, anything with an "LDAP / Active Directory" setting.
//!
//! LDAPv3, read-only but for passwords: bind, search, compare, WhoAmI (RFC 4532), password
//! modify (RFC 3062) and Active Directory's `unicodePwd`, paged results (RFC 2696), StartTLS and
//! LDAPS. People bind with their password or an app password; apps with an LDAP account from the
//! admin portal. Nobody writes the directory over LDAP: that is the portal's job.
//!
//! Not a domain controller: no Kerberos, no NTLM, no joining Windows to a domain. The attributes
//! are Active Directory's so that apps set to "Active Directory" find what they look for.

pub mod directory;
pub mod dn;
pub mod filter;
mod server;

pub use server::{Ldap, LdapConfig, TlsSource};
