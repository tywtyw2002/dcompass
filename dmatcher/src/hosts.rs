// Copyright 2020 LEXUGE
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

//! This is a simple domain matching algorithm to match domains against a set of user-defined domain rules.
//!
//! Features:
//!
//! -  Super fast (187 ns per match for a 73300+ domain rule set)
//! -  No dependencies
//!

use bytes::Bytes;
use domain::base::{name::OwnedLabel, Dname, net::IpAddr};
use std::{collections::HashMap, sync::Arc};


#[derive(Clone)]
/// Match Type
pub enum MatchType {
    /// Internal Node
    None,
    /// Match subdomain
    Subdomain(IpAddr),
    /// Full Match Required.
    Server(IpAddr),
}


/// HostConfig
// pub struct HostConfig {
//     domain: Dname<Bytes>,
//     ip: MatchType,
// }

// #[derive(PartialEq, Clone)]
#[derive(Clone)]
struct LevelNode {
    next_lvs: HashMap<Arc<OwnedLabel>, LevelNode>,
    ip: MatchType,
}

impl LevelNode {
    // fn new(ip: MatchType) -> Self {
    //     Self {
    //         next_lvs: HashMap::new(),
    //         ip: ip,
    //     }
    // }

    fn new() -> Self {
        Self {
            next_lvs: HashMap::new(),
            ip: MatchType::None,
        }
    }
}

/// Domain matcher algorithm
#[derive(Clone)]
pub struct Hosts {
    root: LevelNode,
}

impl Default for Hosts {
    fn default() -> Self {
        Self::new()
    }
}

impl Hosts {
    /// Create a matcher.
    pub fn new() -> Self {
        Self {
            root: LevelNode::new(),
        }
    }

    /// Pass in a string containing `\n` and get all domains inserted.
    // pub fn insert_multi(&mut self, config: &[HostConfig]) {
    //     // This gets rid of empty substrings for stability reasons. See also https://github.com/LEXUGE/dcompass/issues/33.
    //     config.iter().for_each(|d| self.insert(&d.domain, &d.ip));
    // }

    /// Pass in a domain and insert it into the matcher.
    /// This ignores any line containing chars other than A-Z, a-z, 1-9, and -.
    /// See also: https://tools.ietf.org/html/rfc1035
    pub fn insert(&mut self, domain: &Dname<Bytes>, ip: &MatchType) {
        let mut ptr = &mut self.root;
        for lv in domain.iter().rev() {
            ptr = ptr
                .next_lvs
                .entry(Arc::new(lv.to_owned()))
                .or_insert_with(LevelNode::new);
        }
        // Insert IP Node.
        ptr.ip = ip.clone();
    }

    /// Match the domain against inserted domain rules. If `apple.com` is inserted, then `www.apple.com` and `stores.www.apple.com` is considered as matched while `apple.cn` is not.
    pub fn matches(&self, domain: &Dname<Bytes>) -> Option<IpAddr> {
        let mut ptr = &self.root;
        let mut ip_ptr = &ptr.ip;
        let mut lvl: usize = 0;

        for lv in domain.iter().rev() {
            lvl += 1;
            if ptr.next_lvs.is_empty() {
                break;
            }

            // If not empty...
            ptr = match ptr.next_lvs.get(&lv.to_owned()) {
                Some(v) => {
                    match v.ip {
                        MatchType::Server(vx) => {
                            if domain.label_count() == lvl {
                                return Some(vx.clone())
                            }
                        },
                        _ => ip_ptr = &v.ip,
                    }
                    v
                },
                // None => return false,
                None => { break; }
            };
        }

        match ip_ptr {
            MatchType::None => None,
            MatchType::Subdomain(v) => Some(v.clone()),
            MatchType::Server(v) => Some(v.clone())
        }
    }
}

// #[cfg(test)]
// mod tests {
//     use super::Domain;
//     use domain::base::Dname;
//     use std::str::FromStr;

//     macro_rules! dname {
//         ($s:expr) => {
//             Dname::from_str($s).unwrap()
//         };
//     }

//     #[test]
//     fn matches() {
//         let mut matcher = Domain::new();
//         matcher.insert(&dname!("apple.com"));
//         matcher.insert(&dname!("apple.cn"));
//         assert_eq!(matcher.matches(&dname!("store.apple.com")), true);
//         assert_eq!(matcher.matches(&dname!("store.apple.com.")), true);
//         assert_eq!(matcher.matches(&dname!("baidu.com")), false);
//     }

//     #[test]
//     fn insert_multi() {
//         let mut matcher = Domain::new();
//         matcher.insert_multi(&[dname!("apple.com"), dname!("apple.cn")]);
//         assert_eq!(matcher.matches(&dname!("store.apple.cn")), true);
//         assert_eq!(matcher.matches(&dname!("store.apple.com.")), true);
//         assert_eq!(matcher.matches(&dname!("baidu.com")), false);
//     }
// }
