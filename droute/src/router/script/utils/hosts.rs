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

use super::Result;
use bytes::Bytes;
use dmatcher::hosts::{Hosts as HostsAlg, MatchType};
use domain::base::{
    name::FromStrError,
    net::{IpAddr, Ipv4Addr},
    Dname,
};
use std::{path::PathBuf, str::FromStr};

/// The domain matcher
#[derive(Clone)]
#[cfg_attr(feature = "rune-scripting", derive(rune::Any))]
pub struct Hosts(HostsAlg);

fn into_hosts_config(
    list: &str,
) -> std::result::Result<Vec<(Dname<Bytes>, MatchType)>, FromStrError> {
    let mut cfg: Vec<(Dname<Bytes>, MatchType)> = Vec::new();
    for line in list.split('\n') {
        if line.is_empty() {
            continue;
        }

        let c: Vec<&str> = line.split_whitespace().collect();
        if !c[0].chars().all(|c| {
            char::is_ascii_alphabetic(&c) | char::is_ascii_digit(&c) | (c == '-') | (c == '.')
        }) || c[1].is_empty()
        {
            continue;
        }

        let host_str: Dname<Bytes> = Dname::from_str(c[0])?;
        let ip = if c[1].as_bytes()[0] == b'!' {
            MatchType::Server(IpAddr::V4(Ipv4Addr::from_str(&c[1][1..]).unwrap()))
        } else {
            MatchType::Subdomain(IpAddr::V4(Ipv4Addr::from_str(c[1]).unwrap()))
        };

        cfg.push((host_str, ip));
    }

    Ok(cfg)
}

impl Default for Hosts {
    fn default() -> Self {
        Self::new()
    }
}

impl Hosts {
    /// Create an empty `domain` matcher
    pub fn new() -> Self {
        Self(HostsAlg::new())
    }

    /// Add a server name to the domain matcher's list
    pub fn add_host(&mut self, s: &str, ip: &str, is_server: bool) -> Result<()> {
        let domain: Dname<Bytes> = Dname::from_str(s).unwrap();

        let ip = IpAddr::V4(Ipv4Addr::from_str(ip).unwrap());
        let ip_match = if is_server {
            MatchType::Server(ip)
        } else {
            MatchType::Subdomain(ip)
        };

        self.0.insert(&domain, &ip_match);
        Ok(())
    }

    /// Add all question names in a file to the domain matcher's list
    pub fn add_file(&mut self, path: impl AsRef<str>) -> Result<()> {
        // from_str is Infallible
        let (mut file, _) = niffler::from_path(PathBuf::from_str(path.as_ref()).unwrap())?;
        let mut data = String::new();
        file.read_to_string(&mut data)?;
        into_hosts_config(&data)?
            .iter()
            .for_each(|d| self.0.insert(&d.0, &d.1));
        Ok(())
    }

    /// Check if the question name matches any in the matcher.
    pub fn reslove(&self, qname: &Dname<Bytes>) -> Option<IpAddr> {
        self.0.matches(qname)
    }
}
