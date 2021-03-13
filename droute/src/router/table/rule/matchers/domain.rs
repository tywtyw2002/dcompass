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

use super::{super::super::State, Matcher, Result};
use dmatcher::domain::Domain as DomainAlg;
#[cfg(feature = "serde-cfg")]
use serde::Deserialize;
use tokio::{fs::File, io::AsyncReadExt};

/// A matcher that matches if first query's domain is within the domain list provided
pub struct Domain(DomainAlg);

#[cfg_attr(feature = "serde-cfg", serde(rename_all = "lowercase"))]
#[cfg_attr(feature = "serde-cfg", derive(Deserialize))]
#[derive(Clone, Eq, PartialEq)]
/// Type of the domain resources to add to the matcher.
pub enum ResourceType {
    /// Query Name
    Qname(String),

    /// A file
    File(String),
}

impl Domain {
    /// Create a new `Domain` matcher from a list of files where each domain is seperated from one another by `\n`.
    pub async fn new(p: Vec<ResourceType>) -> Result<Self> {
        Ok({
            let mut matcher = DomainAlg::new();
            for r in p {
                match r {
                    ResourceType::Qname(n) => matcher.insert_multi(&n),
                    ResourceType::File(l) => {
                        let mut file = File::open(l).await?;
                        let mut data = String::new();
                        file.read_to_string(&mut data).await?;
                        matcher.insert_multi(&data);
                    }
                }
            }
            Self(matcher)
        })
    }
}

impl Matcher for Domain {
    fn matches(&self, state: &State) -> bool {
        self.0.matches(&state.query.queries()[0].name().to_utf8())
    }
}
