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

/// Structures used for serialize/deserialize information needed to create router and more.
#[cfg(feature = "serde-cfg")]
pub mod parsed;
pub mod rule;

use self::rule::{actions::ActionError, matchers::MatchError, Rule};
use super::upstreams::Upstreams;
use crate::{Label, Validatable, ValidateCell};
use log::*;
#[cfg(feature = "serde-cfg")]
use parsed::{ParActionTrait, ParMatcherTrait, ParRule};
use std::collections::{HashMap, HashSet};
use thiserror::Error;
use trust_dns_client::op::Message;

type Result<T> = std::result::Result<T, TableError>;

/// Errors generated by the `table` section.
#[derive(Error, Debug)]
pub enum TableError {
    /// Errors related to matchers.
    #[error(transparent)]
    MatchError(#[from] MatchError),

    /// Errors related to actions
    #[error(transparent)]
    ActionError(#[from] ActionError),

    /// Some of the table rules are unused.
    #[error("Some of the rules in table are not used: {0:?}")]
    UnusedRules(HashSet<Label>),

    /// Rules are defined recursively, which is prohibited.
    #[error("The `rule` block with tag `{0}` is being recursively called in the `table` section")]
    RuleRecursion(Label),

    /// A rule is not found.
    #[error(
        "Rule with tag `{0}` is not found in the `table` section. Note that tag `start` is required"
    )]
    UndefinedTag(Label),

    /// Multiple rules with the same tag name have been found.
    #[error("Multiple defintions found for tag `{0}` in the `rules` section")]
    MultipleDef(Label),
}

#[derive(Default)]
pub struct State {
    resp: Message,
    query: Message,
}

// Traverse and validate the routing table.
fn traverse(
    // A bucket to count the time each tag being used.
    bucket: &mut HashMap<&Label, (ValidateCell, &Rule)>,
    // Tag of the rule that we are currently on.
    tag: &Label,
) -> Result<()> {
    // Hacky workaround on the borrow checker.
    let (val, on_match, no_match) = if let Some((c, r)) = bucket.get_mut(tag) {
        (c.val(), r.on_match_next(), r.no_match_next())
    } else {
        return Err(TableError::UndefinedTag(tag.clone()));
    };
    if val >= &1 {
        Err(TableError::RuleRecursion(tag.clone()))
    } else {
        bucket.get_mut(tag).unwrap().0.add(1);
        if on_match != &"end".into() {
            traverse(bucket, on_match)?;
        }
        if no_match != &"end".into() {
            traverse(bucket, no_match)?;
        }
        bucket.get_mut(tag).unwrap().0.sub(1);
        Ok(())
    }
}

/// A simple routing table.
pub struct Table {
    rules: HashMap<Label, Rule>,
    // Upstreams used in this table.
    used_upstreams: HashSet<Label>,
}

impl Validatable for Table {
    type Error = TableError;
    fn validate(&self, _: Option<&HashSet<Label>>) -> Result<()> {
        // A bucket used to count the time each rule being used.
        let mut bucket: HashMap<&Label, (ValidateCell, &Rule)> = self
            .rules
            .iter()
            .map(|(k, v)| (k, (ValidateCell::default(), v)))
            .collect();
        traverse(&mut bucket, &"start".into())?;
        let unused: HashSet<Label> = bucket
            .into_iter()
            .filter(|(_, (c, _))| !c.used())
            .map(|(k, _)| k)
            .cloned()
            .collect();
        if unused.is_empty() {
            Ok(())
        } else {
            Err(TableError::UnusedRules(unused))
        }
    }
}

impl Table {
    /// Create a routing table from a bunch of `Rule`s.
    pub fn new(rules: Vec<Rule>) -> Result<Self> {
        let mut table = HashMap::new();
        for r in rules {
            match table.get(r.tag()) {
                Some(_) => return Err(TableError::MultipleDef(r.tag().clone())),
                None => table.insert(r.tag().clone(), r),
            };
        }
        // A bucket used to count the time each rule being used.
        let mut bucket: HashMap<&Label, (ValidateCell, &Rule)> = table
            .iter()
            .map(|(k, v)| (k, (ValidateCell::default(), v)))
            .collect();
        traverse(&mut bucket, &"start".into())?;
        let used_upstreams = bucket
            .iter()
            .filter(|(_, (c, _))| c.used())
            .flat_map(|(_, (_, v))| v.used_upstreams())
            .collect();
        let unused: HashSet<Label> = bucket
            .into_iter()
            .filter(|(_, (c, _))| !c.used())
            .map(|(k, _)| k)
            .cloned()
            .collect();
        if !unused.is_empty() {
            return Err(TableError::UnusedRules(unused));
        }
        Ok(Self {
            rules: table,
            used_upstreams,
        })
    }

    // This is not intended to be used by end-users as they can create with parsed structs from `Router`.
    #[cfg(feature = "serde-cfg")]
    pub(super) async fn parse(
        parsed_rules: Vec<ParRule<impl ParMatcherTrait, impl ParActionTrait>>,
    ) -> Result<Self> {
        let mut rules = Vec::new();
        for r in parsed_rules {
            rules.push(Rule::parse(r).await?);
        }
        Self::new(rules)
    }

    // Not intended to be used by end-users
    pub(super) fn used_upstreams(&self) -> &HashSet<Label> {
        &self.used_upstreams
    }

    // Not intended to be used by end-users
    pub(super) async fn route(&self, query: Message, upstreams: &Upstreams) -> Result<Message> {
        let name = query.queries().iter().next().unwrap().name().to_utf8();
        let mut s = State {
            query,
            ..Default::default()
        };

        let mut tag = "start".into();
        while tag != "end".into() {
            tag = self
                .rules
                .get(&tag)
                .unwrap()
                .route(&mut s, upstreams, &name)
                .await?;
        }
        info!("Domain \"{}\" has finished routing", name);
        Ok(s.resp)
    }
}

#[cfg(test)]
mod tests {
    use super::{
        rule::{
            actions::{CacheMode, Query},
            matchers::{Any, Domain, ResourceType},
            Rule,
        },
        Table, TableError,
    };
    use crate::Label;

    #[tokio::test]
    async fn is_not_recursion() {
        Table::new(vec![
            Rule::new(
                "start".into(),
                Box::new(Any::default()),
                (vec![], "foo".into()),
                (vec![], "foo".into()),
            ),
            Rule::new(
                "foo".into(),
                Box::new(Any::default()),
                (vec![], "end".into()),
                (vec![], "end".into()),
            ),
        ])
        .ok()
        .unwrap();
    }

    #[tokio::test]
    async fn fail_table_recursion() {
        match Table::new(vec![Rule::new(
            "start".into(),
            Box::new(Any::default()),
            (
                vec![Box::new(Query::new("mock".into(), CacheMode::default()))],
                "end".into(),
            ),
            (vec![], "start".into()),
        )])
        .err()
        .unwrap()
        {
            TableError::RuleRecursion(_) => {}
            e => panic!("Not the right error type: {}", e),
        }
    }

    #[tokio::test]
    async fn fail_multiple_defs() {
        match Table::new(vec![
            Rule::new(
                "start".into(),
                Box::new(Any::default()),
                (vec![], "end".into()),
                (vec![], "end".into()),
            ),
            Rule::new(
                "start".into(),
                Box::new(Any::default()),
                (vec![], "end".into()),
                (vec![], "end".into()),
            ),
        ])
        .err()
        .unwrap()
        {
            TableError::MultipleDef(_) => {}
            e => panic!("Not the right error type: {}", e),
        }
    }

    #[tokio::test]
    async fn fail_unused_rules() {
        match Table::new(vec![
            Rule::new(
                "start".into(),
                Box::new(Any::default()),
                (
                    vec![Box::new(Query::new("mock".into(), CacheMode::default()))],
                    "end".into(),
                ),
                (vec![], "end".into()),
            ),
            Rule::new(
                "mock".into(),
                Box::new(Any::default()),
                (vec![], "end".into()),
                (vec![], "end".into()),
            ),
            Rule::new(
                "unused".into(),
                Box::new(Any::default()),
                (vec![], "end".into()),
                (vec![], "end".into()),
            ),
        ])
        .err()
        .unwrap()
        {
            TableError::UnusedRules(v) => {
                assert_eq!(
                    v,
                    vec!["mock", "unused"]
                        .into_iter()
                        .map(|s| Label::from(s))
                        .collect()
                )
            }
            e => panic!("Not the right error type: {}", e),
        }
    }

    #[tokio::test]
    async fn success_domain_table() {
        Table::new(vec![Rule::new(
            "start".into(),
            Box::new(
                Domain::new(vec![ResourceType::File("../data/china.txt".to_string())])
                    .await
                    .unwrap(),
            ),
            (
                vec![Box::new(Query::new("mock".into(), CacheMode::default()))],
                "end".into(),
            ),
            (
                vec![Box::new(Query::new(
                    "another_mock".into(),
                    CacheMode::default(),
                ))],
                "end".into(),
            ),
        )])
        .ok()
        .unwrap();
    }
}
