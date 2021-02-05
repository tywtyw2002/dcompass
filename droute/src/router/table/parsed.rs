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

mod action;
mod matcher;

pub use action::{BuiltinParAction, ParAction, ParActionTrait};
pub use matcher::{BuiltinParMatcher, ParMatcher, ParMatcherTrait};

use super::rule::actions::{Action, Result as ActionResult};
use crate::Label;
use serde::{
    de::{Deserializer, Error as _, SeqAccess, Visitor},
    Deserialize,
};
use std::marker::PhantomData;

/// A parsed branch of a rule.
#[derive(Clone)]
pub struct ParBranch<A: ParActionTrait> {
    seq: Vec<ParAction<A>>,
    next: Label,
}

// This customized deserialization process accept branches of this form:
// ```
// - Action1
// - Action2
// - ...
// - next
// ```
// Here the lifetime constraints are compatible with the ones from serde derivation. We are not adding them to `ParAction` as they are gonna be automatically generated by serde.
impl<'de, A: ParActionTrait + Deserialize<'de>> Deserialize<'de> for ParBranch<A> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Either<A: ParActionTrait> {
            Action(ParAction<A>),
            Tag(Label),
        }

        struct BranchVisitor<A> {
            // Dummy variable for visitor to be constrained by `A`.
            t: PhantomData<A>,
        };

        impl<'de, A: ParActionTrait + Deserialize<'de>> Visitor<'de> for BranchVisitor<A> {
            type Value = ParBranch<A>;

            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("a list of actions with the tag of the next rule as the last element")
            }

            fn visit_seq<V: SeqAccess<'de>>(self, mut sv: V) -> Result<Self::Value, V::Error> {
                let mut seq = Vec::new();

                // Get the `next` from the first element of the type Label.
                let next = loop {
                    match sv.next_element::<Either<A>>()? {
                        Some(Either::Action(a)) => seq.push(a),
                        Some(Either::Tag(l)) => break l,
                        None => return Err(V::Error::custom("Missing the tag of the next rule")),
                    }
                };

                // Verify that this is indeed the last element.
                if sv.next_element::<Either<A>>()?.is_some() {
                    return Err(V::Error::custom(
                        "Extra element after the rule tag specified at last",
                    ));
                }

                Ok(Self::Value { seq, next })
            }
        }

        deserializer.deserialize_seq(BranchVisitor::<A> { t: PhantomData })
    }
}

impl<A: ParActionTrait> ParBranch<A> {
    // Build the ParMatchArm into the internal-used tuple by `Rule`.
    pub(super) async fn build(self) -> ActionResult<(Vec<Box<dyn Action>>, Label)> {
        let mut built: Vec<Box<dyn Action>> = Vec::new();
        for a in self.seq {
            // TODO: Can we make this into a map?
            built.push(a.build().await?);
        }
        Ok((built, self.next))
    }
}

impl<A: ParActionTrait> Default for ParBranch<A> {
    fn default() -> Self {
        Self {
            seq: vec![],
            next: "end".into(),
        }
    }
}

/// A rule composed of tag name, matcher, and branches.
#[derive(Deserialize, Clone)]
#[serde(rename_all = "lowercase")]
#[serde(deny_unknown_fields)]
pub struct ParRule<M: ParMatcherTrait, A: ParActionTrait> {
    /// The tag name of the rule
    pub tag: Label,

    /// The matcher rule uses.
    #[serde(rename = "if")]
    pub matcher: M,

    /// If matcher matches, this branch specifies action and next rule name to route. Defaut to `(Vec::new(), "end".into())`
    #[serde(default = "ParBranch::default")]
    #[serde(rename = "then")]
    pub on_match: ParBranch<A>,

    /// If matcher doesn't, this branch specifies action and next rule name to route. Defaut to `(Vec::new(), "end".into())`
    #[serde(default = "ParBranch::default")]
    #[serde(rename = "else")]
    pub no_match: ParBranch<A>,
}
