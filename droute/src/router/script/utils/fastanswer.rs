// Copyright 2022 LEXUGE
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
use bytes::{Bytes, BytesMut};
use domain::{
    base::{iana::Class, net::IpAddr, Message, MessageBuilder},
    rdata::{Aaaa, A},
};

/// Create a message that stops the requestor to send the query again.
pub fn fast_answer(query: &Message<Bytes>, a: u8, b: u8, c: u8, d: u8) -> Result<Message<Bytes>> {
    // Is 50 a good number?
    let mut builder = MessageBuilder::from_target(BytesMut::with_capacity(50))?
        .start_answer(query, domain::base::iana::Rcode::NoError)?;

    builder.push((
        query.first_question().unwrap().qname(),
        Class::In,
        86400,
        A::from_octets(a, b, c, d),
    ))?;

    Ok(builder.into_message())
}

/// fast_answer_ip
pub fn fast_answer_ip(query: &Message<Bytes>, ip: IpAddr) -> Result<Message<Bytes>> {
    // Is 50 a good number?
    let mut builder = MessageBuilder::from_target(BytesMut::with_capacity(50))?
        .start_answer(query, domain::base::iana::Rcode::NoError)?;

    match ip {
        IpAddr::V4(v4) => builder.push((
            query.first_question().unwrap().qname(),
            Class::In,
            86400,
            A::new(v4),
        ))?,
        IpAddr::V6(v6) => builder.push((
            query.first_question().unwrap().qname(),
            Class::In,
            86400,
            Aaaa::new(v6),
        ))?,
    };

    Ok(builder.into_message())
}
